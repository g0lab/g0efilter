package nftables

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"
)

func ports(src, dst uint16) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], src)
	binary.BigEndian.PutUint16(header[2:4], dst)

	return header
}

func ipv4Packet(proto uint8, fragOffset uint16, options, transport []byte) []byte {
	headerLen := 20 + len(options)
	packet := make([]byte, headerLen, headerLen+len(transport))
	packet[0] = 0x40 | uint8(headerLen/4)                                     //nolint:gosec // small test packet
	binary.BigEndian.PutUint16(packet[2:4], uint16(headerLen+len(transport))) //nolint:gosec // small test packet
	binary.BigEndian.PutUint16(packet[6:8], fragOffset)
	packet[9] = proto
	copy(packet[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(packet[16:20], net.IPv4(10, 0, 0, 2).To4())
	copy(packet[20:], options)

	return append(packet, transport...)
}

func ipv6Packet(next uint8, rest []byte) []byte {
	packet := make([]byte, ipv6HeaderLen, ipv6HeaderLen+len(rest))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(rest))) //nolint:gosec // small test packet
	packet[6] = next
	copy(packet[8:24], net.ParseIP("2001:db8::1"))
	copy(packet[24:40], net.ParseIP("2001:db8::2"))

	return append(packet, rest...)
}

func extHeader(next uint8) []byte {
	return []byte{next, 0, 0, 0, 0, 0, 0, 0}
}

func fragHeader(next uint8, offset uint16) []byte {
	header := []byte{next, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(header[2:4], offset<<3)

	return header
}

func withLength(packet []byte, offset int, length uint16) []byte {
	binary.BigEndian.PutUint16(packet[offset:offset+2], length)

	return packet
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}

	return out
}

type packetCase struct {
	name    string
	payload []byte
	src     string
	dst     string
	proto   string
}

func runPacketCases(t *testing.T, tests []packetCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parsePacketInfo(tt.payload)
			if got.Src != tt.src || got.Dst != tt.dst || got.Protocol != tt.proto {
				t.Errorf("parsePacketInfo() = %s -> %s (%s), want %s -> %s (%s)",
					got.Src, got.Dst, got.Protocol, tt.src, tt.dst, tt.proto)
			}
		})
	}
}

func TestParsePacketInfoHeaders(t *testing.T) {
	t.Parallel()

	runPacketCases(t, []packetCase{
		{"ipv4 udp", ipv4Packet(protoUDP, 0, nil, ports(5353, 53)), "10.0.0.1:5353", "10.0.0.2:53", "UDP"},
		{"ipv4 options", ipv4Packet(protoTCP, 0, make([]byte, 8), ports(1, 2)), "10.0.0.1:1", "10.0.0.2:2", "TCP"},
		{"ipv4 later fragment", ipv4Packet(protoTCP, 10, nil, ports(1, 2)), "10.0.0.1", "10.0.0.2", "6"},
		{
			"ipv4 ah then tcp",
			ipv4Packet(protoAH, 0, nil, concat([]byte{protoTCP, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ports(1, 2))),
			"10.0.0.1:1", "10.0.0.2:2", "TCP",
		},
		{"ipv4 icmp", ipv4Packet(1, 0, nil, []byte{8, 0, 0, 0}), "10.0.0.1", "10.0.0.2", "1"},
		{"ipv4 truncated transport", ipv4Packet(protoTCP, 0, nil, []byte{0, 1}), "10.0.0.1", "10.0.0.2", "6"},
		{"ipv4 bad header length", append([]byte{0x44}, make([]byte, 30)...), "", "", ""},
		{
			"ipv6 hop-by-hop then tcp",
			ipv6Packet(protoHopByHop, concat(extHeader(protoTCP), ports(1, 443))),
			"2001:db8::1:1", "2001:db8::2:443", "TCP",
		},
		{
			"ipv6 first fragment",
			ipv6Packet(protoFragment, concat(fragHeader(protoUDP, 0), ports(1, 53))),
			"2001:db8::1:1", "2001:db8::2:53", "UDP",
		},
		{
			"ipv6 later fragment",
			ipv6Packet(protoFragment, concat(fragHeader(protoUDP, 100), ports(1, 53))),
			"2001:db8::1", "2001:db8::2", "17",
		},
		{"ipv6 truncated extension", ipv6Packet(protoRouting, []byte{protoTCP}), "2001:db8::1", "2001:db8::2", "43"},
	})
}

// Bytes past the declared length are not the packet's, whatever the capture holds.
func TestParsePacketInfoDeclaredLength(t *testing.T) {
	t.Parallel()

	runPacketCases(t, []packetCase{
		{
			"ipv4 total length below header",
			withLength(ipv4Packet(protoTCP, 0, nil, ports(1, 2)), 2, 10),
			"10.0.0.1", "10.0.0.2", "6",
		},
		{
			"ipv4 transport past total length",
			concat(ipv4Packet(protoTCP, 0, nil, nil), ports(1, 2)),
			"10.0.0.1", "10.0.0.2", "6",
		},
		{
			"ipv4 total length beyond capture",
			withLength(ipv4Packet(protoTCP, 0, nil, ports(1, 2)), 2, 1500),
			"10.0.0.1:1", "10.0.0.2:2", "TCP",
		},
		{
			"ipv6 transport past payload length",
			concat(ipv6Packet(protoTCP, nil), ports(1, 443)),
			"2001:db8::1", "2001:db8::2", "6",
		},
		{
			"ipv6 extension past payload length",
			concat(ipv6Packet(protoHopByHop, extHeader(protoTCP)[:4]), extHeader(protoTCP)[4:], ports(1, 443)),
			"2001:db8::1", "2001:db8::2", "0",
		},
	})
}

// declaredEnd is where the IP header says the packet ends, or 0 when it cannot say.
func declaredEnd(payload []byte) int {
	switch {
	case len(payload) < minPacketSize:
		return 0
	case payload[0]>>4 == 4:
		return max(int(binary.BigEndian.Uint16(payload[2:4])), int(payload[0]&0x0f)*4)
	case payload[0]>>4 == 6 && len(payload) >= ipv6HeaderLen:
		return ipv6HeaderLen + int(binary.BigEndian.Uint16(payload[4:6]))
	default:
		return 0
	}
}

// Packets come from the kernel log of arbitrary traffic, so no input may panic,
// and bytes past the declared length must not reach audit records or alerts.
func FuzzParsePacketInfo(f *testing.F) {
	f.Add(ipv4Packet(protoTCP, 0, nil, ports(12345, 443)))
	f.Add(concat(ipv4Packet(protoTCP, 0, nil, nil), ports(1, 2)))
	f.Add(ipv6Packet(protoHopByHop, concat(extHeader(protoFragment), fragHeader(protoTCP, 0), ports(1, 2))))
	f.Add(concat(ipv6Packet(protoTCP, nil), ports(1, 2)))
	f.Add([]byte{0x4f})

	f.Fuzz(func(t *testing.T, payload []byte) {
		got := parsePacketInfo(payload)

		end := declaredEnd(payload)
		if end == 0 || end >= len(payload) {
			return
		}

		mutated := slices.Clone(payload)
		for i := end; i < len(mutated); i++ {
			mutated[i] ^= 0xff
		}

		if again := parsePacketInfo(mutated); again != got {
			t.Errorf("bytes past the declared end %d changed the result: %+v, then %+v", end, got, again)
		}
	})
}
