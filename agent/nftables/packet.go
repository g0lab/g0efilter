package nftables

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

const (
	ipv6HeaderLen   = 40
	maxExtHeaders   = 8
	protoHopByHop   = 0
	protoTCP        = 6
	protoUDP        = 17
	protoRouting    = 43
	protoFragment   = 44
	protoAH         = 51
	protoDestOpts   = 60
	fragOffsetMask  = 0x1fff
	minTransportLen = 4
	laterFragment   = -1
)

func parseIPLayer(payload []byte) (net.IP, net.IP, uint8, []byte, bool) {
	switch payload[0] >> 4 {
	case 4:
		return parseIPv4(payload)
	case 6:
		return parseIPv6(payload)
	default:
		return nil, nil, 0, nil, false
	}
}

func parseIPv4(payload []byte) (net.IP, net.IP, uint8, []byte, bool) {
	headerLen := int(payload[0]&0x0f) * 4
	if headerLen < minPacketSize || len(payload) < headerLen {
		return nil, nil, 0, nil, false
	}

	src, dst, proto := net.IP(payload[12:16]), net.IP(payload[16:20]), payload[9]

	// Like the kernel, a total length that does not cover the header leaves no transport.
	total := int(binary.BigEndian.Uint16(payload[2:4]))
	if total < headerLen || binary.BigEndian.Uint16(payload[6:8])&fragOffsetMask != 0 {
		return src, dst, proto, nil, true
	}

	proto, transport := upperLayer(proto, payload[headerLen:min(total, len(payload))], false)

	return src, dst, proto, transport, true
}

func parseIPv6(payload []byte) (net.IP, net.IP, uint8, []byte, bool) {
	if len(payload) < ipv6HeaderLen {
		return nil, nil, 0, nil, false
	}

	end := min(ipv6HeaderLen+int(binary.BigEndian.Uint16(payload[4:6])), len(payload))
	proto, transport := upperLayer(payload[6], payload[ipv6HeaderLen:end], true)

	return net.IP(payload[8:24]), net.IP(payload[24:40]), proto, transport, true
}

// upperLayer skips AH and, for IPv6, extension headers to reach the transport
// header. transport is nil when a header is truncated or the packet is a later fragment.
func upperLayer(next uint8, rest []byte, ipv6 bool) (uint8, []byte) {
	for range maxExtHeaders {
		if !isExtHeader(next, ipv6) {
			return next, rest
		}

		extLen := extHeaderLen(next, rest)

		switch {
		case extLen == laterFragment:
			return rest[0], nil
		case extLen == 0 || len(rest) < extLen:
			return next, nil
		}

		next, rest = rest[0], rest[extLen:]
	}

	return next, nil
}

func isExtHeader(next uint8, ipv6 bool) bool {
	switch next {
	case protoAH:
		return true
	case protoHopByHop, protoRouting, protoDestOpts, protoFragment:
		return ipv6
	default:
		return false
	}
}

// extHeaderLen returns 0 when the header itself is truncated.
func extHeaderLen(next uint8, rest []byte) int {
	switch next {
	case protoFragment:
		if len(rest) < 8 {
			return 0
		}

		if binary.BigEndian.Uint16(rest[2:4])>>3 != 0 {
			return laterFragment
		}

		return 8
	case protoAH:
		if len(rest) < 2 {
			return 0
		}

		return (int(rest[1]) + 2) * 4
	default:
		if len(rest) < 2 {
			return 0
		}

		return (int(rest[1]) + 1) * 8
	}
}

// parsePacketInfo extracts addresses and ports from a raw IPv4 or IPv6 packet.
func parsePacketInfo(payload []byte) PacketInfo {
	if len(payload) < minPacketSize {
		return PacketInfo{}
	}

	srcIP, dstIP, proto, transport, ok := parseIPLayer(payload)
	if !ok {
		return PacketInfo{}
	}

	src, dst := srcIP.String(), dstIP.String()

	var name string

	switch proto {
	case protoTCP:
		name = "TCP"
	case protoUDP:
		name = "UDP"
	}

	if name == "" || len(transport) < minTransportLen {
		return PacketInfo{
			Src:           src,
			Dst:           dst,
			Protocol:      strconv.Itoa(int(proto)),
			SourceIP:      src,
			DestinationIP: dst,
		}
	}

	srcPort := int(binary.BigEndian.Uint16(transport[0:2]))
	dstPort := int(binary.BigEndian.Uint16(transport[2:4]))

	return PacketInfo{
		Src:             fmt.Sprintf("%s:%d", src, srcPort),
		Dst:             fmt.Sprintf("%s:%d", dst, dstPort),
		Protocol:        name,
		SourceIP:        src,
		DestinationIP:   dst,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
	}
}
