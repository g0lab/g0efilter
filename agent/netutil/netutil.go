// Package netutil provides the SO_MARK dialer that lets g0efilter's own
// outbound traffic (proxy upstreams, dashboard shipping, notifications)
// bypass its nftables rules.
package netutil

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//nolint:gochecknoglobals // One secret mark is shared by every dialer for this process lifetime.
var bypassMark = randomBypassMark()

// UDP DNS forwards bind above Linux's default ephemeral range to avoid
// conntrack tuple collisions with redirected client queries.
const (
	dnsForwardPortLow  = 61000
	dnsForwardPortHigh = 64999
)

//nolint:gochecknoglobals // rotating allocator for the forward source ports
var dnsForwardPort atomic.Uint32

func randomBypassMark() uint32 {
	for {
		var value [4]byte

		_, err := rand.Read(value[:])
		if err != nil {
			panic(fmt.Sprintf("generate SO_MARK bypass value: %v", err))
		}

		mark := binary.NativeEndian.Uint32(value[:])
		if mark != 0 {
			return mark
		}
	}
}

// BypassMark returns the random mark shared by all g0efilter sockets and
// nftables rules for this process lifetime.
func BypassMark() uint32 {
	return bypassMark
}

// MarkedDialer returns a dialer with SO_MARK set so connections bypass the
// nftables REDIRECT/filter rules. Setting the mark needs CAP_NET_ADMIN or, on
// Linux 5.17+, CAP_NET_RAW. It is best-effort because unprivileged test/dev
// environments have no nftables rules to bypass.
func MarkedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_ string, _ string, rc syscall.RawConn) error {
			err := rc.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(BypassMark()))
			})
			if err != nil {
				return fmt.Errorf("socket control error: %w", err)
			}

			return nil
		},
	}
}

// MarkedDNSDialer rotates marked UDP forwards through the pinned source-port range.
func MarkedDNSDialer(timeout time.Duration) *net.Dialer {
	span := uint32(dnsForwardPortHigh - dnsForwardPortLow + 1)
	port := dnsForwardPortLow + int(dnsForwardPort.Add(1)%span)

	d := MarkedDialer(timeout)
	d.LocalAddr = &net.UDPAddr{IP: nil, Port: port, Zone: ""}

	return d
}
