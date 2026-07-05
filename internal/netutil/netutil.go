// Package netutil provides the SO_MARK dialer that lets g0efilter's own
// outbound traffic (proxy upstreams, dashboard shipping, notifications)
// bypass its nftables rules.
package netutil

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// BypassMark is matched by a "meta mark 0x1" rule in every generated ruleset.
const BypassMark = 0x1

// UDP DNS forwards bind above Linux's default ephemeral range to avoid
// conntrack tuple collisions with redirected client queries.
const (
	dnsForwardPortLow  = 61000
	dnsForwardPortHigh = 64999
)

//nolint:gochecknoglobals // rotating allocator for the forward source ports
var dnsForwardPort atomic.Uint32

// MarkedDialer returns a dialer with SO_MARK set so connections bypass the
// nftables REDIRECT/filter rules. Setting the mark needs CAP_NET_ADMIN and is
// best-effort: a real deployment always has the capability (nftables setup
// would fail without it), so a failure here only happens in unprivileged
// test/dev environments where no rules are active anyway.
func MarkedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_ string, _ string, rc syscall.RawConn) error {
			err := rc.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, BypassMark)
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
