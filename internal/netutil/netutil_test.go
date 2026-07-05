//nolint:testpackage // Need access to internal implementation details
package netutil

import (
	"context"
	"net"
	"testing"
	"time"
)

// Setting SO_MARK needs CAP_NET_ADMIN; without it the dial must still succeed
// (unprivileged test/dev environments have no nftables rules to bypass anyway).
func TestMarkedDialerBestEffort(t *testing.T) {
	t.Parallel()

	var lc net.ListenConfig

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = ln.Close() }()

	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			_ = conn.Close()
		}
	}()

	conn, err := MarkedDialer(2*time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial must succeed without CAP_NET_ADMIN: %v", err)
	}

	_ = conn.Close()
}

func TestMarkedDNSDialerPortRange(t *testing.T) {
	t.Parallel()

	var lc net.ListenConfig

	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = pc.Close() }()

	seen := make(map[int]struct{})

	for range 3 {
		conn, dErr := MarkedDNSDialer(2*time.Second).Dial("udp", pc.LocalAddr().String())
		if dErr != nil {
			t.Fatalf("dial failed: %v", dErr)
		}

		addr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			t.Fatalf("unexpected local addr type %T", conn.LocalAddr())
		}

		if addr.Port < dnsForwardPortLow || addr.Port > dnsForwardPortHigh {
			t.Errorf("source port %d outside pinned range %d-%d", addr.Port, dnsForwardPortLow, dnsForwardPortHigh)
		}

		seen[addr.Port] = struct{}{}

		_ = conn.Close()
	}

	if len(seen) != 3 {
		t.Errorf("expected 3 distinct rotated ports, got %d", len(seen))
	}
}
