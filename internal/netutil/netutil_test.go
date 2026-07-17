//nolint:testpackage // Need access to internal implementation details
package netutil

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBypassMarkIsStableAndNonzero(t *testing.T) {
	t.Parallel()

	first := BypassMark()
	if first == 0 {
		t.Fatal("bypass mark must not be zero")
	}

	if second := BypassMark(); second != first {
		t.Fatalf("bypass mark changed during process lifetime: %#x != %#x", first, second)
	}
}

func TestRandomBypassMarkIsNonzeroAndVaries(t *testing.T) {
	t.Parallel()

	first := randomBypassMark()
	for range 8 {
		mark := randomBypassMark()
		if mark == 0 {
			t.Fatal("random bypass mark must not be zero")
		}

		if mark != first {
			return
		}
	}

	t.Fatal("random bypass mark repeated for every sample")
}

// Setting SO_MARK needs CAP_NET_ADMIN or CAP_NET_RAW on recent kernels;
// without either capability the dial must still succeed.
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
