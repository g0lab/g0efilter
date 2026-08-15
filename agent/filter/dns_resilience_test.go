//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/recovery"
	"github.com/miekg/dns"
)

type panicWriter struct {
	mockDNSResponseWriter
}

func (p *panicWriter) WriteMsg(*dns.Msg) error {
	panic("panic while answering")
}

func TestDNSHandleContainsPanic(t *testing.T) {
	t.Parallel()

	lg, buf := testLogger()

	handler := createDNSHandler([]string{"example.com"}, Options{Logger: lg})

	request := new(dns.Msg)
	request.SetQuestion("blocked.example.org.", dns.TypeA)

	handler.handle(&panicWriter{}, request)

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Fatalf("panic in the DNS handler was not contained: %q", buf.String())
	}

	if !strings.Contains(buf.String(), `"component":"dns"`) {
		t.Errorf("panic was not attributed to dns: %q", buf.String())
	}
}

func TestDNSHandleContainsPanicOnMalformedRequest(t *testing.T) {
	t.Parallel()

	lg, buf := testLogger()

	handler := createDNSHandler([]string{"example.com"}, Options{Logger: lg})

	handler.handle(&mockDNSResponseWriter{}, nil)

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Fatalf("panic on a malformed request was not contained: %q", buf.String())
	}
}

func TestRunDNSServersStopsSiblingWhenOneFails(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	addr := reservedAddr(t)

	opts := Options{Logger: lg, ListenAddr: addr}
	handler := createDNSHandler([]string{"example.com"}, opts)
	udpSrv, tcpSrv := setupDNSServers(addr, handler)

	returned := make(chan error, 1)

	go func() {
		returned <- runDNSServers(t.Context(), udpSrv, tcpSrv, handler.upstreams, opts)
	}()

	waitFor(t, func() bool { return tcpPortHeld(t, addr) && udpPortHeld(addr) })

	err := tcpSrv.Shutdown()
	if err != nil {
		t.Fatalf("shutdown tcp: %v", err)
	}

	select {
	case runErr := <-returned:
		if runErr == nil {
			t.Fatal("runDNSServers returned nil after the TCP half exited")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runDNSServers did not return after the TCP half exited")
	}

	if udpPortHeld(addr) {
		t.Error("the UDP sibling was left bound after its partner failed")
	}
}

func TestRunDNSServersReturnsNilOnCancellation(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	addr := reservedAddr(t)

	opts := Options{Logger: lg, ListenAddr: addr}
	handler := createDNSHandler([]string{"example.com"}, opts)
	udpSrv, tcpSrv := setupDNSServers(addr, handler)

	ctx, cancel := context.WithCancel(t.Context())

	returned := make(chan error, 1)

	go func() {
		returned <- runDNSServers(ctx, udpSrv, tcpSrv, handler.upstreams, opts)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case runErr := <-returned:
		if runErr != nil {
			t.Fatalf("runDNSServers = %v, want nil on cancellation", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runDNSServers did not return after cancellation")
	}

	if tcpPortHeld(t, addr) {
		t.Error("the TCP port was still held after shutdown")
	}
}
