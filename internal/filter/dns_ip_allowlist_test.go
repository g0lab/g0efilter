//nolint:testpackage // Exercises unexported DNS IP-allowlist internals.
package filter

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestIPAllowlistContains(t *testing.T) {
	t.Parallel()

	m := newIPAllowlist([]string{
		"40.89.244.232",
		"10.0.0.0/8",
		"2001:db8::/32",
		"::1",
		"  ",        // blank, ignored
		"not-an-ip", // malformed, ignored
	})

	if m.len() != 4 {
		t.Fatalf("len = %d, want 4", m.len())
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"40.89.244.232", true},
		{"40.89.244.233", false},
		{"10.1.2.3", true},  // inside 10.0.0.0/8
		{"11.0.0.1", false}, // outside
		{"2001:db8::1", true},
		{"2001:dead::1", false},
		{"::1", true},
		{"", false},
	}

	for _, c := range cases {
		if got := m.contains(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIPAllowlistEmpty(t *testing.T) {
	t.Parallel()

	if m := newIPAllowlist(nil); m.len() != 0 {
		t.Errorf("nil entries: len = %d, want 0", m.len())
	}

	if m := newIPAllowlist([]string{"", "  "}); m.len() != 0 {
		t.Errorf("blank entries: len = %d, want 0", m.len())
	}
}

func TestFilterToAllowlistedIPs(t *testing.T) {
	t.Parallel()

	handler := &dnsHandler{ipAllow: newIPAllowlist([]string{"40.89.244.232", "2001:db8::/32"})}

	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: "x.", Rrtype: t, Class: dns.ClassINET, Ttl: 60}
	}

	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: "y."},
		&dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP("40.89.244.232")},        // keep
		&dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP("1.2.3.4")},              // drop
		&dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")}, // keep
		&dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.ParseIP("2606::1")},     // drop
	}

	kept := handler.filterToAllowlistedIPs(resp)
	if len(kept) != 2 {
		t.Fatalf("kept %d records, want 2", len(kept))
	}

	for _, rr := range kept {
		switch rec := rr.(type) {
		case *dns.A:
			if !rec.A.Equal(net.ParseIP("40.89.244.232")) {
				t.Errorf("unexpected A record kept: %v", rec.A)
			}
		case *dns.AAAA:
			if !rec.AAAA.Equal(net.ParseIP("2001:db8::1")) {
				t.Errorf("unexpected AAAA record kept: %v", rec.AAAA)
			}
		default:
			t.Errorf("non-address record leaked into reply: %T", rr)
		}
	}
}

// TestResolveViaIPAllowlistNoIPsSkips proves the gate: with no IP allowlist the
// path returns false without forwarding upstream or writing a response, so a
// plain sinkhole still happens.
func TestResolveViaIPAllowlistNoIPsSkips(t *testing.T) {
	t.Parallel()

	handler := createDNSHandler(nil, Options{}) //nolint:exhaustruct

	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.com.", dns.TypeA)

	writer := &mockDNSResponseWriter{responses: make([]*dns.Msg, 0)}

	if handler.resolveViaIPAllowlist(nil, writer, msg, "blocked.example.com", dns.TypeA, "1.1.1.1", 1234, "flow") {
		t.Error("resolveViaIPAllowlist returned true with an empty IP allowlist")
	}

	if len(writer.responses) != 0 {
		t.Errorf("expected no response written, got %d", len(writer.responses))
	}
}
