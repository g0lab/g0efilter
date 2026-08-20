//nolint:testpackage // Exercises unexported DNS IP-allowlist internals.
package filter

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// startTestUpstream runs a UDP DNS server answering from records keyed by
// "<qname>/<qtype>" (e.g. "host.example./AAAA"). It returns the listen address
// for handler.upstreams.
func startTestUpstream(t *testing.T, records map[string][]dns.RR) string {
	t.Helper()

	var lc net.ListenConfig

	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)

		if len(r.Question) > 0 {
			q := r.Question[0]
			reply.Answer = records[q.Name+"/"+typeString(q.Qtype)]
		}

		_ = w.WriteMsg(reply)
	})}

	go func() { _ = srv.ActivateAndServe() }()

	t.Cleanup(func() { _ = srv.Shutdown() })

	return pc.LocalAddr().String()
}

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

func TestIPAllowlistStripsPortConstraints(t *testing.T) {
	t.Parallel()

	m := newIPAllowlist([]string{
		"tcp/40.89.244.232:443",
		"udp/[2001:db8::/32]:53",
	})

	if m.len() != 2 {
		t.Fatalf("len = %d, want 2", m.len())
	}

	if !m.contains(net.ParseIP("40.89.244.232")) {
		t.Error("constrained IPv4 entry did not match its address")
	}

	if !m.contains(net.ParseIP("2001:db8::1")) {
		t.Error("constrained IPv6 CIDR did not match an address in its range")
	}

	if m.contains(net.ParseIP("2001:dead::1")) {
		t.Error("constrained IPv6 CIDR matched an address outside its range")
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
	if len(kept) != 3 {
		t.Fatalf("kept %d records, want 3", len(kept))
	}

	if _, ok := kept[0].(*dns.CNAME); !ok {
		t.Fatalf("first kept record = %T, want CNAME", kept[0])
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
		case *dns.CNAME:
		default:
			t.Errorf("unexpected record leaked into reply: %T", rr)
		}
	}
}

// TestResolveViaIPAllowlistNoIPsSkips proves the gate: with no IP allowlist the
// path returns false without forwarding upstream or writing a response, so a
// plain sinkhole still happens.
func TestResolveViaIPAllowlistNoIPsSkips(t *testing.T) {
	t.Parallel()

	handler := createDNSHandler(nil, Options{})

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

// TestSiblingResolvesToAllowlistedIP proves an AAAA miss consults the A family
// (and vice versa) so a dual-stack host allowlisted by one family is reachable.
func TestSiblingResolvesToAllowlistedIP(t *testing.T) {
	t.Parallel()

	name := "dualstack.example."
	up := startTestUpstream(t, map[string][]dns.RR{
		name + "/A":    {answerA(name, "40.89.244.232", 60)},
		name + "/AAAA": {answerAAAA(name, "2606:4700::1", 60)},
	})

	handler := createDNSHandler(nil, Options{})
	handler.ipAllow = newIPAllowlist([]string{"40.89.244.232"})
	handler.upstreams = []string{up}

	if !handler.siblingResolvesToAllowlistedIP("dualstack.example", dns.TypeAAAA) {
		t.Error("AAAA query: expected sibling A to be allowlisted")
	}

	if handler.siblingResolvesToAllowlistedIP("dualstack.example", dns.TypeA) {
		t.Error("A query: sibling AAAA is not allowlisted, want false")
	}

	if handler.siblingResolvesToAllowlistedIP("dualstack.example", dns.TypeMX) {
		t.Error("non-address qtype has no sibling, want false")
	}
}

// TestResolveViaIPAllowlistSiblingNoData proves the false-positive fix: an AAAA
// probe for an IPv4-only allowlisted host is answered with the zero-address
// sinkhole (not empty NODATA, which would make the resolver walk its search
// list), so the host stays reachable via IPv4 and no BLOCKED alert fires.
func TestResolveViaIPAllowlistSiblingSinkhole(t *testing.T) {
	t.Parallel()

	name := "dualstack.example."
	up := startTestUpstream(t, map[string][]dns.RR{
		name + "/A":    {answerA(name, "40.89.244.232", 60)},
		name + "/AAAA": {answerAAAA(name, "2606:4700::1", 60)},
	})

	handler := createDNSHandler(nil, Options{})
	handler.ipAllow = newIPAllowlist([]string{"40.89.244.232"})
	handler.upstreams = []string{up}

	writer := &mockDNSResponseWriter{responses: make([]*dns.Msg, 0)}
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)

	if !handler.resolveViaIPAllowlist(nil, writer, msg, "dualstack.example", dns.TypeAAAA, "1.1.1.1", 1234, "flow") {
		t.Fatal("expected AAAA to be handled via sibling IP allowlist")
	}

	if len(writer.responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(writer.responses))
	}

	resp := writer.responses[0]
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", resp.Rcode)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 sinkhole answer, got %d", len(resp.Answer))
	}

	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok || !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("expected :: sinkhole answer, got %v", resp.Answer[0])
	}
}

// TestHandleAAAASiblingLogsAllowedNotBlocked drives the full handler and asserts
// the dual-stack AAAA probe logs ALLOWED, never the BLOCKED event that would
// trigger a notification.
func TestHandleAAAASiblingLogsAllowedNotBlocked(t *testing.T) {
	t.Parallel()

	name := "dualstack.example."
	up := startTestUpstream(t, map[string][]dns.RR{
		name + "/A":    {answerA(name, "40.89.244.232", 60)},
		name + "/AAAA": {answerAAAA(name, "2606:4700::1", 60)},
	})

	var buf bytes.Buffer

	handler := createDNSHandler(nil, Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	handler.ipAllow = newIPAllowlist([]string{"40.89.244.232"})
	handler.upstreams = []string{up}

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	handler.handle(&mockDNSResponseWriter{responses: make([]*dns.Msg, 0)}, msg)

	logged := buf.String()
	if strings.Contains(logged, "dns.blocked") || strings.Contains(logged, `"action":"BLOCKED"`) {
		t.Errorf("dual-stack AAAA must not emit a BLOCKED event, got: %s", logged)
	}

	if strings.Contains(logged, `"alert":true`) {
		t.Errorf("benign sibling sinkhole must not flag an alert, got: %s", logged)
	}

	if !strings.Contains(logged, "ip-allowlisted-other-family") {
		t.Errorf("expected ip-allowlisted-other-family note, got: %s", logged)
	}
}

// TestHandleAAAANeitherFamilyBlocks proves a genuine block still alerts: when no
// family resolves to an allowlisted IP the AAAA query is sinkholed and BLOCKED.
func TestHandleAAAANeitherFamilyBlocks(t *testing.T) {
	t.Parallel()

	name := "evil.example."
	up := startTestUpstream(t, map[string][]dns.RR{
		name + "/A":    {answerA(name, "203.0.113.7", 60)},
		name + "/AAAA": {answerAAAA(name, "2606:4700::1", 60)},
	})

	var buf bytes.Buffer

	handler := createDNSHandler(nil, Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	handler.ipAllow = newIPAllowlist([]string{"40.89.244.232"})
	handler.upstreams = []string{up}

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	handler.handle(&mockDNSResponseWriter{responses: make([]*dns.Msg, 0)}, msg)

	logged := buf.String()
	if !strings.Contains(logged, "dns.blocked") {
		t.Errorf("expected dns.blocked for a domain with no allowlisted IP, got: %s", logged)
	}

	if !strings.Contains(logged, `"alert":true`) {
		t.Errorf("genuine block must flag an alert, got: %s", logged)
	}
}
