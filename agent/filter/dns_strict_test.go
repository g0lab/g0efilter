//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func answerA(name, ip string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl, Rdlength: 0},
		A:   net.ParseIP(ip),
	}
}

func answerAAAA(name, ip string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl, Rdlength: 0},
		AAAA: net.ParseIP(ip),
	}
}

func TestExtractAnswerIPs(t *testing.T) {
	t.Parallel()

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
			Target: "cdn.example.net.",
		},
		answerA("cdn.example.net.", "140.82.112.3", 60),
		answerA("cdn.example.net.", "140.82.112.4", 30),
		answerAAAA("cdn.example.net.", "2606:4700:4700::1111", 120),
	}

	ips, ttl := extractAnswerIPs(msg)

	want := []string{"140.82.112.3", "140.82.112.4", "2606:4700:4700::1111"}
	if len(ips) != len(want) {
		t.Fatalf("ips = %v, want %v", ips, want)
	}

	for i, ip := range want {
		if ips[i] != ip {
			t.Errorf("ips[%d] = %q, want %q", i, ips[i], ip)
		}
	}

	// CNAME TTL (300) is ignored; minimum across address records wins
	if ttl != 30 {
		t.Errorf("ttl = %d, want 30 (min across A/AAAA)", ttl)
	}
}

func TestExtractAnswerIPsEmptyAnswer(t *testing.T) {
	t.Parallel()

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
			Target: "b.example.com.",
		},
	}

	ips, _ := extractAnswerIPs(msg)
	if len(ips) != 0 {
		t.Errorf("ips = %v, want none for CNAME-only answer", ips)
	}
}

//nolint:exhaustruct
func TestReportResolvedIPsInvokesHook(t *testing.T) {
	t.Parallel()

	var (
		gotIPs []string
		gotTTL uint32
	)

	h := &dnsHandler{
		opts: Options{
			OnResolved: func(ips []string, ttl uint32) {
				gotIPs = ips
				gotTTL = ttl
			},
		},
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{answerA("github.com.", "140.82.112.3", 42)}

	h.reportResolvedIPs(nil, msg, "github.com")

	if len(gotIPs) != 1 || gotIPs[0] != "140.82.112.3" || gotTTL != 42 {
		t.Errorf("hook got ips=%v ttl=%d, want [140.82.112.3] 42", gotIPs, gotTTL)
	}
}

//nolint:exhaustruct
func TestReportResolvedIPsNilHookAndEmptyAnswer(t *testing.T) {
	t.Parallel()

	// nil hook must be a no-op
	h := &dnsHandler{opts: Options{}}
	h.reportResolvedIPs(nil, new(dns.Msg), "example.com")

	// hook must not fire for answers with no addresses
	called := false
	h2 := &dnsHandler{opts: Options{OnResolved: func(_ []string, _ uint32) { called = true }}}
	h2.reportResolvedIPs(nil, new(dns.Msg), "example.com")

	if called {
		t.Error("OnResolved must not fire when the answer has no A/AAAA records")
	}
}

func TestExtractAnswerIPsZeroTTL(t *testing.T) {
	t.Parallel()

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		answerA("x.example.com.", "192.0.2.1", 0),
		answerA("x.example.com.", "192.0.2.2", 300),
	}

	_, ttl := extractAnswerIPs(msg)
	if ttl != 0 {
		t.Errorf("ttl = %d, want 0 (a TTL=0 record must not be overridden by a later, larger TTL)", ttl)
	}
}
