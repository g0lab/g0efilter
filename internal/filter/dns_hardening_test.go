//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCheckExfilQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		qname string
		qtype uint16
		want  string
	}{
		{"normal name passes", "github.com", dns.TypeA, ""},
		{"long-ish legit name passes", "gitea-pull-through-cache.abc123.r2.cloudflarestorage.com", dns.TypeA, ""},
		{"dkim-style name passes", "selector1._domainkey.example.com", dns.TypeTXT, ""},
		{"null query refused", "example.com", dns.TypeNULL, "null-query"},
		{
			"exfil-length label refused",
			strings.Repeat("a", 60) + ".tunnel.example.com",
			dns.TypeA,
			"label-too-long",
		},
		{
			"very long qname refused",
			strings.Repeat("abcd456789.", 21) + "example.com", // 242 chars total
			dns.TypeA,
			"qname-too-long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := checkExfilQuery(tt.qname, tt.qtype); got != tt.want {
				t.Errorf("checkExfilQuery(%q) = %q, want %q", tt.qname, got, tt.want)
			}
		})
	}
}

func TestCheckExfilResponse(t *testing.T) {
	t.Parallel()

	if got := checkExfilResponse(nil); got != "" {
		t.Errorf("nil response = %q, want empty", got)
	}

	// Normal answer passes
	normal := new(dns.Msg)
	normal.Answer = []dns.RR{answerA("github.com.", "140.82.112.3", 60)}

	if got := checkExfilResponse(normal); got != "" {
		t.Errorf("normal answer = %q, want empty", got)
	}

	// NULL record rejected
	withNull := new(dns.Msg)
	withNull.Answer = []dns.RR{&dns.NULL{
		Hdr:  dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 60, Rdlength: 0},
		Data: "payload",
	}}

	if got := checkExfilResponse(withNull); got != "null-record" {
		t.Errorf("NULL answer = %q, want null-record", got)
	}

	// Bulky TXT payload rejected; small TXT passes
	smallTXT := new(dns.Msg)
	smallTXT.Answer = []dns.RR{txtRecord("v=spf1 include:_spf.example.com ~all")}

	if got := checkExfilResponse(smallTXT); got != "" {
		t.Errorf("small TXT = %q, want empty", got)
	}

	bigTXT := new(dns.Msg)
	bigTXT.Answer = []dns.RR{txtRecord(strings.Repeat("x", 600)), txtRecord(strings.Repeat("y", 600))}

	if got := checkExfilResponse(bigTXT); got != "txt-payload-too-large" {
		t.Errorf("bulky TXT = %q, want txt-payload-too-large", got)
	}
}

func txtRecord(payload string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: "t.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60, Rdlength: 0},
		Txt: []string{payload},
	}
}

func TestDNSRateLimiter(t *testing.T) {
	t.Parallel()

	l := newDNSRateLimiter(0, 0)
	now := time.Now()
	l.now = func() time.Time { return now }

	// Burst allowance
	for i := range dnsRateLimitBurst {
		if !l.allow("10.0.0.1") {
			t.Fatalf("query %d within burst must pass", i)
		}
	}

	if l.allow("10.0.0.1") {
		t.Error("query beyond burst must be limited")
	}

	// A different source has its own bucket
	if !l.allow("10.0.0.2") {
		t.Error("other sources must not be affected")
	}

	// Refill after time passes
	now = now.Add(time.Second)

	if !l.allow("10.0.0.1") {
		t.Error("tokens must refill over time")
	}
}

func TestDNSRateLimiterCustomLimits(t *testing.T) {
	t.Parallel()

	l := newDNSRateLimiter(10, 5)
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := range 5 {
		if !l.allow("10.0.0.1") {
			t.Fatalf("query %d within custom burst must pass", i)
		}
	}

	if l.allow("10.0.0.1") {
		t.Error("query beyond custom burst must be limited")
	}

	now = now.Add(100 * time.Millisecond)

	if !l.allow("10.0.0.1") {
		t.Error("token must refill at the custom rate")
	}

	if l.allow("10.0.0.1") {
		t.Error("only one token should have refilled")
	}

	d := newDNSRateLimiter(0, -1)
	if d.qps != dnsRateLimitQPS || d.burst != dnsRateLimitBurst {
		t.Errorf("defaults not applied: qps=%v burst=%v", d.qps, d.burst)
	}
}

func TestDNSRateLimiterBoundedUnderSourceFlood(t *testing.T) {
	t.Parallel()

	l := newDNSRateLimiter(0, 0)
	now := time.Now()
	l.now = func() time.Time { return now }

	// A flood of always-fresh spoofed sources: idle pruning never applies, so
	// the hard cap must bound the bucket map.
	for i := range rateLimiterMaxSources * 2 {
		l.allow("src-" + strconv.Itoa(i))

		now = now.Add(time.Millisecond)
	}

	if len(l.buckets) > rateLimiterMaxSources {
		t.Errorf("buckets = %d, want <= %d", len(l.buckets), rateLimiterMaxSources)
	}
}

//nolint:exhaustruct
func TestBlockExfilQueryModes(t *testing.T) {
	t.Parallel()

	longLabel := strings.Repeat("a", 60) + ".example.com"

	// Enforcing: violation answered with REFUSED
	h := &dnsHandler{opts: Options{DNSHardening: true}}
	w := &captureWriter{}

	if !h.blockExfilQuery(nil, w, new(dns.Msg), longLabel, dns.TypeA, "1.2.3.4", 1234, "") {
		t.Error("hardening violation must block when enforcing")
	}

	if w.msg == nil || w.msg.Rcode != dns.RcodeRefused {
		t.Error("expected REFUSED response")
	}

	// Audit mode: logged only, query proceeds
	hAudit := &dnsHandler{opts: Options{DNSHardening: true, AuditMode: true}}

	if hAudit.blockExfilQuery(nil, &captureWriter{}, new(dns.Msg), longLabel, dns.TypeA, "1.2.3.4", 1234, "") {
		t.Error("audit mode must not block hardening violations")
	}

	// Hardening off: no checks
	hOff := &dnsHandler{opts: Options{}}
	if hOff.blockExfilQuery(nil, &captureWriter{}, new(dns.Msg), longLabel, dns.TypeA, "1.2.3.4", 1234, "") {
		t.Error("disabled hardening must not block")
	}
}

// captureWriter records the response message written by the handler.
type captureWriter struct {
	dns.ResponseWriter

	msg *dns.Msg
}

func (w *captureWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m

	return nil
}
