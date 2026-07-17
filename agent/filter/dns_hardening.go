package filter

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS hardening blocks deterministic tunneling shapes without noisy entropy checks.
const (
	exfilMaxQname = 220
	exfilMaxLabel = 56

	maxTXTPayloadBytes = 1024
	maxResponseBytes   = 4096

	dnsRateLimitQPS   = 50
	dnsRateLimitBurst = 100

	rateLimiterMaxSources = 4096
	rateLimiterIdleEvict  = time.Minute
)

// checkExfilQuery returns a non-empty reason when a query looks like a tunnel/exfil channel.
func checkExfilQuery(qname string, qtype uint16) string {
	if qtype == dns.TypeNULL {
		return "null-query"
	}

	if len(qname) > exfilMaxQname {
		return "qname-too-long"
	}

	for label := range strings.SplitSeq(qname, ".") {
		if len(label) > exfilMaxLabel {
			return "label-too-long"
		}
	}

	return ""
}

// checkExfilResponse returns a non-empty reason when an upstream answer looks like
// a tunnel payload (oversized message, NULL records, bulky TXT rdata).
func checkExfilResponse(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}

	if resp.Len() > maxResponseBytes {
		return "response-too-large"
	}

	txtBytes := 0

	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.NULL:
			return "null-record"
		case *dns.TXT:
			for _, s := range record.Txt {
				txtBytes += len(s)
			}
		}
	}

	if txtBytes > maxTXTPayloadBytes {
		return "txt-payload-too-large"
	}

	return ""
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// dnsRateLimiter is enforced even in audit/learning mode to protect the proxy.
type dnsRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time
	qps     float64
	burst   float64
}

// newDNSRateLimiter falls back to defaults for qps/burst values <= 0.
func newDNSRateLimiter(qps, burst int) *dnsRateLimiter {
	l := &dnsRateLimiter{
		mu:      sync.Mutex{},
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
		qps:     dnsRateLimitQPS,
		burst:   dnsRateLimitBurst,
	}

	if qps > 0 {
		l.qps = float64(qps)
	}

	if burst > 0 {
		l.burst = float64(burst)
	}

	return l
}

func (l *dnsRateLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	bucket, ok := l.buckets[source]
	if !ok {
		if len(l.buckets) >= rateLimiterMaxSources {
			l.pruneLocked(now)
		}

		// A flood of fresh spoofed sources defeats idle pruning; evict the
		// longest-idle bucket so the map stays bounded.
		if len(l.buckets) >= rateLimiterMaxSources {
			l.evictOldestLocked()
		}

		bucket = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[source] = bucket
	}

	bucket.tokens += now.Sub(bucket.last).Seconds() * l.qps
	if bucket.tokens > l.burst {
		bucket.tokens = l.burst
	}

	bucket.last = now

	if bucket.tokens < 1 {
		return false
	}

	bucket.tokens--

	return true
}

func (l *dnsRateLimiter) pruneLocked(now time.Time) {
	for src, bucket := range l.buckets {
		if now.Sub(bucket.last) > rateLimiterIdleEvict {
			delete(l.buckets, src)
		}
	}
}

func (l *dnsRateLimiter) evictOldestLocked() {
	var (
		oldestSrc string
		oldestAt  time.Time
	)

	for src, bucket := range l.buckets {
		if oldestSrc == "" || bucket.last.Before(oldestAt) {
			oldestSrc = src
			oldestAt = bucket.last
		}
	}

	if oldestSrc != "" {
		delete(l.buckets, oldestSrc)
	}
}
