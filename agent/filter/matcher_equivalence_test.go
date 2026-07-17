//nolint:testpackage // Exercises the unexported matcher against its reference.
package filter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

// referenceAllows is the un-bucketed semantics the matcher must agree with: a linear matchPattern scan.
func referenceAllows(patterns []string, host string) bool {
	h := normalizeDomain(host)
	for _, p := range patterns {
		if matchPattern(h, normalizeDomain(p)) {
			return true
		}
	}

	return false
}

// assertEquivalent fails if the matcher disagrees with the reference for host.
func assertEquivalent(t *testing.T, patterns []string, host string) {
	t.Helper()

	want := referenceAllows(patterns, host)
	got := newMatcher(patterns).allows(host)

	if got != want {
		t.Errorf("allows(%q) = %v, want %v (patterns=%v)", host, got, want, patterns)
	}
}

// allDomainPatternVariants covers every matcher bucket, emphasising domain regex shapes.
func allDomainPatternVariants() []string {
	return []string{
		// empty and exact
		"",
		"example.com",
		"api.example.com",
		"a.b.c.example.com",
		// bare wildcard
		"*",
		// leading suffix wildcards
		"*.example.com",
		"*.cdn.example.net",
		"*.co.uk",
		// mid-name wildcards
		"sub.*.sub.domain.com",
		"gitea-*.r2.cloudflarestorage.com",
		"*.foo.*.com",
		"a.*.*.b.com",
		"prefix*.example.org",
		// regex: anchored exact
		`/^exact\.example\.com$/`,
		// regex: unanchored inner (wrapper still anchors whole host)
		`/example\.io/`,
		// regex: any-subdomain
		`/^.*\.example\.dev$/`,
		`/^[^.]+\.example\.dev$/`,
		// regex: character classes and quantifiers
		`/^api-[0-9]+\.example\.com$/`,
		`/^[a-z]{2,5}\.example\.com$/`,
		`/^host-[0-9]{1,3}-prod\.internal$/`,
		// regex: alternation and groups
		`/^(api|cdn|static)\.example\.com$/`,
		`/^(a|b)-[0-9]+\.svc\.local$/`,
		// regex: optional label
		`/^(www\.)?example\.shop$/`,
		// regex: escaped dots vs literal
		`/^cache\.example\.co\.uk$/`,
		// regex: perl classes \d \w
		`/^\d+\.example\.com$/`,
		`/^\w+\.metrics\.example\.com$/`,
		// regex: unescaped dot metacharacter (matches any single char)
		`/^api.example\.com$/`,
		// regex: non-capturing group
		`/^(?:api|cdn)\.example\.net$/`,
		// regex: optional leading labels, apex or subdomain
		`/^(.*\.)?example\.zone$/`,
		// regex: mixed classes and repetition counts
		`/^node-[0-9]{2}-[a-z]{3}\.cluster\.local$/`,
		// regex: uppercase literals, must still match lowercased host (?i)
		`/^API\.EXAMPLE\.io$/`,
		// regex: + and ? quantifiers
		`/^a+b?\.example\.com$/`,
		// regex: escaped plus, literal '+' (never appears in a hostname)
		`/^plus\+sign\.example\.com$/`,
		// regex: trailing-anchored any-prefix
		`/.*\.trailing\.net$/`,
		// regex: anchored single label, no dots
		`/^localhost$/`,
		// regex: alternation of whole hosts
		`/^(one\.example\.com|two\.example\.com)$/`,
		// regex: invalid (RE2 rejects) - must be handled as never-match
		`/^(unclosed\.example\.com$/`,
	}
}

// probeHosts is a broad set of hosts spanning matches, near-misses, and edge cases.
func probeHosts() []string {
	return append(baseProbeHosts(), regexProbeHosts()...)
}

func baseProbeHosts() []string {
	return []string{
		"",
		"example.com",
		"EXAMPLE.COM",
		"api.example.com",
		"a.b.c.example.com",
		"x.example.com",
		"deep.sub.example.com",
		"example.net",
		"www.example.net",
		"cdn.example.net",
		"a.cdn.example.net",
		"example.co.uk",
		"shop.example.co.uk",
		"sub.abc.sub.domain.com",
		"sub.a.b.sub.domain.com",
		"sub.sub.domain.com",
		"xsub.abc.sub.domain.com",
		"gitea-1.r2.cloudflarestorage.com",
		"gitea-.r2.cloudflarestorage.com",
		"other.r2.cloudflarestorage.com",
		"a.foo.bar.com",
		"a.foo.com",
		"a.x.y.b.com",
		"a.b.com",
		"prefixthing.example.org",
		"prefix.example.org",
		"exact.example.com",
		"notexact.example.com",
		"example.io",
		"sub.example.io",
		"anything.example.dev",
		"a.b.example.dev",
		"api-123.example.com",
		"api-.example.com",
		"apix-1.example.com",
		"abc.example.com",
		"toolonglabel.example.com",
		"host-12-prod.internal",
		"host-1234-prod.internal",
		"api.example.com.evil.net",
		"cdn.example.com",
		"static.example.com",
		"z.example.com",
		"a-9.svc.local",
		"c-9.svc.local",
		"www.example.shop",
		"example.shop",
		"bad.example.shop",
		"cache.example.co.uk",
		"cachexexample.co.uk",
		"..example.com",
		"example.com.",
		"a..b.com",
		// leading-dot hosts that equal a registered suffix
		".example.com",
		".cdn.example.net",
		".co.uk",
		".foo.bar.com",
	}
}

func regexProbeHosts() []string {
	return []string{
		// perl classes \d \w
		"123.example.com",
		"12a.example.com",
		"abc.metrics.example.com",
		"ab_c.metrics.example.com",
		"a.b.metrics.example.com",
		// unescaped dot metacharacter
		"apixexample.com",
		"api.example.com",
		"apixxexample.com",
		// non-capturing group
		"api.example.net",
		"cdn.example.net",
		"static.example.net",
		// apex or subdomain
		"example.zone",
		"a.example.zone",
		"a.b.example.zone",
		"notexample.zone",
		// mixed classes and counts
		"node-01-abc.cluster.local",
		"node-1-abc.cluster.local",
		"node-01-abcd.cluster.local",
		// uppercase literal pattern
		"api.example.io",
		"API.EXAMPLE.IO",
		// + and ? quantifiers
		"ab.example.com",
		"aab.example.com",
		"a.example.com",
		"b.example.com",
		// literal plus
		"plus+sign.example.com",
		"plussign.example.com",
		// trailing-anchored any-prefix
		"a.trailing.net",
		"deep.sub.trailing.net",
		"trailing.net",
		// single label, no dots
		"localhost",
		"localhost.localdomain",
		// whole-host alternation
		"one.example.com",
		"two.example.com",
		"three.example.com",
		// invalid regex target
		"unclosed.example.com",
	}
}

// FuzzMatcherEquivalence asserts the bucketed matcher agrees with the linear
// reference for arbitrary pattern/host inputs, catching categorization bugs
// (like a leading-dot suffix) that fixed test cases might miss.
func FuzzMatcherEquivalence(f *testing.F) {
	seeds := []struct{ pattern, host string }{
		{"*.example.com", ".example.com"},
		{"*.example.com", "a.example.com"},
		{"*.example.com", "example.com"},
		{"sub.*.domain.com", "sub.x.domain.com"},
		{`/^api\.example\.com$/`, "api.example.com"},
		{"*", "anything.com"},
		{"", ""},
		{"example.com", "example.com"},
		{"*.co.uk", ".co.uk"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.host)
	}

	f.Fuzz(func(t *testing.T, pattern, host string) {
		patterns := []string{pattern}
		want := referenceAllows(patterns, host)

		if got := newMatcher(patterns).allows(host); got != want {
			t.Errorf("divergence: pattern=%q host=%q got=%v want=%v", pattern, host, got, want)
		}
	})
}

// TestMatcherEquivalencePerPattern catches categorization bugs in any single pattern shape.
func TestMatcherEquivalencePerPattern(t *testing.T) {
	t.Parallel()

	for _, p := range allDomainPatternVariants() {
		patterns := []string{p}
		for _, host := range probeHosts() {
			assertEquivalent(t, patterns, host)
		}
	}
}

// TestMatcherEquivalenceCombined covers interactions between buckets in one matcher.
func TestMatcherEquivalenceCombined(t *testing.T) {
	t.Parallel()

	patterns := allDomainPatternVariants()
	for _, host := range probeHosts() {
		assertEquivalent(t, patterns, host)
	}
}

// TestMatcherEquivalenceLargeGenerated stresses the buckets with a large mixed allowlist.
func TestMatcherEquivalenceLargeGenerated(t *testing.T) {
	t.Parallel()

	const n = 2000

	patterns := make([]string, 0, n*3)
	for i := range n {
		patterns = append(patterns,
			fmt.Sprintf("host-%05d.example.com", i),
			fmt.Sprintf("*.svc-%05d.example.net", i),
			fmt.Sprintf(`/^api-%05d-[0-9]+\.example\.org$/`, i),
		)
	}

	matcher := newMatcher(patterns)

	hosts := []string{
		"host-00000.example.com",
		"host-01999.example.com",
		"host-02000.example.com", // out of range: miss
		"host-99999.example.com",
		"a.svc-00042.example.net",
		"deep.a.svc-01234.example.net",
		"svc-00042.example.net", // apex: suffix wildcard must not match
		"a.svc-99999.example.net",
		"api-00007-42.example.org",
		"api-00007-.example.org", // needs at least one digit: miss
		"api-99999-1.example.org",
		"nope.example.io",
		"",
	}

	for _, host := range hosts {
		want := referenceAllows(patterns, host)
		if got := matcher.allows(host); got != want {
			t.Errorf("large: allows(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLongestLiteralChunk(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"sub.*.sub.domain.com": ".sub.domain.com",
		"gitea-*.r2.com":       ".r2.com",
		"*.foo.*.com":          ".foo.",
		"a.*.*.b.com":          ".b.com",
		"prefix*.example.org":  ".example.org",
		"*.example.com":        ".example.com",
	}

	for pattern, want := range cases {
		if got := longestLiteralChunk(pattern); got != want {
			t.Errorf("longestLiteralChunk(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// TestPreFilterNeverChangesResult proves the required-literal gate never changes a match.
func TestPreFilterNeverChangesResult(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"sub.*.sub.domain.com",
		"*.foo.*.com",
		"a.*.*.b.com",
	}

	for _, p := range patterns {
		re, err := policy.CompileWildcardPattern(normalizeDomain(p))
		if err != nil {
			t.Fatalf("compile %q: %v", p, err)
		}

		required := longestLiteralChunk(p)
		matcher := newMatcher([]string{p})

		for _, host := range probeHosts() {
			h := normalizeDomain(host)
			gated := strings.Contains(h, required) && re.MatchString(h)

			if got := matcher.allows(host); got != gated {
				t.Errorf("pattern %q host %q: matcher=%v gated-regex=%v", p, host, got, gated)
			}

			// Soundness: no host may match the regex without the required literal.
			if !strings.Contains(h, required) && re.MatchString(h) {
				t.Errorf("pattern %q host %q: regex matched without required literal %q", p, host, required)
			}
		}
	}
}
