//nolint:testpackage // Exercises the unexported matcher entry point.
package filter

import "testing"

// matchCase is a pattern with hosts that must match and hosts that must not
// (including deliberate near-misses). Unlike the equivalence tests, these assert
// absolute correctness, so a regex-anchoring or semantics bug is caught.
type matchCase struct {
	pattern string
	match   []string
	noMatch []string
}

// literalAndAnchorCases: literal regexes and anchoring / substring-injection near-misses.
func literalAndAnchorCases() []matchCase {
	return []matchCase{
		{
			pattern: `/^api\.example\.com$/`,
			match:   []string{"api.example.com", "API.EXAMPLE.COM", "Api.Example.Com"},
			noMatch: []string{
				"xapi.example.com", "api.example.com.evil.net", "api.example.co",
				"apixexample.com", "api.example.comm", "api-example.com",
				".api.example.com", "sub.api.example.com",
			},
		},
		{
			pattern: `/example\.com/`, // inner unanchored, wrapper anchors the whole host
			match:   []string{"example.com"},
			noMatch: []string{
				"example.com.evil.net", "notexample.com", "sub.example.com",
				"example.comm", "aexample.com", "example.co",
			},
		},
		{
			pattern: `/^(one\.example\.com|two\.example\.com)$/`,
			match:   []string{"one.example.com", "two.example.com"},
			noMatch: []string{"three.example.com", "one.example.com.evil", "oneexample.com", "one.example.co"},
		},
		{
			pattern: `/^localhost$/`,
			match:   []string{"localhost", "LOCALHOST"},
			noMatch: []string{"localhost.localdomain", "xlocalhost", "localhosts", ".localhost"},
		},
	}
}

// classAndQuantifierCases: character classes, quantifiers, and count boundaries.
func classAndQuantifierCases() []matchCase {
	return []matchCase{
		{
			pattern: `/^api-[0-9]+\.example\.com$/`,
			match:   []string{"api-1.example.com", "api-123.example.com"},
			noMatch: []string{
				"api-.example.com", "api-abc.example.com", "api-1a.example.com",
				"api-1.example.com.evil", "xapi-1.example.com", "api-1.example.org",
			},
		},
		{
			pattern: `/^[a-z]{2,5}\.example\.com$/`,
			match:   []string{"ab.example.com", "abcde.example.com", "AB.example.com"},
			noMatch: []string{"a.example.com", "abcdef.example.com", "a1.example.com", "ab-.example.com"},
		},
		{
			pattern: `/^[^.]+\.example\.com$/`, // exactly one label, no dots
			match:   []string{"api.example.com", "x.example.com", "a-b.example.com"},
			noMatch: []string{"a.b.example.com", "example.com", ".example.com"},
		},
		{
			pattern: `/^node-[0-9]{2}-[a-z]{3}\.cluster\.local$/`,
			match:   []string{"node-01-abc.cluster.local"},
			noMatch: []string{
				"node-1-abc.cluster.local", "node-012-abc.cluster.local",
				"node-01-abcd.cluster.local", "node-01-ab.cluster.local",
				"node-01-abc.cluster.local.evil",
			},
		},
	}
}

// groupWildcardAndDotCases: groups, optional labels, the unescaped-dot metachar, and wildcards.
func groupWildcardAndDotCases() []matchCase {
	return []matchCase{
		{
			pattern: `/^(api|cdn|static)\.example\.com$/`,
			match:   []string{"api.example.com", "cdn.example.com", "static.example.com"},
			noMatch: []string{"apis.example.com", "ap.example.com", "api.example.net", "api.cdn.example.com"},
		},
		{
			pattern: `/^(www\.)?example\.shop$/`,
			match:   []string{"example.shop", "www.example.shop"},
			noMatch: []string{"wwww.example.shop", "ww.example.shop", "api.example.shop", "example.shopx"},
		},
		{
			pattern: `/^(.*\.)?example\.zone$/`, // apex or any subdomain
			match:   []string{"example.zone", "a.example.zone", "a.b.example.zone"},
			noMatch: []string{"notexample.zone", "example.zone.evil", "xexample.zone"},
		},
		{
			pattern: `/^api.example\.com$/`, // unescaped dot matches exactly one char
			match:   []string{"api.example.com", "apixexample.com", "apiXexample.com"},
			noMatch: []string{"apiexample.com", "apixxexample.com", "api.example.com.evil"},
		},
		{
			pattern: `*.example.com`, // suffix wildcard, not regex
			match:   []string{"a.example.com", "a.b.example.com", "A.Example.Com"},
			noMatch: []string{"example.com", "aexample.com", "example.com.evil", ".example.com", "xexample.com"},
		},
	}
}

// moreLiteralCases: exact matching, trailing-dot and case normalization, IDNA, and $-only anchors.
func moreLiteralCases() []matchCase {
	return []matchCase{
		{
			pattern: "example.com",                                          // exact (non-regex)
			match:   []string{"example.com", "EXAMPLE.COM", "example.com."}, // trailing dot normalized away
			noMatch: []string{"sub.example.com", "example.com.evil", "xexample.com", "example.co", "example.comm"},
		},
		{
			pattern: `/example\.com$/`, // only a trailing anchor inside; wrapper still anchors the start
			match:   []string{"example.com"},
			noMatch: []string{"sub.example.com", "example.com.evil", "xexample.com"},
		},
		{
			pattern: "münchen.de", // IDNA: unicode + case both normalize to the same punycode
			match:   []string{"münchen.de", "MÜNCHEN.DE"},
			noMatch: []string{"munchen.de", "muenchen.de", "xn--wrong.de"},
		},
		{
			pattern: `/^[0-9]{1,3}\.example\.net$/`,
			match:   []string{"1.example.net", "123.example.net"},
			noMatch: []string{"1234.example.net", "a.example.net", ".example.net"},
		},
	}
}

// moreWildcardCases: multi-level suffixes, double public suffix, and mid-name boundaries.
func moreWildcardCases() []matchCase {
	return []matchCase{
		{
			pattern: "*.a.example.com",
			match:   []string{"x.a.example.com", "y.x.a.example.com"},
			noMatch: []string{"a.example.com", "x.b.example.com", "xa.example.com"},
		},
		{
			pattern: "*.co.uk",
			match:   []string{"example.co.uk", "a.b.co.uk"},
			noMatch: []string{"co.uk", "xco.uk", "example.co.ukx"},
		},
		{
			pattern: "sub.*.domain.com",
			match:   []string{"sub.x.domain.com", "sub.x.y.domain.com"},
			noMatch: []string{"sub..domain.com", "xsub.a.domain.com", "sub.a.domain.com.evil", "sub.domain.com"},
		},
		{
			pattern: "gitea-*.r2.cloudflarestorage.com",
			match:   []string{"gitea-abc.r2.cloudflarestorage.com", "gitea-1.r2.cloudflarestorage.com"},
			noMatch: []string{"other.r2.cloudflarestorage.com", "gitea-.r2.cloudflarestorage.com"},
		},
	}
}

// injectionAndSafetyCases: embedded-newline and substring-in-the-middle attempts
// must not match, proving matching is anchored to the whole host.
func injectionAndSafetyCases() []matchCase {
	return []matchCase{
		{
			pattern: `/^.*\.example\.com$/`,
			match:   []string{"a.example.com", "deep.sub.example.com"},
			noMatch: []string{
				"example.com", "a.example.org", "a.example.com.evil",
				"a.example.com\nevil.example.com", // newline injection
			},
		},
		{
			pattern: "*.example.com",
			match:   []string{"a.example.com"},
			noMatch: []string{
				"a.example.com\nevil.com",         // suffix appears mid-string, not at end
				"evil.com.a.example.com.attacker", // real suffix is .attacker
			},
		},
		{
			pattern: "api.example.com", // exact
			// Surrounding whitespace is trimmed by normalizeDomain, so it still matches;
			// interior whitespace/newlines are not, so those must not match.
			match:   []string{"api.example.com", " api.example.com", "api.example.com "},
			noMatch: []string{"api.example.com\nevil", "api.example.com evil", "api.example.com\tevil"},
		},
	}
}

func domainMatchCases() []matchCase {
	cases := literalAndAnchorCases()
	cases = append(cases, classAndQuantifierCases()...)
	cases = append(cases, groupWildcardAndDotCases()...)
	cases = append(cases, moreLiteralCases()...)
	cases = append(cases, moreWildcardCases()...)
	cases = append(cases, injectionAndSafetyCases()...)

	return cases
}

// TestDomainMatchingCorrectness asserts absolute match/no-match results for many
// domain regexes and wildcards against matching hosts and near-miss hosts.
func TestDomainMatchingCorrectness(t *testing.T) {
	t.Parallel()

	for _, tc := range domainMatchCases() {
		allow := []string{tc.pattern}

		for _, host := range tc.match {
			if !allowedHost(host, allow) {
				t.Errorf("pattern %q: %q should MATCH but did not", tc.pattern, host)
			}
		}

		for _, host := range tc.noMatch {
			if allowedHost(host, allow) {
				t.Errorf("pattern %q: %q should NOT match but did", tc.pattern, host)
			}
		}
	}
}

// TestDomainMatchingCombined puts every pattern in one allowlist and re-checks
// each host, so no pattern accidentally matches another's near-misses.
func TestDomainMatchingCombined(t *testing.T) {
	t.Parallel()

	cases := domainMatchCases()

	allow := make([]string, 0, len(cases))
	for _, tc := range cases {
		allow = append(allow, tc.pattern)
	}

	for _, tc := range cases {
		for _, host := range tc.match {
			if !allowedHost(host, allow) {
				t.Errorf("combined: %q should MATCH (via %q) but did not", host, tc.pattern)
			}
		}
	}
}
