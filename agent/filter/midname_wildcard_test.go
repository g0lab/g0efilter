//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"testing"
)

// Mid-name wildcards and their regex equivalents must behave identically:
// '*' spans one or more characters including dots, anchored to the whole host.
func TestMidNameWildcardAndRegexEquivalence(t *testing.T) {
	t.Parallel()

	wildcard := NormalizePatterns([]string{"sub.*.sub.domain.com"})
	regex := NormalizePatterns([]string{`/^sub\..+\.sub\.domain\.com$/`})

	cases := []struct {
		host string
		want bool
	}{
		{"sub.abc123.sub.domain.com", true},
		{"sub.a.b.sub.domain.com", true}, // '*' crosses label boundaries
		{"SUB.ABC.SUB.DOMAIN.COM", true}, // case-insensitive
		{"sub.sub.domain.com", false},    // wildcard requires at least one char
		{"xsub.abc.sub.domain.com", false},
		{"sub.abc.sub.domain.com.evil.net", false},
	}

	for _, c := range cases {
		if got := allowedHost(c.host, wildcard); got != c.want {
			t.Errorf("wildcard: allowedHost(%q) = %v, want %v", c.host, got, c.want)
		}

		if got := allowedHost(c.host, regex); got != c.want {
			t.Errorf("regex: allowedHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestMidNameWildcardOriginalFeatureRequest(t *testing.T) {
	t.Parallel()

	allow := NormalizePatterns([]string{"gitea-pull-through-cache.*.r2.cloudflarestorage.com"})

	if !allowedHost("gitea-pull-through-cache.abc123.r2.cloudflarestorage.com", allow) {
		t.Error("bucket subdomain must match")
	}

	if allowedHost("other-bucket.abc123.r2.cloudflarestorage.com", allow) {
		t.Error("different bucket prefix must not match")
	}
}

// Leading-only '*.” keeps the existing suffix-match fast path; a pattern with both
// a leading and a mid '*' must go through the wildcard compiler instead.
func TestLeadingAndMidWildcardCombined(t *testing.T) {
	t.Parallel()

	allow := NormalizePatterns([]string{"*.foo.*.com"})

	if !allowedHost("a.foo.bar.com", allow) {
		t.Error("expected match for a.foo.bar.com")
	}

	if allowedHost("a.foo.com", allow) {
		t.Error("middle segment is required")
	}
}

//nolint:exhaustruct
func TestMidNameWildcardInDenylist(t *testing.T) {
	t.Parallel()

	opts := Options{
		DefaultAllow: true,
		Denylist:     NormalizePatterns([]string{"telemetry.*.example.com"}),
	}

	if hostPermitted("telemetry.eu1.example.com", nil, opts) {
		t.Error("mid-name wildcard denylist entry must block")
	}

	if !hostPermitted("api.eu1.example.com", nil, opts) {
		t.Error("non-matching host must pass under default-allow")
	}

	// Explicit allow overrides the wildcard deny
	if !hostPermitted("telemetry.ok.example.com", []string{"telemetry.ok.example.com"}, opts) {
		t.Error("explicit allow must override wildcard deny")
	}
}
