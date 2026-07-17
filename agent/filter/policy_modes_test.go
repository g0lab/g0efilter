//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"testing"
)

func TestAllowedHostRegexPatterns(t *testing.T) {
	t.Parallel()

	allowlist := NormalizePatterns([]string{
		"github.com",
		`/^gitea-pull-through-cache\.\w+\.r2\.cloudflarestorage\.com$/`,
	})

	tests := []struct {
		host string
		want bool
	}{
		{"gitea-pull-through-cache.abc123.r2.cloudflarestorage.com", true},
		{"GITEA-PULL-THROUGH-CACHE.ABC123.R2.CLOUDFLARESTORAGE.COM", true},
		{"gitea-pull-through-cache.a.b.r2.cloudflarestorage.com", false}, // \w+ has no dots
		{"other.abc123.r2.cloudflarestorage.com", false},
		{"gitea-pull-through-cache.abc123.r2.cloudflarestorage.com.evil.net", false},
		{"github.com", true},
	}

	for _, tt := range tests {
		if got := allowedHost(tt.host, allowlist); got != tt.want {
			t.Errorf("allowedHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestNormalizePatternsKeepsRegexIntact(t *testing.T) {
	t.Parallel()

	in := []string{`/^A\.B\.COM$/`, "EXAMPLE.com"}

	out := NormalizePatterns(in)
	if out[0] != `/^A\.B\.COM$/` {
		t.Errorf("regex pattern mangled: %q", out[0])
	}

	if out[1] != "example.com" {
		t.Errorf("literal not normalized: %q", out[1])
	}
}

//nolint:exhaustruct
func TestHostPermittedDefaultDeny(t *testing.T) {
	t.Parallel()

	allow := []string{"github.com"}
	opts := Options{}

	if !hostPermitted("github.com", allow, opts) {
		t.Error("allowlisted host must pass")
	}

	if hostPermitted("google.com", allow, opts) {
		t.Error("non-allowlisted host must be blocked")
	}

	if hostPermitted("", allow, opts) {
		t.Error("empty host must be blocked under default-deny")
	}
}

//nolint:exhaustruct
func TestHostPermittedDefaultAllow(t *testing.T) {
	t.Parallel()

	allow := []string{"api.tracker.com"}
	opts := Options{
		DefaultAllow: true,
		Denylist:     NormalizePatterns([]string{"*.tracker.com", "analytics.example.com"}),
	}

	if !hostPermitted("anything.example.org", allow, opts) {
		t.Error("unlisted host must pass under default-allow")
	}

	if hostPermitted("telemetry.tracker.com", allow, opts) {
		t.Error("denylisted host must be blocked")
	}

	if hostPermitted("analytics.example.com", allow, opts) {
		t.Error("denylisted exact host must be blocked")
	}

	if !hostPermitted("api.tracker.com", allow, opts) {
		t.Error("allowlist entry must override the denylist")
	}

	if !hostPermitted("", allow, opts) {
		t.Error("empty host passes under default-allow (nothing to match)")
	}
}

//nolint:exhaustruct
func TestHostPermittedLearningModeNeverBlocks(t *testing.T) {
	t.Parallel()

	opts := Options{LearningMode: true}

	for _, host := range []string{"", "blocked.example.com", "github.com"} {
		if !hostPermitted(host, nil, opts) {
			t.Errorf("learning mode blocked %q", host)
		}
	}
}

//nolint:exhaustruct
func TestMaybeLearnHost(t *testing.T) {
	t.Parallel()

	var learned []string

	opts := Options{
		LearningMode: true,
		OnLearn: func(kind, value string) {
			learned = append(learned, kind+":"+value)
		},
	}
	allow := NormalizePatterns([]string{"github.com"})

	maybeLearnHost("github.com", allow, opts) // already allowlisted: not learned
	maybeLearnHost("new.example.com", allow, opts)
	maybeLearnHost("", allow, opts)

	if len(learned) != 1 || learned[0] != "domain:new.example.com" {
		t.Errorf("learned = %v, want [domain:new.example.com]", learned)
	}

	maybeLearnIP("9.9.9.9", opts)

	if len(learned) != 2 || learned[1] != "ip:9.9.9.9" {
		t.Errorf("learned = %v, want ip:9.9.9.9 appended", learned)
	}
}

//nolint:exhaustruct
func TestMaybeLearnDisabledOutsideLearningMode(t *testing.T) {
	t.Parallel()

	called := false
	opts := Options{
		OnLearn: func(_, _ string) { called = true },
	}

	maybeLearnHost("new.example.com", nil, opts)
	maybeLearnIP("9.9.9.9", opts)

	if called {
		t.Error("OnLearn must not fire outside learning mode")
	}
}

// Invalid regex entries (which validation would reject anyway) must fail closed.
func TestAllowedHostInvalidRegexNeverMatches(t *testing.T) {
	t.Parallel()

	if allowedHost("example.com", []string{"/[unclosed/"}) {
		t.Error("invalid regex must not match anything")
	}
}
