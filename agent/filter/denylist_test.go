//nolint:testpackage // Need access to internal implementation details
package filter

import "testing"

// Gaps left by TestHostPermittedDefaultAllow, which already covers exact and
// wildcard denies, the allowlist override and the empty host.

func TestDenylistRegexPatterns(t *testing.T) {
	t.Parallel()

	opts := Options{
		DefaultAllow: true,
		Denylist:     NormalizePatterns([]string{`/^(.*\.)?tracker\.com$/`}),
	}
	allow := NormalizePatterns([]string{"api.tracker.com"})

	for _, host := range []string{"tracker.com", "a.tracker.com", "a.b.tracker.com"} {
		if hostPermitted(host, allow, opts) {
			t.Errorf("regex-denylisted %q was permitted", host)
		}
	}

	// The regex is anchored, so this is not a denylist match and default-allow
	// lets it through.
	if !hostPermitted("nottracker.com", allow, opts) {
		t.Error("nottracker.com must not match an anchored .tracker.com regex")
	}

	if !hostPermitted("api.tracker.com", allow, opts) {
		t.Error("allowlist must still override a regex denylist entry")
	}
}

// Under default-deny the allowlist is authoritative and the denylist is never
// consulted, so a host in neither list is blocked and one in both is allowed.
func TestDenylistIgnoredUnderDefaultDeny(t *testing.T) {
	t.Parallel()

	opts := Options{Denylist: NormalizePatterns([]string{"github.com", "*.evil.com"})}
	allow := NormalizePatterns([]string{"github.com"})

	if !hostPermitted("github.com", allow, opts) {
		t.Error("allowlisted host must pass under default-deny even when denylisted")
	}

	if hostPermitted("other.example.com", allow, opts) {
		t.Error("host in neither list must be blocked under default-deny")
	}
}

// Serve80 prebuilds denyMatcher; the []string path builds one per call. A
// divergence would mean the hot path enforces differently from the tested one.
func TestDenylistPrebuiltMatcherMatchesLazyPath(t *testing.T) {
	t.Parallel()

	patterns := NormalizePatterns([]string{"*.tracker.com", "analytics.example.com", `/^ads\..*$/`})
	allow := newMatcher(NormalizePatterns([]string{"api.tracker.com"}))

	lazy := Options{DefaultAllow: true, Denylist: patterns}

	prebuilt := lazy
	prebuilt.denyMatcher = newMatcher(patterns)

	hosts := []string{
		"api.tracker.com", "telemetry.tracker.com", "analytics.example.com",
		"ads.example.org", "unlisted.example.net", "tracker.com", "",
	}

	for _, host := range hosts {
		if got, want := hostPermittedBy(host, allow, prebuilt), hostPermittedBy(host, allow, lazy); got != want {
			t.Errorf("host %q: prebuilt denyMatcher = %v, lazy = %v", host, got, want)
		}
	}
}

func TestDenylistNormalisesHostForm(t *testing.T) {
	t.Parallel()

	opts := Options{
		DefaultAllow: true,
		Denylist:     NormalizePatterns([]string{"Analytics.Example.COM.", "*.Tracker.com"}),
	}

	// normalizeHost is what the filters apply before matching.
	for _, raw := range []string{
		"analytics.example.com", "ANALYTICS.EXAMPLE.COM", "analytics.example.com.",
		"Analytics.Example.Com:8080", "telemetry.TRACKER.com",
	} {
		if hostPermitted(normalizeHost(raw), nil, opts) {
			t.Errorf("denylisted host %q was permitted after normalisation", raw)
		}
	}
}

// Learning writes into the allowlist, which overrides the denylist, so recording
// a denied entry would permanently undo the deny.
func TestLearningModeSkipsDenylistedEntries(t *testing.T) {
	t.Parallel()

	newOpts := func(learned *[]string) Options {
		return Options{
			LearningMode: true,
			DefaultAllow: true,
			Denylist:     NormalizePatterns([]string{"analytics.example.com", "*.tracker.com"}),
			DenyIPs:      []string{"10.0.0.0/8", "203.0.113.5"},
			OnLearn:      func(kind, value string) { *learned = append(*learned, kind+":"+value) },
		}
	}

	t.Run("denylisted domains are not recorded", func(t *testing.T) {
		t.Parallel()

		var learned []string

		opts := newOpts(&learned)

		maybeLearnHost("analytics.example.com", nil, opts)
		maybeLearnHost("telemetry.tracker.com", nil, opts)

		if len(learned) != 0 {
			t.Errorf("learned denylisted domains: %v", learned)
		}
	})

	t.Run("denylisted IPs are not recorded, including via CIDR", func(t *testing.T) {
		t.Parallel()

		var learned []string

		opts := newOpts(&learned)

		maybeLearnIP("10.1.2.3", opts)
		maybeLearnIP("203.0.113.5", opts)

		if len(learned) != 0 {
			t.Errorf("learned denylisted IPs: %v", learned)
		}
	})

	t.Run("everything else is still recorded", func(t *testing.T) {
		t.Parallel()

		var learned []string

		opts := newOpts(&learned)

		maybeLearnHost("new.example.com", nil, opts)
		maybeLearnIP("9.9.9.9", opts)

		want := []string{"domain:new.example.com", "ip:9.9.9.9"}
		if len(learned) != 2 || learned[0] != want[0] || learned[1] != want[1] {
			t.Errorf("learned = %v, want %v", learned, want)
		}
	})
}
