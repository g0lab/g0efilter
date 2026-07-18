//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
	"time"
)

func TestResolvedElementArgsV4(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("add", "140.82.112.3", 300*time.Second)
	if err != nil {
		t.Fatalf("resolvedElementArgs: %v", err)
	}

	got := strings.Join(args, " ")
	want := "add element ip g0efilter_v4 resolved_allow_v4 { 140.82.112.3 timeout 300s }"

	if got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestResolvedElementArgsV6(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("add", "2606:4700:4700::1111", 120*time.Second)
	if err != nil {
		t.Fatalf("resolvedElementArgs: %v", err)
	}

	got := strings.Join(args, " ")
	if !strings.Contains(got, "ip6 g0efilter_v6 resolved_allow_v6") {
		t.Errorf("IPv6 address must target the v6 set: %q", got)
	}
}

func TestResolvedElementArgsDeleteHasNoTimeout(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("delete", "1.2.3.4", 0)
	if err != nil {
		t.Fatalf("resolvedElementArgs: %v", err)
	}

	if strings.Contains(strings.Join(args, " "), "timeout") {
		t.Error("delete element must not carry a timeout")
	}
}

func TestResolvedElementArgsRejectsInvalidIP(t *testing.T) {
	t.Parallel()

	// DNS answers are untrusted: anything that isn't a clean IP must be rejected
	// before it reaches an nft invocation.
	for _, bad := range []string{"", "not-an-ip", "1.2.3.4; drop table", "999.1.1.1", "github.com"} {
		_, err := resolvedElementArgs("add", bad, time.Minute)
		if err == nil {
			t.Errorf("resolvedElementArgs(%q) = nil error, want rejection", bad)
		}
	}
}

func TestClampTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, minResolvedTTL},                  // no TTL -> floor
		{5 * time.Second, minResolvedTTL},    // short CDN TTL -> floor
		{10 * time.Minute, 10 * time.Minute}, // sane TTL passes through
		{7 * 24 * time.Hour, maxResolvedTTL}, // absurd TTL -> cap
	}

	for _, tt := range tests {
		if got := clampTTL(tt.in); got != tt.want {
			t.Errorf("clampTTL(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

//nolint:exhaustruct
func TestGenerateRulesetDNSStrict(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:   []string{"1.1.1.1"},
		HTTPSPort: 8443,
		HTTPPort:  8080,
		DNSPort:   53,
		Mode:      "dns-strict",
	})

	for _, want := range []string{
		"policy drop;",
		"set resolved_allow_v4",
		"set resolved_allow_v6",
		"flags timeout",
		"ip daddr @resolved_allow_v4 accept",
		"ip6 daddr @resolved_allow_v6 accept",
		"ip daddr @allow_daddr_v4 accept",
		`log prefix "blocked" group 0`,
		"redirect to :53", // DNS NAT redirect still present
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("dns-strict ruleset missing %q", want)
		}
	}

	if strings.Contains(ruleset, "policy accept;") {
		t.Error("dns-strict filter chains must not be policy accept")
	}
}

//nolint:exhaustruct
func TestGenerateRulesetDNSStrictDefaultAllowDegrades(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		DenyV4:       []string{"203.0.113.7"},
		HTTPSPort:    8443,
		HTTPPort:     8080,
		DNSPort:      53,
		Mode:         "dns-strict",
		DefaultAllow: true,
	})

	if strings.Contains(ruleset, "resolved_allow") {
		t.Error("default-allow must not include strict resolved sets")
	}

	if !strings.Contains(ruleset, "policy accept;") {
		t.Error("default-allow dns-strict must degrade to accept chains")
	}

	if !strings.Contains(ruleset, "ip daddr @deny_daddr_v4 drop") {
		t.Error("denylist enforcement must remain in degraded mode")
	}
}
