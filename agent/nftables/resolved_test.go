//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

func TestResolvedElementArgsV4(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("add", "140.82.112.3", 300*time.Second, policy.DomainRule{})
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

	args, err := resolvedElementArgs("add", "2606:4700:4700::1111", 120*time.Second, policy.DomainRule{})
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

	args, err := resolvedElementArgs("delete", "1.2.3.4", 0, policy.DomainRule{})
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
		_, err := resolvedElementArgs("add", bad, time.Minute, policy.DomainRule{})
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

func TestResolvedElementArgsConstrained(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("add", "140.82.112.3", 300*time.Second,
		policy.DomainRule{Pattern: "example.com", Proto: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("resolvedElementArgs: %v", err)
	}

	got := strings.Join(args, " ")
	want := "add element ip g0efilter_v4 resolved_allow_v4_port { 140.82.112.3 . tcp . 443 timeout 300s }"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolvedElementArgsConstrainedV6(t *testing.T) {
	t.Parallel()

	args, err := resolvedElementArgs("add", "2606:4700:4700::1111", 120*time.Second,
		policy.DomainRule{Pattern: "example.com", Proto: "udp", Port: 53})
	if err != nil {
		t.Fatalf("resolvedElementArgs: %v", err)
	}

	got := strings.Join(args, " ")
	if !strings.Contains(got, "resolved_allow_v6_port") || !strings.Contains(got, ". udp . 53") {
		t.Errorf("got %q, want the v6 concat set with a udp/53 element", got)
	}
}

func TestResolvedElementArgsRejectsBadConstraint(t *testing.T) {
	t.Parallel()

	for _, bad := range []policy.DomainRule{
		{Pattern: "example.com", Proto: "sctp", Port: 443},
		{Pattern: "example.com", Proto: "tcp; drop", Port: 443},
		{Pattern: "example.com", Proto: "tcp", Port: 70000},
		{Pattern: "example.com", Proto: "tcp", Port: -1},
	} {
		_, err := resolvedElementArgs("add", "1.2.3.4", time.Minute, bad)
		if err == nil {
			t.Errorf("resolvedElementArgs(%+v) = nil error, want rejection", bad)
		}
	}
}
