//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

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

// Untrusted DNS input is rejected before any netlink traffic, each problem once.
//
//nolint:paralleltest // t.Setenv rules out parallel subtests
func TestAddResolvedIPsRejectsUntrustedInput(t *testing.T) {
	t.Setenv("BRIDGE_INTERFACES", "br0")

	tests := []struct {
		name  string
		ips   []string
		rules []policy.DomainRule
		want  string
	}{
		{"not an address", []string{"not-an-ip"}, nil, `invalid resolved IP: "not-an-ip"`},
		{"unknown protocol", []string{"1.2.3.4"}, []policy.DomainRule{{Proto: "sctp", Port: 443}}, "sctp"},
		{"port out of range", []string{"1.2.3.4"}, []policy.DomainRule{{Proto: "tcp", Port: 70000}}, "70000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddResolvedIPs(t.Context(), tt.ips, time.Minute, tt.rules)
			if err == nil {
				t.Fatal("AddResolvedIPs accepted untrusted input")
			}

			if got := strings.Count(err.Error(), tt.want); got != 1 {
				t.Errorf("%q reported %d times, want 1:\n%v", tt.want, got, err)
			}
		})
	}
}
