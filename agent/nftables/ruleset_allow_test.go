//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
)

//nolint:exhaustruct
func TestGenerateRulesetDefaultAllowHTTPS(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:      []string{"1.1.1.1"},
		AllowV6:      []string{"2606:4700:4700::1111"},
		DenyV4:       []string{"10.0.0.0/8", "192.168.1.5"},
		DenyV6:       []string{"fd00::/8"},
		HTTPSPort:    8443,
		HTTPPort:     8080,
		DNSPort:      53,
		Mode:         "https",
		DefaultAllow: true,
	})

	for _, want := range []string{
		"policy accept;",
		"deny_daddr_v4",
		"deny_daddr_v6",
		"10.0.0.0/8",
		"192.168.1.5",
		"fd00::/8",
		`ip daddr @deny_daddr_v4 log prefix "blocked" group 0`,
		"ip daddr @deny_daddr_v4 drop",
		"ip6 daddr @deny_daddr_v6 drop",
		"ip daddr @allow_daddr_v4 accept",
		"ip daddr @deny_daddr_v4 return", // NAT skips deny IPs so the filter chain sees the real daddr
		"redirect to :8080",
		"redirect to :8443",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("default-allow HTTPS ruleset missing %q\n%s", want, ruleset)
		}
	}

	if strings.Contains(ruleset, "policy drop;") {
		t.Error("default-allow ruleset must not contain policy drop")
	}
}

//nolint:exhaustruct
func TestGenerateRulesetDefaultAllowDNS(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		DenyV4:       []string{"203.0.113.7"},
		HTTPSPort:    8443,
		HTTPPort:     8080,
		DNSPort:      5353,
		Mode:         "dns",
		DefaultAllow: true,
	})

	for _, want := range []string{
		"policy accept;",
		"deny_daddr_v4",
		"203.0.113.7",
		"ip daddr @deny_daddr_v4 drop",
		"redirect to :5353",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("default-allow DNS ruleset missing %q\n%s", want, ruleset)
		}
	}
}

//nolint:exhaustruct
func TestGenerateRulesetEmptyDenySetOmitsElements(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		HTTPSPort:    8443,
		HTTPPort:     8080,
		DNSPort:      53,
		Mode:         "https",
		DefaultAllow: true,
	})

	// An empty deny set must render without an elements line (nft rejects `elements = {}`)
	idx := strings.Index(ruleset, "set deny_daddr_v4")
	if idx == -1 {
		t.Fatal("deny_daddr_v4 set missing")
	}

	block := ruleset[idx : strings.Index(ruleset[idx:], "}")+idx]
	if strings.Contains(block, "elements") {
		t.Errorf("empty deny set must omit elements:\n%s", block)
	}
}

//nolint:exhaustruct
func TestGenerateRulesetDefaultDenyUnchanged(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:   []string{"1.1.1.1"},
		HTTPSPort: 8443,
		HTTPPort:  8080,
		DNSPort:   53,
		Mode:      "https",
	})

	for _, want := range []string{
		"policy drop;",
		`log prefix "blocked" group 0`,
		"ip daddr @allow_daddr_v4 accept",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("default-deny ruleset missing %q", want)
		}
	}

	if strings.Contains(ruleset, "deny_daddr") {
		t.Error("default-deny ruleset must not reference deny sets")
	}
}
