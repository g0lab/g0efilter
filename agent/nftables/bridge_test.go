//nolint:testpackage // Exercises unexported ruleset validation helpers.
package nftables

import (
	"context"
	"strings"
	"testing"
)

func TestBridgeRulesFilterDockerNetworksWithoutTrustingTheBypassMark(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:          []string{"192.0.2.10"},
		AllowV6:          []string{"2001:db8::10"},
		AllowPortV4:      []string{"192.0.2.20 . tcp . 8443"},
		AllowPortV6:      nil,
		DenyV4:           nil,
		DenyV6:           nil,
		HTTPSPort:        65443,
		HTTPPort:         65080,
		DNSPort:          65053,
		Mode:             "https",
		DefaultAllow:     false,
		Audit:            false,
		BridgeInterfaces: []string{"docker0", "br-*"},
	})

	for _, want := range []string{
		"table ip g0efilter_bridge_v4",
		"table ip6 g0efilter_bridge_v6",
		`iifname "docker0" jump bridge_egress`,
		`iifname "br-*" jump bridge_redirect`,
		"tcp dport 443 redirect to :65443",
		"ip daddr @allow_daddr_v4 accept",
		"ip daddr . meta l4proto . th dport @allow_daddr_port_v4 accept",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("bridge ruleset missing %q", want)
		}
	}

	// Container to container is not egress: dropping it would break linked containers.
	for _, want := range []string{
		`oifname "docker0" accept`,
		`oifname "br-*" accept`,
		`fib daddr . iif oifname "docker0" return`,
		`fib daddr . iif oifname "br-*" return`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("bridge ruleset missing same-bridge exemption %q", want)
		}
	}

	bridgeStart := strings.Index(ruleset, "table ip g0efilter_bridge_v4")
	if bridgeStart < 0 {
		t.Fatal("bridge table missing")
	}

	if strings.Contains(ruleset[bridgeStart:], "meta mark") {
		t.Fatal("bridge traffic must not be able to spoof the agent bypass mark")
	}
}

func TestBridgeInterfacePatternsAreValidatedBeforeRunningNft(t *testing.T) {
	t.Setenv("BRIDGE_INTERFACES", `docker0,bad\" } drop`)

	err := ApplyPolicyRulesWithContext(context.Background(), PolicyRules{}, "65443", "65080", "65053")
	if err == nil || !strings.Contains(err.Error(), "invalid bridge interface pattern") {
		t.Fatalf("error = %v, want interface validation failure", err)
	}
}

func TestNoBridgeTablesUnlessConfigured(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		HTTPSPort: 65443,
		HTTPPort:  65080,
		DNSPort:   65053,
		Mode:      "https",
	})
	if strings.Contains(ruleset, "g0efilter_bridge") {
		t.Fatal("bridge hooks must be opt-in outside the GitHub Action")
	}
}

//nolint:funlen // One table keeps all policy-mode expectations together.
func TestBridgeRulesCoverEveryPolicyMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		mode         string
		defaultAllow bool
		audit        bool
		want         []string
		absent       []string
	}{
		{
			name: "https default deny",
			mode: "https",
			want: []string{"tcp dport 443 redirect to :65443", `log prefix "blocked" group 0`},
		},
		{
			name:         "https default allow",
			mode:         "https",
			defaultAllow: true,
			want:         []string{"@deny_daddr_v4 drop", "tcp dport 80 redirect to :65080"},
		},
		{
			name:   "dns",
			mode:   "dns",
			want:   []string{"udp dport 53 redirect to :65053", "tcp dport 53 redirect to :65053"},
			absent: []string{"tcp dport 443 redirect"},
		},
		{
			name: "dns strict",
			mode: "dns-strict",
			want: []string{"@resolved_allow_v4 accept", "@resolved_allow_v6 accept"},
		},
		{
			name:  "audit",
			mode:  "https",
			audit: true,
			want:  []string{`log prefix "audit" group 0`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ruleset := GenerateRuleset(RulesetConfig{
				AllowV4:          []string{"192.0.2.10"},
				AllowV6:          []string{"2001:db8::10"},
				DenyV4:           []string{"198.51.100.10"},
				HTTPSPort:        65443,
				HTTPPort:         65080,
				DNSPort:          65053,
				Mode:             tc.mode,
				DefaultAllow:     tc.defaultAllow,
				Audit:            tc.audit,
				BridgeInterfaces: []string{"docker0"},
			})
			for _, want := range tc.want {
				if !strings.Contains(ruleset, want) {
					t.Errorf("ruleset missing %q", want)
				}
			}

			for _, absent := range tc.absent {
				if strings.Contains(ruleset, absent) {
					t.Errorf("ruleset unexpectedly contains %q", absent)
				}
			}
		})
	}
}
