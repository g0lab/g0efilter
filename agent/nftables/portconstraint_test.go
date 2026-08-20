//nolint:testpackage // exercises internal ruleset generation
package nftables

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func portConstraintConfig(mode string) RulesetConfig {
	v4, v6, portV4, portV6 := classifyByFamily([]string{
		"1.1.1.1",
		"tcp/1.2.3.4:3389",
		"9.9.9.9:22",
		"udp/[2606:4700:4700::1111]:53",
		"2606:4700:4700::64",
	})

	return RulesetConfig{
		AllowV4:     v4,
		AllowV6:     v6,
		AllowPortV4: portV4,
		AllowPortV6: portV6,
		HTTPSPort:   8443,
		HTTPPort:    8080,
		DNSPort:     53,
		Mode:        mode,
	}
}

func TestClassifyByFamilyPortConstraints(t *testing.T) {
	t.Parallel()

	_, _, portV4, portV6 := classifyByFamily([]string{
		"1.1.1.1", "tcp/1.2.3.4:3389", "9.9.9.9:22", "udp/[2606:4700:4700::1111]:53",
	})

	wantV4 := []string{"1.2.3.4 . tcp . 3389", "9.9.9.9 . tcp . 22"}
	if strings.Join(portV4, ",") != strings.Join(wantV4, ",") {
		t.Errorf("portV4 = %v, want %v", portV4, wantV4)
	}

	wantV6 := []string{"2606:4700:4700::1111 . udp . 53"}
	if strings.Join(portV6, ",") != strings.Join(wantV6, ",") {
		t.Errorf("portV6 = %v, want %v", portV6, wantV6)
	}
}

func TestGenerateRulesetEmitsPortConcatSets(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"https", "dns-strict"} {
		ruleset := GenerateRuleset(portConstraintConfig(mode))

		for _, want := range []string{
			"set allow_daddr_port_v4",
			"type ipv4_addr . inet_proto . inet_service",
			"1.2.3.4 . tcp . 3389",
			"9.9.9.9 . tcp . 22",
			"ip daddr . meta l4proto . th dport @allow_daddr_port_v4 accept",
			"set allow_daddr_port_v6",
			"type ipv6_addr . inet_proto . inet_service",
			"2606:4700:4700::1111 . udp . 53",
			"ip6 daddr . meta l4proto . th dport @allow_daddr_port_v6 accept",
		} {
			if !strings.Contains(ruleset, want) {
				t.Errorf("%s ruleset missing %q", mode, want)
			}
		}

		if !strings.Contains(ruleset, "elements = {1.1.1.1}") {
			t.Errorf("%s ruleset dropped the unconstrained IPv4 entry", mode)
		}

		if mode == "https" {
			for _, want := range []string{
				"ip daddr . meta l4proto . th dport @allow_daddr_port_v4 return",
				"ip6 daddr . meta l4proto . th dport @allow_daddr_port_v6 return",
			} {
				if !strings.Contains(ruleset, want) {
					t.Errorf("%s NAT ruleset missing %q", mode, want)
				}
			}
		}
	}
}

func TestApplyPolicyRulesRejectsUnenforceablePortConstraint(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		defaultAllow bool
	}{
		{"plain dns mode", "dns", false},
		{"default-allow https", "https", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FILTER_MODE", tt.mode)

			err := ApplyPolicyRulesWithContext(
				context.Background(),
				PolicyRules{AllowIPs: []string{"tcp/1.2.3.4:3389"}, DefaultAllow: tt.defaultAllow},
				"8443", "8080", "53",
			)
			if !errors.Is(err, errUnsupportedPortConstraint) {
				t.Fatalf("want errUnsupportedPortConstraint, got %v", err)
			}
		})
	}
}

func TestGeneratedRulesetPassesNftCheck(t *testing.T) {
	t.Parallel()

	_, lookErr := exec.LookPath("nft")
	if lookErr != nil {
		t.Skip("nft not available")
	}

	for _, mode := range []string{"https", "dns-strict", "dns"} {
		ruleset := GenerateRuleset(portConstraintConfig(mode))

		cmd := exec.Command("nft", "-c", "-f", "-") //nolint:noctx // short-lived check
		cmd.Stdin = strings.NewReader(ruleset)

		out, err := cmd.CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "not permitted") || strings.Contains(string(out), "Operation not permitted") {
				t.Skipf("nft -c needs privileges unavailable here: %s", strings.TrimSpace(string(out)))
			}

			t.Fatalf("nft -c rejected the %s ruleset: %v\n%s", mode, err, out)
		}
	}
}
