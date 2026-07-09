//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/internal/actions"
)

// The SO_MARK bypass lets g0efilter's own polling escape the egress filter. It is
// hand-copied into every generated chain, so a dropped copy only fails in a slow
// docker run; assert every composed table carries it with the right verdict.
func TestBypassLinePresentInEveryChain(t *testing.T) {
	t.Parallel()

	modes := []string{actions.ModeHTTPS, actions.ModeDNS, actions.ModeDNSStrict, "unknown"}

	for _, mode := range modes {
		for _, defaultAllow := range []bool{false, true} {
			for _, audit := range []bool{false, true} {
				//nolint:exhaustruct
				cfg := RulesetConfig{
					AllowV4:      []string{"192.0.2.1"},
					AllowV6:      []string{"2001:db8::1"},
					DenyV4:       []string{"198.51.100.1"},
					DenyV6:       []string{"2001:db8::dead"},
					HTTPSPort:    8443,
					HTTPPort:     8080,
					DNSPort:      5353,
					Mode:         mode,
					DefaultAllow: defaultAllow,
					Audit:        audit,
				}

				ruleset := GenerateRuleset(cfg)
				assertBypassInEveryTable(t, ruleset, cfg)
			}
		}
	}
}

func assertBypassInEveryTable(t *testing.T, ruleset string, cfg RulesetConfig) {
	t.Helper()

	tables := splitTables(t, ruleset)
	if len(tables) == 0 {
		t.Fatalf("no tables generated for cfg %+v", cfg)
	}

	for name, body := range tables {
		// NAT chains cannot "accept"; they hand back to the filter hook with "return".
		verdict := "accept"
		if strings.Contains(name, "nat") {
			verdict = "return"
		}

		want := "meta mark 0x1 " + verdict
		if !strings.Contains(body, want) {
			t.Errorf("cfg %+v: table %q missing bypass line %q\n%s", cfg, name, want, body)
		}
	}
}
