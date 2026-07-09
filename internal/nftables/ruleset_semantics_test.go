//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/internal/actions"
)

// splitTables slices a generated ruleset into per-table bodies keyed by "family name".
func splitTables(t *testing.T, ruleset string) map[string]string {
	t.Helper()

	out := map[string]string{}

	for _, chunk := range strings.Split(ruleset, "\ntable ")[1:] {
		header, _, ok := strings.Cut(chunk, " {")
		if !ok {
			t.Fatalf("malformed table header in chunk:\n%s", chunk)
		}

		out[header] = chunk
	}

	return out
}

func tableBody(t *testing.T, ruleset, name string) string {
	t.Helper()

	body, ok := splitTables(t, ruleset)[name]
	if !ok {
		t.Fatalf("table %q not found in ruleset:\n%s", name, ruleset)
	}

	return body
}

// setElements extracts the "elements = {...}" contents of a named set, or "" if it has none.
func setElements(t *testing.T, body, setName string) string {
	t.Helper()

	_, after, ok := strings.Cut(body, "set "+setName+" {")
	if !ok {
		t.Fatalf("set %s not found in:\n%s", setName, body)
	}

	block, _, ok := strings.Cut(after, "\n    }")
	if !ok {
		t.Fatalf("unterminated set %s", setName)
	}

	_, elems, ok := strings.Cut(block, "elements = {")
	if !ok {
		return ""
	}

	elems, _, ok = strings.Cut(elems, "}")
	if !ok {
		t.Fatalf("unterminated elements in set %s", setName)
	}

	return elems
}

func setMembers(t *testing.T, body, setName string) map[string]bool {
	t.Helper()

	members := map[string]bool{}

	for e := range strings.SplitSeq(setElements(t, body, setName), ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			members[e] = true
		}
	}

	return members
}

func assertSetHas(t *testing.T, body, setName string, want ...string) {
	t.Helper()

	members := setMembers(t, body, setName)
	for _, w := range want {
		if !members[w] {
			t.Errorf("set %s missing element %q (have %v)", setName, w, members)
		}
	}
}

func assertSetLacks(t *testing.T, body, setName string, unwanted ...string) {
	t.Helper()

	members := setMembers(t, body, setName)
	for _, u := range unwanted {
		if members[u] {
			t.Errorf("set %s must not contain %q", setName, u)
		}
	}
}

func assertHasAll(t *testing.T, s string, subs ...string) {
	t.Helper()

	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("missing %q in:\n%s", sub, s)
		}
	}
}

func assertLacksAll(t *testing.T, s string, subs ...string) {
	t.Helper()

	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Errorf("must not contain %q in:\n%s", sub, s)
		}
	}
}

//nolint:exhaustruct
func httpsDefaultDenyConfig() RulesetConfig {
	return RulesetConfig{
		AllowV4:   []string{"192.0.2.10", "198.51.100.0/24"},
		AllowV6:   []string{"2001:db8::5"},
		HTTPSPort: 8443,
		HTTPPort:  8080,
		DNSPort:   5353,
		Mode:      "https",
	}
}

func TestRulesetSemanticsHTTPSDefaultDenySets(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(httpsDefaultDenyConfig())

	// Allowlisted IPs land in the allow sets of both the filter and NAT tables.
	assertSetHas(t, tableBody(t, ruleset, "ip g0efilter_v4"), "allow_daddr_v4",
		"192.0.2.10", "198.51.100.0/24")
	assertSetHas(t, tableBody(t, ruleset, "ip g0efilter_nat_v4"), "allow_daddr_v4",
		"192.0.2.10", "198.51.100.0/24")
	assertSetHas(t, tableBody(t, ruleset, "ip6 g0efilter_v6"), "allow_daddr_v6", "2001:db8::5")
	assertSetHas(t, tableBody(t, ruleset, "ip6 g0efilter_nat_v6"), "allow_daddr_v6", "2001:db8::5")

	// Default-deny has no denylist sets at all.
	assertLacksAll(t, ruleset, "deny_daddr_v4", "deny_daddr_v6")
}

func TestRulesetSemanticsHTTPSDefaultDenyChains(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(httpsDefaultDenyConfig())

	filterV4 := tableBody(t, ruleset, "ip g0efilter_v4")
	assertHasAll(t, filterV4,
		"policy drop;",
		"ip daddr @allow_daddr_v4 accept",
		`ip daddr @allow_daddr_v4 log prefix "allowed" group 0`,
		`log prefix "blocked" group 0`,
	)

	// NAT redirects 80/443 to the configured proxy ports, and only those ports.
	natV4 := tableBody(t, ruleset, "ip g0efilter_nat_v4")
	assertHasAll(t, natV4,
		"tcp dport 80  redirect to :8080",
		"tcp dport 443 redirect to :8443",
		"ip daddr @allow_daddr_v4 return",
	)
	assertLacksAll(t, natV4, "dport 53", "redirect to :5353")

	natV6 := tableBody(t, ruleset, "ip6 g0efilter_nat_v6")
	assertHasAll(t, natV6,
		"tcp dport 80  redirect to :8080",
		"tcp dport 443 redirect to :8443",
	)
}

// Regression for #118: every filter chain must drop invalid conntrack state before any
// log rule, else out-of-state packets on closed flows are misreported as policy blocks.
func TestRulesetSemanticsInvalidStateDroppedBeforeAnyLog(t *testing.T) {
	t.Parallel()

	modes := []string{actions.ModeHTTPS, actions.ModeDNS, actions.ModeDNSStrict}

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

				for name, body := range splitTables(t, GenerateRuleset(cfg)) {
					if strings.Contains(name, "nat") {
						continue
					}

					assertInvalidDropBeforeLog(t, cfg, name, body)
				}
			}
		}
	}
}

func assertInvalidDropBeforeLog(t *testing.T, cfg RulesetConfig, name, body string) {
	t.Helper()

	invalid := strings.Index(body, "ct state invalid drop")
	if invalid < 0 {
		t.Errorf("cfg %+v: filter chain %q missing 'ct state invalid drop'\n%s", cfg, name, body)

		return
	}

	// Must drop before any log rule (blocked, or audit under dry-run).
	if firstLog := strings.Index(body, "log prefix"); firstLog >= 0 && invalid > firstLog {
		t.Errorf("cfg %+v: chain %q logs before dropping invalid state\n%s", cfg, name, body)
	}
}

func TestRulesetSemanticsDNSDefaultDeny(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4: []string{"192.0.2.10"},
		AllowV6: []string{"2001:db8::5"},
		DNSPort: 5353,
		Mode:    "dns",
	})

	filterV4 := tableBody(t, ruleset, "ip g0efilter_v4")
	assertSetHas(t, filterV4, "allow_daddr_v4", "192.0.2.10")
	assertHasAll(t, filterV4,
		"policy accept;", // dns mode enforces at the DNS proxy, not the filter chain
		"ip daddr 127.0.0.1 udp dport 5353 accept",
	)

	// All DNS traffic is redirected to the proxy port; direct proxy access is exempted.
	natV4 := tableBody(t, ruleset, "ip g0efilter_nat_v4")
	assertHasAll(t, natV4,
		"udp dport 53  redirect to :5353",
		"tcp dport 53  redirect to :5353",
		"ip daddr 127.0.0.1 udp dport 5353 return",
	)
	assertLacksAll(t, natV4, "dport 80", "dport 443")

	natV6 := tableBody(t, ruleset, "ip6 g0efilter_nat_v6")
	assertHasAll(t, natV6, "udp dport 53  redirect to :5353")

	// Plain dns mode has no strict-mode runtime set.
	assertLacksAll(t, ruleset, "resolved_allow_v4", "resolved_allow_v6", "policy drop;")
}

func TestRulesetSemanticsDNSStrictDefaultDeny(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4: []string{"192.0.2.10"},
		AllowV6: []string{"2001:db8::5"},
		DNSPort: 5353,
		Mode:    "dns-strict",
	})

	filterV4 := tableBody(t, ruleset, "ip g0efilter_v4")
	assertSetHas(t, filterV4, "allow_daddr_v4", "192.0.2.10")
	assertHasAll(t, filterV4,
		"policy drop;",
		"set resolved_allow_v4",
		"flags timeout",
		"ip daddr @resolved_allow_v4 accept",
		"ip daddr @allow_daddr_v4 accept",
		`log prefix "blocked" group 0`,
	)

	filterV6 := tableBody(t, ruleset, "ip6 g0efilter_v6")
	assertSetHas(t, filterV6, "allow_daddr_v6", "2001:db8::5")
	assertHasAll(t, filterV6, "set resolved_allow_v6", "ip6 daddr @resolved_allow_v6 accept")

	natV4 := tableBody(t, ruleset, "ip g0efilter_nat_v4")
	assertHasAll(t, natV4, "udp dport 53  redirect to :5353", "tcp dport 53  redirect to :5353")
	assertLacksAll(t, natV4, "dport 80", "dport 443")
}

// dns-strict enforces at the IP layer, so QUIC (UDP/443) needs no special casing: the
// daddr allow rules carry no protocol/dport qualifier, so QUIC to an allow-listed IP is
// accepted and default-drop blocks the rest. A tcp/udp/dport qualifier would break this.
func TestRulesetSemanticsDNSStrictQUICProtocolAgnostic(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4: []string{"192.0.2.10"},
		AllowV6: []string{"2001:db8::5"},
		DNSPort: 5353,
		Mode:    actions.ModeDNSStrict,
	})

	filterV4 := tableBody(t, ruleset, "ip g0efilter_v4")

	// Default-drop catches UDP/QUIC to non-allow-listed destinations.
	assertHasAll(t, filterV4, "policy drop;")

	// Allows carry no protocol qualifier, so QUIC to an allowed/resolved IP is accepted.
	assertHasAll(t, filterV4,
		"ip daddr @allow_daddr_v4 accept",
		"ip daddr @resolved_allow_v4 accept",
	)
	assertLacksAll(t, filterV4,
		"ip daddr @allow_daddr_v4 tcp",
		"ip daddr @allow_daddr_v4 udp",
		"ip daddr @resolved_allow_v4 tcp",
		"ip daddr @resolved_allow_v4 udp",
	)

	// Strict mode redirects only DNS, never 443 - no TCP-proxy path for UDP to miss.
	natV4 := tableBody(t, ruleset, "ip g0efilter_nat_v4")
	assertLacksAll(t, natV4, "dport 443")
}

func TestRulesetSemanticsDefaultAllowDenylist(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:      []string{"192.0.2.10"},
		AllowV6:      []string{"2001:db8::5"},
		DenyV4:       []string{"203.0.113.7", "10.0.0.0/8"},
		DenyV6:       []string{"fd00::/8"},
		HTTPSPort:    8443,
		HTTPPort:     8080,
		Mode:         "https",
		DefaultAllow: true,
	})

	filterV4 := tableBody(t, ruleset, "ip g0efilter_v4")

	// Each IP lands in its own set and never leaks into the other.
	assertSetHas(t, filterV4, "allow_daddr_v4", "192.0.2.10")
	assertSetLacks(t, filterV4, "allow_daddr_v4", "203.0.113.7", "10.0.0.0/8")
	assertSetHas(t, filterV4, "deny_daddr_v4", "203.0.113.7", "10.0.0.0/8")
	assertSetLacks(t, filterV4, "deny_daddr_v4", "192.0.2.10")

	assertHasAll(t, filterV4,
		"policy accept;",
		"ip daddr @allow_daddr_v4 accept",
		"ip daddr @deny_daddr_v4 drop",
	)

	filterV6 := tableBody(t, ruleset, "ip6 g0efilter_v6")
	assertSetHas(t, filterV6, "deny_daddr_v6", "fd00::/8")
	assertHasAll(t, filterV6, "ip6 daddr @deny_daddr_v6 drop")

	// NAT must skip both sets so allow-listed IPs bypass the proxy and
	// deny-listed IPs keep their daddr for the filter chain to drop.
	natV4 := tableBody(t, ruleset, "ip g0efilter_nat_v4")
	assertHasAll(t, natV4,
		"ip daddr @allow_daddr_v4 return",
		"ip daddr @deny_daddr_v4 return",
		"tcp dport 80  redirect to :8080",
		"tcp dport 443 redirect to :8443",
	)

	assertLacksAll(t, ruleset, "policy drop;")
}

func TestRulesetSemanticsModeSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mode    string
		wantDNS bool
	}{
		{name: "unknown falls back to https", mode: "bogus", wantDNS: false},
		{name: "empty falls back to https", mode: "", wantDNS: false},
		{name: "mode is case-insensitive", mode: "DNS", wantDNS: true},
		{name: "dns-strict uses dns nat", mode: "DNS-Strict", wantDNS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			//nolint:exhaustruct
			ruleset := GenerateRuleset(RulesetConfig{
				HTTPSPort: 8443,
				HTTPPort:  8080,
				DNSPort:   5353,
				Mode:      tt.mode,
			})

			if tt.wantDNS {
				assertHasAll(t, ruleset, "udp dport 53  redirect to :5353")
				assertLacksAll(t, ruleset, "redirect to :8443", "redirect to :8080")

				return
			}

			assertHasAll(t, ruleset, "tcp dport 443 redirect to :8443", "tcp dport 80  redirect to :8080")
			assertLacksAll(t, ruleset, "dport 53")
		})
	}
}

func TestRulesetSemanticsEmptyAllowlistPlaceholders(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		HTTPSPort: 8443,
		HTTPPort:  8080,
		Mode:      "https",
	})

	// Empty allowlists fall back to harmless loopback placeholders so the sets stay valid.
	assertSetHas(t, tableBody(t, ruleset, "ip g0efilter_v4"), "allow_daddr_v4", "127.0.0.1")
	assertSetHas(t, tableBody(t, ruleset, "ip6 g0efilter_v6"), "allow_daddr_v6", "::1")
}

func TestRulesetSemanticsAuditDNSStrict(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4: []string{"192.0.2.10"},
		DNSPort: 5353,
		Mode:    "dns-strict",
		Audit:   true,
	})

	// Audit keeps the strict-mode structure but fails open with audit logging.
	assertHasAll(t, ruleset,
		"set resolved_allow_v4",
		`log prefix "audit" group 0`,
		"udp dport 53  redirect to :5353",
	)
	assertLacksAll(t, ruleset,
		"policy drop;",
		`log prefix "blocked" group 0`,
		"\n        drop\n",
	)
	assertSetHas(t, tableBody(t, ruleset, "ip g0efilter_v4"), "allow_daddr_v4", "192.0.2.10")
}

func TestGenerateNftRulesetMatchesGenerateRuleset(t *testing.T) {
	t.Parallel()

	fromWrapper := GenerateNftRuleset([]string{"192.0.2.10"}, []string{"2001:db8::5"}, 8443, 8080, 5353, "https")

	//nolint:exhaustruct
	fromConfig := GenerateRuleset(RulesetConfig{
		AllowV4:   []string{"192.0.2.10"},
		AllowV6:   []string{"2001:db8::5"},
		HTTPSPort: 8443,
		HTTPPort:  8080,
		DNSPort:   5353,
		Mode:      "https",
	})

	if fromWrapper != fromConfig {
		t.Error("GenerateNftRuleset must produce the same ruleset as the equivalent RulesetConfig")
	}
}
