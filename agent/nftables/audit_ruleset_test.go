//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
)

//nolint:exhaustruct
func TestGenerateRulesetAuditHTTPS(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:   []string{"1.1.1.1"},
		HTTPSPort: 8443,
		HTTPPort:  8080,
		DNSPort:   53,
		Mode:      "https",
		Audit:     true,
	})

	if strings.Contains(ruleset, "policy drop") {
		t.Error("audit ruleset must not contain policy drop")
	}

	if strings.Contains(ruleset, "\n        drop\n") {
		t.Error("audit ruleset must not contain drop verdicts")
	}

	if !strings.Contains(ruleset, `log prefix "audit" group 0`) {
		t.Error("audit ruleset must log would-be drops with the audit prefix")
	}

	if strings.Contains(ruleset, `log prefix "blocked"`) {
		t.Error("audit ruleset must not use the blocked prefix")
	}

	// NAT redirects must survive so proxies still observe domains
	if !strings.Contains(ruleset, "redirect to :8443") {
		t.Error("audit ruleset must keep proxy redirects")
	}
}

//nolint:exhaustruct
func TestGenerateRulesetAuditDefaultAllowDenylist(t *testing.T) {
	t.Parallel()

	ruleset := GenerateRuleset(RulesetConfig{
		DenyV4:       []string{"203.0.113.7"},
		HTTPSPort:    8443,
		HTTPPort:     8080,
		DNSPort:      53,
		Mode:         "https",
		DefaultAllow: true,
		Audit:        true,
	})

	if !strings.Contains(ruleset, `ip daddr @deny_daddr_v4 log prefix "audit" group 0`) {
		t.Error("denylisted IPs must audit-log in audit mode")
	}

	if !strings.Contains(ruleset, "ip daddr @deny_daddr_v4 accept") {
		t.Error("denylisted IPs must be accepted in audit mode")
	}

	if strings.Contains(ruleset, "@deny_daddr_v4 drop") || strings.Contains(ruleset, "@deny_daddr_v6 drop") {
		t.Error("audit ruleset must not drop denylisted IPs")
	}
}

func TestMapPrefixToActionAudit(t *testing.T) {
	t.Parallel()

	if got := mapPrefixToAction("audit"); got != "AUDIT" {
		t.Errorf("mapPrefixToAction(audit) = %q, want AUDIT", got)
	}
}
