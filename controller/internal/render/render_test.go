//nolint:testpackage // Need access to internal implementation details
package render

import (
	"errors"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
)

func domainRule(name string, domains ...string) v1alpha1.EgressRule {
	//nolint:exhaustruct // ports are set explicitly where they matter
	return v1alpha1.EgressRule{
		Name: name,
		To:   []v1alpha1.EgressPeer{{DomainNames: domains}}, //nolint:exhaustruct // networks unused
	}
}

func networkRule(name string, networks ...string) v1alpha1.EgressRule {
	//nolint:exhaustruct // ports are set explicitly where they matter
	return v1alpha1.EgressRule{
		Name: name,
		To:   []v1alpha1.EgressPeer{{Networks: networks}}, //nolint:exhaustruct // domains unused
	}
}

func TestRulesRendersDomainsAndNetworks(t *testing.T) {
	t.Parallel()

	got, err := Rules([]v1alpha1.EgressRule{
		domainRule("apis", "api.example.com", "*.cdn.example.com"),
		networkRule("dns", "10.96.0.10", "10.42.0.0/16"),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	wantDomains := []string{"*.cdn.example.com", "api.example.com"}
	if strings.Join(got.Domains, ",") != strings.Join(wantDomains, ",") {
		t.Errorf("domains = %v, want %v", got.Domains, wantDomains)
	}

	wantNetworks := []string{"10.42.0.0/16", "10.96.0.10"}
	if strings.Join(got.Networks, ",") != strings.Join(wantNetworks, ",") {
		t.Errorf("networks = %v, want %v", got.Networks, wantNetworks)
	}
}

// A rule with ports has to expand to one allowlist entry per peer and port, because
// the agent's allowlist is flat.
func TestRulesExpandsPorts(t *testing.T) {
	t.Parallel()

	rule := networkRule("db", "10.0.0.5")
	rule.Ports = []v1alpha1.EgressPort{
		{Protocol: "TCP", Port: 5432},
		{Protocol: "UDP", Port: 53},
	}

	got, err := Rules([]v1alpha1.EgressRule{rule})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	want := []string{"tcp/10.0.0.5:5432", "udp/10.0.0.5:53"}
	if strings.Join(got.Networks, ",") != strings.Join(want, ",") {
		t.Errorf("networks = %v, want %v", got.Networks, want)
	}
}

// An unconstrained entry allows every port, so a rule with no ports must not
// accidentally render a port constraint.
func TestRulesWithoutPortsIsUnconstrained(t *testing.T) {
	t.Parallel()

	got, err := Rules([]v1alpha1.EgressRule{networkRule("any", "10.0.0.5")})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Networks) != 1 || got.Networks[0] != "10.0.0.5" {
		t.Errorf("networks = %v, want [10.0.0.5]", got.Networks)
	}
}

func TestPortWithoutProtocolDefaultsToTCP(t *testing.T) {
	t.Parallel()

	rule := networkRule("web", "10.0.0.5")
	rule.Ports = []v1alpha1.EgressPort{{Protocol: "", Port: 443}}

	got, err := Rules([]v1alpha1.EgressRule{rule})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Networks) != 1 || got.Networks[0] != "tcp/10.0.0.5:443" {
		t.Errorf("networks = %v, want [tcp/10.0.0.5:443]", got.Networks)
	}
}

// An unbracketed IPv6 literal with a port is ambiguous and the agent would reject it.
func TestIPv6LiteralsAreBracketed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		network string
		want    string
	}{
		{name: "address", network: "2001:db8::1", want: "tcp/[2001:db8::1]:443"},
		{name: "cidr", network: "2001:db8::/32", want: "tcp/[2001:db8::/32]:443"},
		{name: "ipv4 stays bare", network: "10.0.0.5", want: "tcp/10.0.0.5:443"},
		{name: "ipv4 cidr stays bare", network: "10.0.0.0/8", want: "tcp/10.0.0.0/8:443"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := networkRule("r", tc.network)
			rule.Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: 443}}

			got, err := Rules([]v1alpha1.EgressRule{rule})
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			if len(got.Networks) != 1 || got.Networks[0] != tc.want {
				t.Errorf("networks = %v, want [%s]", got.Networks, tc.want)
			}
		})
	}
}

// Cluster policies are merged in additively, and must not be able to remove
// anything a namespaced policy allows.
func TestRulesMergesSetsAdditively(t *testing.T) {
	t.Parallel()

	namespaced := []v1alpha1.EgressRule{domainRule("app", "api.example.com")}
	cluster := []v1alpha1.EgressRule{networkRule("dns", "10.96.0.10")}

	got, err := Rules(namespaced, cluster)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Domains) != 1 || len(got.Networks) != 1 {
		t.Errorf("merge lost entries: %+v", got)
	}
}

func TestRulesDeduplicates(t *testing.T) {
	t.Parallel()

	got, err := Rules(
		[]v1alpha1.EgressRule{domainRule("a", "api.example.com", "api.example.com")},
		[]v1alpha1.EgressRule{domainRule("b", "api.example.com")},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Domains) != 1 {
		t.Errorf("domains = %v, want one entry", got.Domains)
	}
}

// Output has to be stable: a reordered spec that means the same thing must not
// rewrite the ConfigMap and reload every filtered pod.
func TestRenderIsOrderIndependent(t *testing.T) {
	t.Parallel()

	first, err := Rules([]v1alpha1.EgressRule{
		domainRule("a", "b.example.com", "a.example.com"),
		networkRule("b", "10.0.0.2", "10.0.0.1"),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	second, err := Rules([]v1alpha1.EgressRule{
		networkRule("b", "10.0.0.1", "10.0.0.2"),
		domainRule("a", "a.example.com", "b.example.com"),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if first.Document() != second.Document() {
		t.Errorf("reordering changed the output:\n%s\n---\n%s", first.Document(), second.Document())
	}
}

func TestRulesRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule v1alpha1.EgressRule
		want error
	}{
		{
			name: "peer with nothing set",
			//nolint:exhaustruct // an empty peer is the subject
			rule: v1alpha1.EgressRule{Name: "empty", To: []v1alpha1.EgressPeer{{}}},
			want: ErrEmptyPeer,
		},
		{name: "malformed network", rule: networkRule("bad", "10.0.0"), want: ErrInvalidNetwork},
		{name: "malformed cidr", rule: networkRule("bad", "10.0.0.0/99"), want: ErrInvalidNetwork},
		{name: "empty network", rule: networkRule("bad", ""), want: ErrInvalidNetwork},
		{name: "zero-padded prefix length", rule: networkRule("bad", "10.0.0.0/08"), want: ErrInvalidNetwork},
		// A bare "*" would quietly allow every destination, defeating default-deny.
		{name: "catch-all domain", rule: domainRule("bad", "*"), want: ErrInvalidDomain},
		{name: "domain with a port", rule: domainRule("bad", "api.example.com:443"), want: ErrInvalidDomain},
		{name: "domain with a path", rule: domainRule("bad", "example.com/api"), want: ErrInvalidDomain},
		{name: "domain with whitespace", rule: domainRule("bad", "api example.com"), want: ErrInvalidDomain},
		{name: "empty domain", rule: domainRule("bad", ""), want: ErrInvalidDomain},
		{name: "domain without a suffix", rule: domainRule("bad", "localhost"), want: ErrInvalidDomain},
		{name: "domain with invalid labels", rule: domainRule("bad", "-api.example.com"), want: ErrInvalidDomain},
		{name: "domain with numeric suffix", rule: domainRule("bad", "api.123"), want: ErrInvalidDomain},
		{name: "invalid regex", rule: domainRule("bad", `/[unterminated/`), want: ErrInvalidDomain},
		// A non-printable character would break the rendered YAML and take every
		// other rule in the document down with it.
		{name: "domain with a control character", rule: domainRule("bad", "a\u0001b.example.com"), want: ErrInvalidDomain},
		{name: "domain with a C1 control", rule: domainRule("bad", "a\u008ab.example.com"), want: ErrInvalidDomain},
		{name: "domain with a line separator", rule: domainRule("bad", "a\u2028b.example.com"), want: ErrInvalidDomain},
		{name: "domain with invalid utf-8", rule: domainRule("bad", "a\xd6b.example.com"), want: ErrInvalidDomain},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := Rules([]v1alpha1.EgressRule{tc.rule})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}

			// The rule name has to appear or an operator cannot tell which rule broke.
			if tc.rule.Name != "" && !strings.Contains(err.Error(), tc.rule.Name) {
				t.Errorf("error does not name the rule: %v", err)
			}
		})
	}
}

func TestRulesValidateWildcardDomains(t *testing.T) {
	t.Parallel()

	valid := []string{"*.example.com", "api-*.example.com", "sub.*.example.com"}
	for _, domain := range valid {
		policy, err := Rules([]v1alpha1.EgressRule{domainRule("wildcard", domain)})
		if err != nil {
			t.Errorf("valid wildcard %q rejected: %v", domain, err)

			continue
		}

		if len(policy.Domains) != 1 || policy.Domains[0] != domain {
			t.Errorf("wildcard %q rendered as %v", domain, policy.Domains)
		}
	}

	invalid := []string{"sub.**.example.com", "example*", "sub.*.example!.com"}
	for _, domain := range invalid {
		_, err := Rules([]v1alpha1.EgressRule{domainRule("wildcard", domain)})
		if !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("invalid wildcard %q returned %v", domain, err)
		}
	}
}

func TestPortValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port v1alpha1.EgressPort
	}{
		{name: "zero", port: v1alpha1.EgressPort{Protocol: "TCP", Port: 0}},
		{name: "negative", port: v1alpha1.EgressPort{Protocol: "TCP", Port: -1}},
		{name: "too large", port: v1alpha1.EgressPort{Protocol: "TCP", Port: 70000}},
		{name: "unknown protocol", port: v1alpha1.EgressPort{Protocol: "SCTP", Port: 443}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := networkRule("r", "10.0.0.1")
			rule.Ports = []v1alpha1.EgressPort{tc.port}

			_, err := Rules([]v1alpha1.EgressRule{rule})
			if !errors.Is(err, ErrInvalidPort) {
				t.Fatalf("got %v, want ErrInvalidPort", err)
			}
		})
	}
}

func TestRulesForModeRejectsUnenforceablePortConstraints(t *testing.T) {
	t.Parallel()

	domain := domainRule("api", "api.example.com")
	domain.Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: 443}}

	network := networkRule("database", "10.0.0.5")
	network.Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: 5432}}

	tests := []struct {
		name string
		mode string
		rule v1alpha1.EgressRule
	}{
		{name: "domain in https", mode: "https", rule: domain},
		{name: "domain in dns", mode: "dns", rule: domain},
		{name: "network in dns", mode: "dns", rule: network},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := RulesForMode(tc.mode, []v1alpha1.EgressRule{tc.rule})
			if !errors.Is(err, ErrUnsupportedConstraint) {
				t.Fatalf("got %v, want ErrUnsupportedConstraint", err)
			}
		})
	}

	_, err := RulesForMode("dns-strict", []v1alpha1.EgressRule{domain, network})
	if err != nil {
		t.Fatalf("dns-strict rejected enforceable constraints: %v", err)
	}

	_, err = RulesForMode("https", []v1alpha1.EgressRule{network})
	if err != nil {
		t.Fatalf("https rejected an enforceable network constraint: %v", err)
	}
}

// Regex patterns are the agent's own syntax and must reach it unaltered.
func TestRegexDomainsPassThrough(t *testing.T) {
	t.Parallel()

	got, err := Rules([]v1alpha1.EgressRule{domainRule("regex", `/^api\.example\.com$/`)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Domains) != 1 || got.Domains[0] != `/^api\.example\.com$/` {
		t.Errorf("domains = %v, want the pattern unchanged", got.Domains)
	}
}

func TestInternationalDomainPassesThrough(t *testing.T) {
	t.Parallel()

	const domain = "caf\u00e9.example"

	got, err := Rules([]v1alpha1.EgressRule{domainRule("idn", domain)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if len(got.Domains) != 1 || got.Domains[0] != domain {
		t.Errorf("domains = %v, want the original IDN", got.Domains)
	}
}

func TestDocumentIsValidAgentPolicy(t *testing.T) {
	t.Parallel()

	policy, err := Rules([]v1alpha1.EgressRule{
		domainRule("apis", "api.example.com"),
		networkRule("dns", "10.96.0.10"),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	got := policy.Document()

	for _, want := range []string{
		"allowlist:\n",
		"  ips:\n    - '10.96.0.10'\n",
		"  domains:\n    - 'api.example.com'\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("document missing %q:\n%s", want, got)
		}
	}
}

// A quote inside a regex pattern would otherwise close the YAML scalar.
func TestDocumentEscapesQuotesInPatterns(t *testing.T) {
	t.Parallel()

	policy, err := Rules([]v1alpha1.EgressRule{domainRule("regex", `/^a'b$/`)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if want := `    - '/^a''b$/'` + "\n"; !strings.Contains(policy.Document(), want) {
		t.Errorf("document does not escape the quote:\n%s", policy.Document())
	}
}

// An empty policy must still be a parseable document that denies everything, not a
// truncated file the agent would refuse to load.
func TestEmptyPolicyRendersExplicitEmptyLists(t *testing.T) {
	t.Parallel()

	policy, err := Rules(nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !policy.Empty() {
		t.Error("a policy with no rules is not reported as empty")
	}

	got := policy.Document()

	for _, want := range []string{"  ips: []\n", "  domains: []\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("document missing %q:\n%s", want, got)
		}
	}
}
