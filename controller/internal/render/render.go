// Package render turns EgressPolicy rules into the policy document the g0efilter
// agent reads.
//
// The agent's allowlist is flat: entries are `[proto/]host[:port]` strings. A rule
// with ports therefore expands to one entry per peer and port, and a rule without
// ports renders one unconstrained entry per peer.
package render

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"golang.org/x/net/idna"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	maxDomainLength = 253
	maxRegexLength  = 1024
)

var (
	// ErrEmptyPeer means a peer set neither domains nor networks, so the rule could
	// not express a destination.
	ErrEmptyPeer = errors.New("peer must set domainNames or networks")

	// ErrInvalidNetwork means an entry is not a usable IP or CIDR.
	ErrInvalidNetwork = errors.New("invalid network")

	// ErrInvalidDomain means an entry would not match as a domain, or would widen
	// the policy beyond what was written.
	ErrInvalidDomain = errors.New("invalid domain name")

	// ErrInvalidPort means a port or protocol constraint is out of range.
	ErrInvalidPort = errors.New("invalid port")

	// ErrUnsupportedConstraint means the selected filter mode cannot enforce a
	// rule's protocol and port without widening it.
	ErrUnsupportedConstraint = errors.New("port constraint is not supported by the filter mode")

	hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// Policy is the document the agent loads from its policy ConfigMap.
type Policy struct {
	Domains  []string
	Networks []string
}

// DocumentFor keeps datapath settings and rules in one projected-file snapshot.
func (p Policy) DocumentFor(spec v1alpha1.SidecarSpec) (string, error) {
	runtime := struct {
		Mode         string   `json:"mode"`
		Enforcement  string   `json:"enforcement"`
		DNSUpstreams []string `json:"dnsUpstreams"`
		DNSHardening *bool    `json:"dnsHardening"`
		DNSRateQPS   int32    `json:"dnsRateQps"`
		DNSRateBurst int32    `json:"dnsRateBurst"`
	}{Mode: spec.Mode, Enforcement: spec.Enforcement, DNSUpstreams: spec.DNS.Upstreams, DNSHardening: spec.DNS.Hardening}
	if spec.DNS.RateQPS != nil {
		runtime.DNSRateQPS = *spec.DNS.RateQPS
	}

	if spec.DNS.RateBurst != nil {
		runtime.DNSRateBurst = *spec.DNS.RateBurst
	}

	data, err := json.Marshal(runtime)
	if err != nil {
		return "", fmt.Errorf("render runtime settings: %w", err)
	}

	return p.Document() + "runtime: " + string(data) + "\n", nil
}

// Empty reports whether the policy allows nothing.
func (p Policy) Empty() bool { return len(p.Domains) == 0 && len(p.Networks) == 0 }

// Rules renders the union of every rule set into one policy. Sets are merged
// additively, which is what makes a ClusterEgressPolicy a baseline a namespaced
// policy can extend but not narrow.
func Rules(sets ...[]v1alpha1.EgressRule) (Policy, error) {
	domains := newOrderedSet()
	networks := newOrderedSet()

	for _, rules := range sets {
		for i, rule := range rules {
			err := renderRule(rule, domains, networks)
			if err != nil {
				return Policy{}, fmt.Errorf("rule %s: %w", ruleLabel(rule, i), err)
			}
		}
	}

	return Policy{Domains: domains.sorted(), Networks: networks.sorted()}, nil
}

// RulesForMode renders rules only when the selected agent mode can enforce all
// of their port constraints.
func RulesForMode(mode string, sets ...[]v1alpha1.EgressRule) (Policy, error) {
	if mode == "" {
		mode = "https"
	}

	for _, rules := range sets {
		for i, rule := range rules {
			err := validateRuleMode(mode, rule, i)
			if err != nil {
				return Policy{}, err
			}
		}
	}

	return Rules(sets...)
}

func validateRuleMode(mode string, rule v1alpha1.EgressRule, index int) error {
	if len(rule.Ports) == 0 {
		return nil
	}

	for _, peer := range rule.To {
		if len(peer.DomainNames) > 0 && mode != "dns-strict" {
			return fmt.Errorf("rule %s: %w: domain ports require dns-strict, got %s",
				ruleLabel(rule, index), ErrUnsupportedConstraint, mode)
		}

		if len(peer.Networks) > 0 && mode != "https" && mode != "dns-strict" {
			return fmt.Errorf("rule %s: %w: network ports require https or dns-strict, got %s",
				ruleLabel(rule, index), ErrUnsupportedConstraint, mode)
		}
	}

	return nil
}

// ClusterRules returns the rules from cluster policies that select a namespace.
func ClusterRules(
	namespaceLabels map[string]string,
	policies []v1alpha1.ClusterEgressPolicy,
) ([]v1alpha1.EgressRule, error) {
	rules, _, err := ClusterBaselines(namespaceLabels, policies)

	return rules, err
}

// ClusterBaselines returns the selecting cluster policies' rules and a revision
// identifying them by UID and generation, so a caller selects once for both.
func ClusterBaselines(
	namespaceLabels map[string]string,
	policies []v1alpha1.ClusterEgressPolicy,
) ([]v1alpha1.EgressRule, string, error) {
	matched, err := selectingCluster(namespaceLabels, policies)
	if err != nil {
		return nil, "", err
	}

	var rules []v1alpha1.EgressRule

	parts := make([]string, 0, len(matched))

	for _, policy := range matched {
		rules = append(rules, policy.Spec.Egress...)
		parts = append(parts, fmt.Sprintf("%s/%s:%d", policy.Name, policy.UID, policy.Generation))
	}

	// An empty selection still hashes, so a recorded revision is never the empty
	// string a reconciler that predates the field leaves behind.
	revision := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(parts, "\n"))))

	return rules, revision, nil
}

// selectingCluster returns the matching cluster policies in a stable order, so
// neither the rendered document nor the revision churns.
func selectingCluster(
	namespaceLabels map[string]string,
	policies []v1alpha1.ClusterEgressPolicy,
) ([]v1alpha1.ClusterEgressPolicy, error) {
	matched := make([]v1alpha1.ClusterEgressPolicy, 0, len(policies))

	for _, policy := range policies {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("cluster policy %s: %w", policy.Name, err)
		}

		if selector.Matches(labels.Set(namespaceLabels)) {
			matched = append(matched, policy)
		}
	}

	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })

	return matched, nil
}

func ruleLabel(rule v1alpha1.EgressRule, index int) string {
	if rule.Name != "" {
		return fmt.Sprintf("%q", rule.Name)
	}

	return fmt.Sprintf("#%d", index)
}

func renderRule(rule v1alpha1.EgressRule, domains, networks *orderedSet) error {
	constraints, err := portConstraints(rule.Ports)
	if err != nil {
		return err
	}

	for _, peer := range rule.To {
		if len(peer.DomainNames) == 0 && len(peer.Networks) == 0 {
			return ErrEmptyPeer
		}

		for _, domain := range peer.DomainNames {
			err = addEntries(domains, domain, constraints, validateDomain)
			if err != nil {
				return err
			}
		}

		for _, network := range peer.Networks {
			err = addEntries(networks, network, constraints, validateNetwork)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// addEntries writes one allowlist entry per port constraint, or a single
// unconstrained entry when the rule names no ports.
func addEntries(into *orderedSet, host string, constraints []string, validate func(string) error) error {
	host = strings.TrimSpace(host)

	err := validate(host)
	if err != nil {
		return err
	}

	if len(constraints) == 0 {
		into.add(host)

		return nil
	}

	for _, constraint := range constraints {
		into.add(entry(host, constraint))
	}

	return nil
}

// entry formats "proto/host:port". An IPv6 literal is bracketed so the port is not
// mistaken for part of the address.
func entry(host, constraint string) string {
	proto, port, _ := strings.Cut(constraint, "/")

	if isIPv6Literal(host) {
		return fmt.Sprintf("%s/[%s]:%s", proto, host, port)
	}

	return fmt.Sprintf("%s/%s:%s", proto, host, port)
}

func isIPv6Literal(host string) bool {
	addr, _, err := net.ParseCIDR(host)
	if err == nil {
		return addr.To4() == nil
	}

	parsed := net.ParseIP(host)

	return parsed != nil && parsed.To4() == nil
}

// portConstraints renders each port as "proto/port", deduplicated and ordered so a
// spec change that only reorders ports does not rewrite the ConfigMap.
func portConstraints(ports []v1alpha1.EgressPort) ([]string, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	seen := newOrderedSet()

	for _, port := range ports {
		if port.Port < 1 || port.Port > 65535 {
			return nil, fmt.Errorf("%w: %d", ErrInvalidPort, port.Port)
		}

		proto := strings.ToLower(strings.TrimSpace(port.Protocol))
		if proto == "" {
			proto = "tcp"
		}

		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("%w: protocol %q", ErrInvalidPort, port.Protocol)
		}

		seen.add(fmt.Sprintf("%s/%d", proto, port.Port))
	}

	return seen.sorted(), nil
}

func validateNetwork(value string) error {
	if value == "" {
		return fmt.Errorf("%w: empty", ErrInvalidNetwork)
	}

	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("%w: %q", ErrInvalidNetwork, value)
		}

		return nil
	}

	if net.ParseIP(value) == nil {
		return fmt.Errorf("%w: %q", ErrInvalidNetwork, value)
	}

	return nil
}

// validateDomain rejects entries that would silently widen the policy: a bare "*"
// allows everything, and whitespace or a port would not parse as a domain.
func validateDomain(value string) error {
	err := checkNotWidening(value)
	if err != nil {
		return err
	}

	err = checkRenderable(value)
	if err != nil {
		return err
	}

	if strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") && len(value) > 2 {
		return validateRegex(value)
	}

	if strings.Contains(value, ":") {
		return fmt.Errorf("%w: %q has a port; use ports instead", ErrInvalidDomain, value)
	}

	if strings.Contains(value, "/") {
		return fmt.Errorf("%w: %q contains a path", ErrInvalidDomain, value)
	}

	return validateHostname(value)
}

func validateRegex(value string) error {
	inner := value[1 : len(value)-1]
	if len(inner) > maxRegexLength {
		return fmt.Errorf("%w: regex is too long", ErrInvalidDomain)
	}

	_, err := regexp.Compile(`\A(?i:` + inner + `)\z`)
	if err != nil {
		return fmt.Errorf("%w: regex %q: %w", ErrInvalidDomain, value, err)
	}

	return nil
}

func validateHostname(value string) error {
	original := value

	value, wildcard := trimLeadingWildcard(value)
	if wildcard {
		return validateWildcard(value)
	}

	value = strings.TrimSuffix(value, ".")

	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > maxDomainLength || net.ParseIP(ascii) != nil {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, original)
	}

	if !validDomainLabels(ascii) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, original)
	}

	return nil
}

func trimLeadingWildcard(value string) (string, bool) {
	suffix, leading := strings.CutPrefix(value, "*.")
	if leading && !strings.Contains(suffix, "*") {
		return suffix, false
	}

	return value, strings.Contains(value, "*")
}

func validDomainLabels(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || allDigits(parts[len(parts)-1]) {
		return false
	}

	for _, part := range parts {
		if !validLabel(part) {
			return false
		}
	}

	return true
}

func validateWildcard(value string) error {
	value = strings.TrimSuffix(value, ".")
	if !validWildcardStructure(value) {
		return fmt.Errorf("%w: wildcard %q", ErrInvalidDomain, value)
	}

	for part := range strings.SplitSeq(value, "*") {
		for _, r := range part {
			if !wildcardCharacter(r) {
				return fmt.Errorf("%w: wildcard %q", ErrInvalidDomain, value)
			}
		}
	}

	return nil
}

func validWildcardStructure(value string) bool {
	return len(value) <= maxDomainLength &&
		!strings.Contains(value, "**") &&
		!strings.Contains(value, "..") &&
		!strings.HasPrefix(value, ".") &&
		!strings.HasSuffix(value, ".") &&
		strings.Contains(value, ".")
}

func wildcardCharacter(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' || r == '.' || r == '-'
}

func validLabel(value string) bool {
	return hostnameLabel.MatchString(value)
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func checkNotWidening(value string) error {
	if value == "" {
		return fmt.Errorf("%w: empty", ErrInvalidDomain)
	}

	if value == "*" || value == "*." {
		return fmt.Errorf("%w: %q matches every destination", ErrInvalidDomain, value)
	}

	if strings.ContainsAny(value, " \t\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidDomain, value)
	}

	return nil
}

// checkRenderable rejects values that would break the YAML the domain is written
// into. Invalid UTF-8, a control byte or a separator makes the whole document
// unparseable, dropping every other rule with it.
func checkRenderable(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %q is not valid UTF-8", ErrInvalidDomain, value)
	}

	for _, r := range value {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: %q contains a non-printable character", ErrInvalidDomain, value)
		}
	}

	return nil
}

// orderedSet deduplicates while producing deterministic output.
type orderedSet struct {
	seen map[string]struct{}
}

func newOrderedSet() *orderedSet {
	return &orderedSet{seen: make(map[string]struct{})}
}

func (s *orderedSet) add(value string) {
	s.seen[value] = struct{}{}
}

func (s *orderedSet) sorted() []string {
	if len(s.seen) == 0 {
		return nil
	}

	out := make([]string, 0, len(s.seen))
	for value := range s.seen {
		out = append(out, value)
	}

	sort.Strings(out)

	return out
}

// Document renders the policy as the YAML the agent's policy ConfigMap holds.
// Output is deterministic so an unchanged spec never rewrites the ConfigMap and
// never triggers a pointless reload in every filtered pod.
func (p Policy) Document() string {
	var b strings.Builder

	b.WriteString("# Rendered by the g0efilter controller. Do not edit.\n")
	b.WriteString("allowlist:\n")

	writeList(&b, "ips", p.Networks)
	writeList(&b, "domains", p.Domains)

	return b.String()
}

func writeList(b *strings.Builder, field string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(b, "  %s: []\n", field)

		return
	}

	fmt.Fprintf(b, "  %s:\n", field)

	for _, value := range values {
		// A quote in a regex pattern would otherwise close the scalar and make the
		// whole document unparseable, dropping every rule the policy carries.
		fmt.Fprintf(b, "    - '%s'\n", strings.ReplaceAll(value, "'", "''"))
	}
}
