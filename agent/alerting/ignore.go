package alerting

import (
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
)

// ignoreRule suppresses the alert for an expected block. One entry of
// NOTIFICATION_IGNORE_DOMAINS compiles to one rule; see docs/configuration.md.
type ignoreRule interface {
	matches(info BlockedConnectionInfo) bool
}

type ignoreRules []ignoreRule

func compileIgnoreRules(patterns []string) ignoreRules {
	rules := make(ignoreRules, 0, len(patterns))

	for _, pattern := range patterns {
		rule, ok := parseIgnoreRule(pattern)
		if ok {
			rules = append(rules, rule)
		}
	}

	if len(rules) == 0 {
		return nil
	}

	return rules
}

func (r ignoreRules) matches(info BlockedConnectionInfo) bool {
	for _, rule := range r {
		if rule.matches(info) {
			return true
		}
	}

	return false
}

//nolint:ireturn // A rule set is heterogeneous by design; that is the extension point.
func parseIgnoreRule(pattern string) (ignoreRule, bool) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return nil, false
	}

	if rule, ok := namedRules[pattern]; ok {
		return rule, true
	}

	if class, ok := addrClasses[pattern]; ok {
		return addrClassRule{class: class}, true
	}

	if component, ok := strings.CutPrefix(pattern, "component:"); ok {
		if component == "" {
			return nil, false
		}

		return componentRule{component: component}, true
	}

	prefix, err := netip.ParsePrefix(pattern)
	if err == nil {
		return prefixRule{prefix: prefix.Masked()}, true
	}

	addr, err := netip.ParseAddr(pattern)
	if err == nil {
		return prefixRule{prefix: netip.PrefixFrom(addr, addr.BitLen())}, true
	}

	// A domain holds neither character: this is a malformed CIDR or a host:port.
	if strings.ContainsAny(pattern, "/:") {
		slog.Warn("notification.ignore_rule_invalid", "pattern", pattern)

		return nil, false
	}

	return domainRule{pattern: pattern}, true
}

type domainRule struct {
	pattern string
}

func (d domainRule) matches(info BlockedConnectionInfo) bool {
	return matchesPattern(strings.ToLower(info.Destination), d.pattern)
}

type prefixRule struct {
	prefix netip.Prefix
}

func (p prefixRule) matches(info BlockedConnectionInfo) bool {
	addr, ok := destinationAddr(info)

	return ok && p.prefix.Contains(addr)
}

// namedRules are the keyword rules; default is local addresses plus a host's clock sync.
//
//nolint:gochecknoglobals // A fixed lookup table, keyed by the documented names.
var namedRules = map[string]ignoreRule{
	"ip-only": ipOnlyRule{},
	"ntp":     ntpRule{},
	"default": ignoreRules{addrClassRule{class: isLocal}, ntpRule{}},
}

// addrClasses name the noisy ranges; IPv6 neighbor discovery alone floods ff02:: blocks.
//
//nolint:gochecknoglobals // A fixed lookup table, keyed by the documented names.
var addrClasses = map[string]func(netip.Addr) bool{
	"multicast":   netip.Addr.IsMulticast,
	"loopback":    netip.Addr.IsLoopback,
	"private":     netip.Addr.IsPrivate,
	"unspecified": netip.Addr.IsUnspecified,
	"link-local":  isLinkLocal,
	"local":       isLocal,
	"public":      func(addr netip.Addr) bool { return !isLocal(addr) },
}

func isLinkLocal(addr netip.Addr) bool {
	return addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

func isLocal(addr netip.Addr) bool {
	return addr.IsMulticast() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsUnspecified() || isLinkLocal(addr)
}

type addrClassRule struct {
	class func(netip.Addr) bool
}

func (a addrClassRule) matches(info BlockedConnectionInfo) bool {
	addr, ok := destinationAddr(info)

	return ok && a.class(addr)
}

// destinationAddr checks both fields: components populate one or the other.
func destinationAddr(info BlockedConnectionInfo) (netip.Addr, bool) {
	for _, candidate := range []string{info.DestinationIP, info.Destination} {
		addr, err := netip.ParseAddr(candidate)
		if err == nil {
			return addr, true
		}

		// A component may report the destination only as host:port.
		addrPort, err := netip.ParseAddrPort(candidate)
		if err == nil {
			return addrPort.Addr(), true
		}
	}

	return netip.Addr{}, false
}

// ntpRule suppresses a host's clock sync: UDP to port 123, which a runner or VM retries all
// job long. TCP to 123 is not NTP and still alerts.
type ntpRule struct{}

func (ntpRule) matches(info BlockedConnectionInfo) bool {
	return strings.EqualFold(info.Protocol, "udp") && destinationPort(info) == "123"
}

// destinationPort checks both fields, as destinationAddr does.
func destinationPort(info BlockedConnectionInfo) string {
	if info.DestinationPort != "" {
		return info.DestinationPort
	}

	addrPort, err := netip.ParseAddrPort(info.Destination)
	if err != nil {
		return ""
	}

	return strconv.Itoa(int(addrPort.Port()))
}

// ipOnlyRule suppresses blocks with no hostname, leaving the domain-aware components to alert.
type ipOnlyRule struct{}

func (ipOnlyRule) matches(info BlockedConnectionInfo) bool {
	ipPort := info.DestinationIP
	if info.DestinationPort != "" {
		ipPort = info.DestinationIP + ":" + info.DestinationPort
	}

	return isIPOnlyDestination(info.Destination, info.DestinationIP, ipPort)
}

type componentRule struct {
	component string
}

func (c componentRule) matches(info BlockedConnectionInfo) bool {
	return strings.EqualFold(info.Component, c.component)
}
