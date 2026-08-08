package policy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ProtoTCP and ProtoUDP are the protocol constraint values.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

var (
	errPortRange      = errors.New("invalid port (want 1-65535)")
	errProtoNeedsPort = errors.New("protocol constraint requires a port")
	errPortOnDenylist = errors.New("port constraints are not supported on the denylist")
)

// IPPortRule is a parsed allow/deny IP entry with optional protocol and port
// constraints. Proto "" and Port 0 mean "any" (an unconstrained whole-IP rule).
type IPPortRule struct {
	Addr  string // IP or CIDR
	Proto string // "tcp", "udp", or "" for any
	Port  int    // 1-65535, or 0 for any
}

// Constrained reports whether the rule restricts protocol/port rather than
// matching all traffic to the address.
func (r IPPortRule) Constrained() bool {
	return r.Port != 0
}

// ParseIPPortRule parses "[proto/]ip[:port]" or "[proto/]cidr[:port]". A bare
// ip/cidr is unconstrained; a port with no protocol defaults to tcp; a protocol
// prefix requires a port.
func ParseIPPortRule(entry string) (IPPortRule, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return IPPortRule{}, fmt.Errorf("%w: empty", errInvalidIP)
	}

	proto, entry := splitProto(entry)

	addr, port, err := splitAddrPort(entry)
	if err != nil {
		return IPPortRule{}, err
	}

	// validateIP trims before checking, so "[:: ]" would validate and then be
	// silently dropped by every consumer that re-parses Addr. Reject it instead of
	// normalising: a typo should fail loudly, not quietly change what is allowed.
	if strings.TrimSpace(addr) != addr {
		return IPPortRule{}, fmt.Errorf("%w (contains whitespace): %s", errInvalidIP, entry)
	}

	proto, err = resolveProtoPort(proto, port, entry)
	if err != nil {
		return IPPortRule{}, err
	}

	err = validateIP(addr)
	if err != nil {
		return IPPortRule{}, err
	}

	return IPPortRule{Addr: addr, Proto: proto, Port: port}, nil
}

// resolveProtoPort enforces that a protocol prefix carries a port, and defaults a
// bare port to tcp.
func resolveProtoPort(proto string, port int, entry string) (string, error) {
	if proto != "" && port == 0 {
		return "", fmt.Errorf("%w: %s", errProtoNeedsPort, entry)
	}

	if port != 0 && proto == "" {
		return ProtoTCP, nil
	}

	return proto, nil
}

func splitProto(entry string) (string, string) {
	switch {
	case strings.HasPrefix(strings.ToLower(entry), "tcp/"):
		return ProtoTCP, entry[len("tcp/"):]
	case strings.HasPrefix(strings.ToLower(entry), "udp/"):
		return ProtoUDP, entry[len("udp/"):]
	default:
		return "", entry
	}
}

func splitAddrPort(s string) (string, int, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("%w: %s", errInvalidIP, s)
		}

		addr := s[1:end]
		rest := s[end+1:]

		if rest == "" {
			return addr, 0, nil
		}

		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("%w: %s", errInvalidIP, s)
		}

		port, err := parsePortStr(rest[1:])

		return addr, port, err
	}

	// A single colon marks host:port; IPv6 literals have two or more.
	if strings.Count(s, ":") == 1 {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0, fmt.Errorf("%w: %s", errInvalidIP, s)
		}

		port, err := parsePortStr(portStr)

		return host, port, err
	}

	return s, 0, nil
}

// DomainRule is a parsed allowlist domain entry with an optional protocol and
// port constraint. Pattern keeps the bare exact/wildcard/regex form used for
// matching, so the constraint never affects which hosts match.
type DomainRule struct {
	Pattern string
	Proto   string // "tcp", "udp", or "" for any
	Port    int    // 1-65535, or 0 for any
}

// Constrained reports whether the rule restricts protocol/port.
func (r DomainRule) Constrained() bool {
	return r.Port != 0
}

// ParseDomainRule parses "[proto/]domain[:port]". A bare domain is unconstrained;
// a port with no protocol defaults to tcp; a protocol prefix requires a port.
func ParseDomainRule(entry string) (DomainRule, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return DomainRule{}, fmt.Errorf("%w: empty", errInvalidDomain)
	}

	proto, rest := splitProto(entry)

	pattern, port, err := splitDomainPort(rest)
	if err != nil {
		return DomainRule{}, err
	}

	proto, err = resolveProtoPort(proto, port, entry)
	if err != nil {
		return DomainRule{}, err
	}

	err = validateDomain(pattern)
	if err != nil {
		return DomainRule{}, err
	}

	return DomainRule{Pattern: pattern, Proto: proto, Port: port}, nil
}

// splitDomainPort separates a trailing :port. A domain never contains a colon and
// a regex pattern always ends with '/', so only an all-digit suffix is read as a
// port - a colon inside a regex body is left alone.
func splitDomainPort(s string) (string, int, error) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 || idx == len(s)-1 || !isAllDigits(s[idx+1:]) {
		return s, 0, nil
	}

	port, err := parsePortStr(s[idx+1:])
	if err != nil {
		return "", 0, err
	}

	return s[:idx], port, nil
}

func parsePortStr(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: %q", errPortRange, s)
	}

	return port, nil
}
