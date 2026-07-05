// Package nftables provides nftables integration.
package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/internal/actions"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	minPacketSize = 20
)

var errPortOutOfRange = errors.New("port out of range")

// Version returns the nftables version string.
func Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "nft", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get nft version: %w", err)
	}

	// Output is typically "nftables v1.0.9 (Spark In The Dark)"
	version := strings.TrimPrefix(strings.TrimSpace(string(out)), "nftables ")

	return version, nil
}

// parsePort validates and converts a port string to an integer between 1 and 65535.
func parsePort(s, name string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid %s port %q: %w", name, s, err)
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: %s port %d", errPortOutOfRange, name, port)
	}

	return port, nil
}

func splitByFamily(allowlist []string) ([]string, []string) {
	var v4, v6 []string

	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}

			if ipnet.IP.To4() != nil {
				v4 = append(v4, entry)
			} else {
				v6 = append(v6, entry)
			}

			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}

	return v4, v6
}

// ApplyNftRulesAuto applies nftables rules using port numbers from environment variables or defaults.
func ApplyNftRulesAuto(allowlist []string, httpsPortStr, httpPortStr string) error {
	dnsPortStr := strings.TrimSpace(os.Getenv("DNS_PORT"))
	if dnsPortStr == "" {
		dnsPortStr = "53"
	}

	return ApplyNftRules(allowlist, httpsPortStr, httpPortStr, dnsPortStr)
}

func validateAndParseRuleset(ctx context.Context, ruleset string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft dry-run failed: %w\nOutput:\n%s", err, out.String())
	}

	return nil
}

func applyRuleset(ctx context.Context, ruleset string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w\nOutput:\n%s", err, out.String())
	}

	return nil
}

// atomicReplacePreamble removes all managed tables inside the replacement transaction.
const atomicReplacePreamble = `table ip g0efilter_v4
delete table ip g0efilter_v4
table ip g0efilter_nat_v4
delete table ip g0efilter_nat_v4
table ip6 g0efilter_v6
delete table ip6 g0efilter_v6
table ip6 g0efilter_nat_v6
delete table ip6 g0efilter_nat_v6
`

// PolicyRules describes the inputs for ruleset generation and application.
type PolicyRules struct {
	AllowIPs     []string
	DenyIPs      []string // enforced only when DefaultAllow is true
	DefaultAllow bool
	Audit        bool // dry-run: would-be drops are logged with the "audit" prefix and accepted
}

// ApplyNftRulesWithContext generates and applies a default-deny ruleset using the provided context.
func ApplyNftRulesWithContext(
	ctx context.Context,
	allowlist []string,
	httpsPortStr,
	httpPortStr,
	dnsPortStr string) error {
	//nolint:exhaustruct
	return ApplyPolicyRulesWithContext(ctx, PolicyRules{AllowIPs: allowlist}, httpsPortStr, httpPortStr, dnsPortStr)
}

// ApplyPolicyRulesWithContext generates and applies the nftables ruleset for the given policy stance.
func ApplyPolicyRulesWithContext(
	ctx context.Context,
	rules PolicyRules,
	httpsPortStr,
	httpPortStr,
	dnsPortStr string) error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("FILTER_MODE")))
	if mode == "" {
		mode = actions.ModeHTTPS
	}

	if len(rules.AllowIPs) == 0 {
		rules.AllowIPs = []string{"127.0.0.1"}
	}

	httpsPort, err := parsePort(httpsPortStr, "HTTPS")
	if err != nil {
		return err
	}

	httpPort, err := parsePort(httpPortStr, "HTTP")
	if err != nil {
		return err
	}

	dnsPort, err := parsePort(dnsPortStr, "DNS")
	if err != nil {
		return err
	}

	allowV4, allowV6 := splitByFamily(rules.AllowIPs)
	denyV4, denyV6 := splitByFamily(rules.DenyIPs)

	ruleset := GenerateRuleset(RulesetConfig{
		AllowV4:      allowV4,
		AllowV6:      allowV6,
		DenyV4:       denyV4,
		DenyV6:       denyV6,
		HTTPSPort:    httpsPort,
		HTTPPort:     httpPort,
		DNSPort:      dnsPort,
		Mode:         mode,
		DefaultAllow: rules.DefaultAllow,
		Audit:        rules.Audit,
	})
	if !strings.HasSuffix(ruleset, "\n") {
		ruleset += "\n"
	}

	// Avoid a default-open gap during live reload.
	ruleset = atomicReplacePreamble + ruleset

	err = validateAndParseRuleset(ctx, ruleset)
	if err != nil {
		return err
	}

	return applyRuleset(ctx, ruleset)
}

// ApplyNftRules applies nftables rules using a background context.
func ApplyNftRules(allowlist []string, httpsPortStr, httpPortStr, dnsPortStr string) error {
	return ApplyNftRulesWithContext(context.Background(), allowlist, httpsPortStr, httpPortStr, dnsPortStr)
}

// setBlock renders a named nftables set, omitting the elements line when the list is empty.
func setBlock(name, addrType, elements string) string {
	if elements == "" {
		return fmt.Sprintf("    set %s {\n        type %s\n        flags interval\n    }\n", name, addrType)
	}

	return fmt.Sprintf(
		"    set %s {\n        type %s\n        flags interval\n        elements = {%s}\n    }\n",
		name, addrType, elements,
	)
}

// generateHTTPSFilterRulesAllow creates IPv4 filter rules for HTTPS default-allow (denylist) mode.
func generateHTTPSFilterRulesAllow(allowSet, denySet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
%s%s
    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on 127.0.0.1
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTP proxy
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTPS proxy

        # Explicit allowlist overrides the denylist
        ip daddr @allow_daddr_v4 accept

        # Log and drop deny-listed destinations
        ip daddr @deny_daddr_v4 log prefix "blocked" group 0
        ip daddr @deny_daddr_v4 drop
    }
}
`, setBlock("allow_daddr_v4", "ipv4_addr", allowSet),
		setBlock("deny_daddr_v4", "ipv4_addr", denySet),
		httpPort, httpsPort)
}

// generateHTTPSNATRulesAllow creates IPv4 NAT rules for HTTPS default-allow mode. Deny-listed
// IPs are not redirected so they keep their original daddr for the filter chain to log+drop.
func generateHTTPSNATRulesAllow(allowSet, denySet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_nat_v4 {
%s%s
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip daddr @allow_daddr_v4 return

        # Deny-listed IPs are dropped in the filter chain, not proxied
        ip daddr @deny_daddr_v4 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, setBlock("allow_daddr_v4", "ipv4_addr", allowSet),
		setBlock("deny_daddr_v4", "ipv4_addr", denySet),
		httpPort, httpsPort)
}

// generateHTTPSFilterRulesAllowV6 creates IPv6 filter rules for HTTPS default-allow mode.
func generateHTTPSFilterRulesAllowV6(allowSet, denySet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
%s%s
    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on ::1
        ip6 daddr ::1 tcp dport %d accept    # HTTP proxy
        ip6 daddr ::1 tcp dport %d accept    # HTTPS proxy

        # Explicit allowlist overrides the denylist
        ip6 daddr @allow_daddr_v6 accept

        # Log and drop deny-listed destinations
        ip6 daddr @deny_daddr_v6 log prefix "blocked" group 0
        ip6 daddr @deny_daddr_v6 drop
    }
}
`, setBlock("allow_daddr_v6", "ipv6_addr", allowSet),
		setBlock("deny_daddr_v6", "ipv6_addr", denySet),
		httpPort, httpsPort)
}

// generateHTTPSNATRulesAllowV6 creates IPv6 NAT rules for HTTPS default-allow mode.
func generateHTTPSNATRulesAllowV6(allowSet, denySet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_nat_v6 {
%s%s
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip6 daddr @allow_daddr_v6 return

        # Deny-listed IPs are dropped in the filter chain, not proxied
        ip6 daddr @deny_daddr_v6 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, setBlock("allow_daddr_v6", "ipv6_addr", allowSet),
		setBlock("deny_daddr_v6", "ipv6_addr", denySet),
		httpPort, httpsPort)
}

// generateDNSFilterRulesAllow creates IPv4 filter rules for DNS default-allow mode.
// The chain is already policy accept; deny-listed IPs are logged and dropped.
func generateDNSFilterRulesAllow(allowSet, denySet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
%s%s
    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip daddr 127.0.0.1 udp dport %d accept
        ip daddr 127.0.0.1 tcp dport %d accept

        # Explicit allowlist overrides the denylist
        ip daddr @allow_daddr_v4 accept

        # Log and drop deny-listed destinations
        ip daddr @deny_daddr_v4 log prefix "blocked" group 0
        ip daddr @deny_daddr_v4 drop
    }
}
`, setBlock("allow_daddr_v4", "ipv4_addr", allowSet),
		setBlock("deny_daddr_v4", "ipv4_addr", denySet),
		dnsPort, dnsPort)
}

// generateDNSFilterRulesAllowV6 creates IPv6 filter rules for DNS default-allow mode.
func generateDNSFilterRulesAllowV6(allowSet, denySet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
%s%s
    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip6 daddr ::1 udp dport %d accept
        ip6 daddr ::1 tcp dport %d accept

        # Explicit allowlist overrides the denylist
        ip6 daddr @allow_daddr_v6 accept

        # Log and drop deny-listed destinations
        ip6 daddr @deny_daddr_v6 log prefix "blocked" group 0
        ip6 daddr @deny_daddr_v6 drop
    }
}
`, setBlock("allow_daddr_v6", "ipv6_addr", allowSet),
		setBlock("deny_daddr_v6", "ipv6_addr", denySet),
		dnsPort, dnsPort)
}

// generateDNSStrictFilterRules creates IPv4 filter rules for dns-strict mode: policy drop,
// with a runtime resolved_allow_v4 timeout set that the DNS proxy populates as allowed
// domains resolve. Connections to IPs never resolved through the proxy are dropped.
func generateDNSStrictFilterRules(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
%s
    set resolved_allow_v4 {
        type ipv4_addr
        flags timeout
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip daddr 127.0.0.1 udp dport %d accept
        ip daddr 127.0.0.1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept

        # Allow and log statically allow-listed destinations
        ip daddr @allow_daddr_v4 log prefix "allowed" group 0
        ip daddr @allow_daddr_v4 accept

        # Allow destinations resolved through the DNS proxy (TTL-bounded)
        ip daddr @resolved_allow_v4 log prefix "allowed" group 0
        ip daddr @resolved_allow_v4 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, setBlock("allow_daddr_v4", "ipv4_addr", allowSet), dnsPort, dnsPort)
}

// generateDNSStrictFilterRulesV6 creates IPv6 filter rules for dns-strict mode.
func generateDNSStrictFilterRulesV6(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
%s
    set resolved_allow_v6 {
        type ipv6_addr
        flags timeout
    }

    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip6 daddr ::1 udp dport %d accept
        ip6 daddr ::1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmpv6 type echo-request ip6 daddr @allow_daddr_v6 accept

        # ICMPv6 neighbour discovery is required for any IPv6 connectivity
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

        # Allow and log statically allow-listed destinations
        ip6 daddr @allow_daddr_v6 log prefix "allowed" group 0
        ip6 daddr @allow_daddr_v6 accept

        # Allow destinations resolved through the DNS proxy (TTL-bounded)
        ip6 daddr @resolved_allow_v6 log prefix "allowed" group 0
        ip6 daddr @resolved_allow_v6 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, setBlock("allow_daddr_v6", "ipv6_addr", allowSet), dnsPort, dnsPort)
}

// generateDNSFilterRules creates nftables filter rules for DNS mode that block non-allowlisted traffic.
func generateDNSFilterRules(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip daddr 127.0.0.1 udp dport %d accept
        ip daddr 127.0.0.1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept
    }
}
`, allowSet, dnsPort, dnsPort)
}

// generateHTTPSFilterRules creates nftables filter rules for HTTPS mode with logging and allowlist enforcement.
func generateHTTPSFilterRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on 127.0.0.1
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTP proxy
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTPS proxy

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept

        # Allow and log allow-listed destinations
        ip daddr @allow_daddr_v4 log prefix "allowed" group 0
        ip daddr @allow_daddr_v4 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateDNSNATRules creates nftables NAT rules that redirect all DNS traffic to the local DNS proxy.
func generateDNSNATRules(dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_nat_v4 {
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Exempt direct access to the local DNS proxy
        ip daddr 127.0.0.1 udp dport 53 return
        ip daddr 127.0.0.1 tcp dport 53 return
        ip daddr 127.0.0.1 udp dport %d return
        ip daddr 127.0.0.1 tcp dport %d return

        # Redirect ALL DNS (UDP/TCP 53) to local DNS proxy
        udp dport 53  log prefix "dns_redirected" group 0
        udp dport 53  redirect to :%d
        tcp dport 53  log prefix "dns_redirected" group 0
        tcp dport 53  redirect to :%d
    }
}
`, dnsPort, dnsPort, dnsPort, dnsPort)
}

// generateHTTPSNATRules creates nftables NAT rules that redirect HTTP/HTTPS to local proxies for non-allowlisted IPs.
func generateHTTPSNATRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_nat_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip daddr @allow_daddr_v4 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateHTTPSFilterRulesV6 creates IPv6 nftables filter rules for HTTPS mode.
func generateHTTPSFilterRulesV6(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on ::1
        ip6 daddr ::1 tcp dport %d accept    # HTTP proxy
        ip6 daddr ::1 tcp dport %d accept    # HTTPS proxy

        # Allow ping to allow-listed destinations
        icmpv6 type echo-request ip6 daddr @allow_daddr_v6 accept

        # Allow and log allow-listed destinations
        ip6 daddr @allow_daddr_v6 log prefix "allowed" group 0
        ip6 daddr @allow_daddr_v6 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateHTTPSNATRulesV6 creates IPv6 nftables NAT rules for HTTPS mode.
func generateHTTPSNATRulesV6(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_nat_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip6 daddr @allow_daddr_v6 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateDNSFilterRulesV6 creates IPv6 nftables filter rules for DNS mode.
func generateDNSFilterRulesV6(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip6 daddr ::1 udp dport %d accept
        ip6 daddr ::1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmpv6 type echo-request ip6 daddr @allow_daddr_v6 accept
    }
}
`, allowSet, dnsPort, dnsPort)
}

// generateDNSNATRulesV6 creates IPv6 nftables NAT rules for DNS mode.
func generateDNSNATRulesV6(dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_nat_v6 {
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Exempt direct access to the local DNS proxy
        ip6 daddr ::1 udp dport 53 return
        ip6 daddr ::1 tcp dport 53 return
        ip6 daddr ::1 udp dport %d return
        ip6 daddr ::1 tcp dport %d return

        # Redirect ALL DNS (UDP/TCP 53) to local DNS proxy
        udp dport 53  log prefix "dns_redirected" group 0
        udp dport 53  redirect to :%d
        tcp dport 53  log prefix "dns_redirected" group 0
        tcp dport 53  redirect to :%d
    }
}
`, dnsPort, dnsPort, dnsPort, dnsPort)
}

// GenerateNftRuleset generates a complete default-deny nftables ruleset for the specified
// mode, ports, and allowlists. v4 and v6 are pre-split IPv4 and IPv6 allowlist entries.
func GenerateNftRuleset(v4, v6 []string, httpsPort, httpPort, dnsPort int, mode string) string {
	//nolint:exhaustruct
	return GenerateRuleset(RulesetConfig{
		AllowV4:   v4,
		AllowV6:   v6,
		HTTPSPort: httpsPort,
		HTTPPort:  httpPort,
		DNSPort:   dnsPort,
		Mode:      mode,
	})
}

// RulesetConfig holds all inputs for nftables ruleset generation.
type RulesetConfig struct {
	AllowV4, AllowV6 []string
	DenyV4, DenyV6   []string // enforced only when DefaultAllow is true
	HTTPSPort        int
	HTTPPort         int
	DNSPort          int
	Mode             string
	DefaultAllow     bool
	Audit            bool // dry-run: would-be drops logged with the "audit" prefix and accepted
}

// GenerateRuleset generates a complete nftables ruleset. With DefaultAllow the filter
// chains are policy accept and deny-listed IPs are logged and dropped; otherwise the
// default-deny allowlist model applies. HTTP/HTTPS (or DNS) traffic is redirected
// through the local proxies in both stances so domain policy applies. With Audit,
// every drop verdict becomes an "audit" log plus accept.
func GenerateRuleset(cfg RulesetConfig) string {
	ruleset := generateEnforcingRuleset(cfg)
	if cfg.Audit {
		ruleset = auditRuleset(ruleset)
	}

	return ruleset
}

// auditRuleset converts a ruleset's enforcement verdicts to dry-run equivalents:
// chains fail open and would-be drops log with the "audit" prefix instead. The
// replacements match the exact verdict forms our templates emit.
func auditRuleset(ruleset string) string {
	ruleset = strings.ReplaceAll(ruleset, "policy drop;", "policy accept;")
	ruleset = strings.ReplaceAll(ruleset, `log prefix "blocked" group 0`, `log prefix "audit" group 0`)
	ruleset = strings.ReplaceAll(ruleset, "\n        drop\n", "\n        accept\n")
	ruleset = strings.ReplaceAll(ruleset, " @deny_daddr_v4 drop", " @deny_daddr_v4 accept")
	ruleset = strings.ReplaceAll(ruleset, " @deny_daddr_v6 drop", " @deny_daddr_v6 accept")

	return ruleset
}

func generateEnforcingRuleset(cfg RulesetConfig) string {
	mode := strings.ToLower(cfg.Mode)
	if mode != actions.ModeDNS && mode != actions.ModeDNSStrict {
		mode = actions.ModeHTTPS
	}

	// Placeholder entries keep the allow sets non-empty (loopback is harmless to allow).
	allowSetV4 := strings.Join(cfg.AllowV4, ", ")
	if allowSetV4 == "" {
		allowSetV4 = "127.0.0.1"
	}

	allowSetV6 := strings.Join(cfg.AllowV6, ", ")
	if allowSetV6 == "" {
		allowSetV6 = "::1"
	}

	if cfg.DefaultAllow {
		denySetV4 := strings.Join(cfg.DenyV4, ", ")
		denySetV6 := strings.Join(cfg.DenyV6, ", ")

		// Strict enforcement is meaningless under default-allow: fall back to plain DNS-mode rules
		if mode == actions.ModeDNS || mode == actions.ModeDNSStrict {
			return generateDNSFilterRulesAllow(allowSetV4, denySetV4, cfg.DNSPort) +
				"\n" + generateDNSNATRules(cfg.DNSPort) +
				"\n" + generateDNSFilterRulesAllowV6(allowSetV6, denySetV6, cfg.DNSPort) +
				"\n" + generateDNSNATRulesV6(cfg.DNSPort)
		}

		return generateHTTPSFilterRulesAllow(allowSetV4, denySetV4, cfg.HTTPPort, cfg.HTTPSPort) +
			"\n" + generateHTTPSNATRulesAllow(allowSetV4, denySetV4, cfg.HTTPPort, cfg.HTTPSPort) +
			"\n" + generateHTTPSFilterRulesAllowV6(allowSetV6, denySetV6, cfg.HTTPPort, cfg.HTTPSPort) +
			"\n" + generateHTTPSNATRulesAllowV6(allowSetV6, denySetV6, cfg.HTTPPort, cfg.HTTPSPort)
	}

	if mode == actions.ModeDNSStrict {
		return generateDNSStrictFilterRules(allowSetV4, cfg.DNSPort) +
			"\n" + generateDNSNATRules(cfg.DNSPort) +
			"\n" + generateDNSStrictFilterRulesV6(allowSetV6, cfg.DNSPort) +
			"\n" + generateDNSNATRulesV6(cfg.DNSPort)
	}

	if mode == actions.ModeDNS {
		return generateDNSFilterRules(allowSetV4, cfg.DNSPort) +
			"\n" + generateDNSNATRules(cfg.DNSPort) +
			"\n" + generateDNSFilterRulesV6(allowSetV6, cfg.DNSPort) +
			"\n" + generateDNSNATRulesV6(cfg.DNSPort)
	}

	return generateHTTPSFilterRules(allowSetV4, cfg.HTTPPort, cfg.HTTPSPort) +
		"\n" + generateHTTPSNATRules(allowSetV4, cfg.HTTPPort, cfg.HTTPSPort) +
		"\n" + generateHTTPSFilterRulesV6(allowSetV6, cfg.HTTPPort, cfg.HTTPSPort) +
		"\n" + generateHTTPSNATRulesV6(allowSetV6, cfg.HTTPPort, cfg.HTTPSPort)
}

// StreamNfLog starts streaming netfilter log events using the default logger.
func StreamNfLog() error {
	return StreamNfLogWithLogger(context.Background(), slog.Default())
}

// parseNflogConfig reads NFLOG_BUFSIZE and NFLOG_QTHRESH from environment or returns defaults.
func parseNflogConfig() (uint32, uint32) {
	dfltBuf := uint32(96)
	dfltQ := uint32(50)

	if v := strings.TrimSpace(os.Getenv("NFLOG_BUFSIZE")); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil && n > 0 {
			dfltBuf = uint32(n)
		}
	}

	if v := strings.TrimSpace(os.Getenv("NFLOG_QTHRESH")); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil && n > 0 {
			dfltQ = uint32(n)
		}
	}

	return dfltBuf, dfltQ
}

// setupLogger creates a logger with component, hostname, and tenant_id context fields.
func setupLogger(lg *slog.Logger) *slog.Logger {
	hostname := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil {
			hostname = strings.TrimSpace(h)
		}
	}

	base := []any{"component", "nflog"}
	if hostname != "" {
		base = append(base, "hostname", hostname)
	}

	if tid := strings.TrimSpace(os.Getenv("TENANT_ID")); tid != "" {
		base = append(base, "tenant_id", tid)
	}

	return lg.With(base...)
}

// PacketInfo holds parsed network layer information from a raw packet.
type PacketInfo struct {
	Src             string
	Dst             string
	Protocol        string
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
}

// parseIPLayer decodes the IP layer from a raw packet payload.
// Returns the parsed packet, source/destination IPs, protocol number, and whether parsing succeeded.
func parseIPLayer(payload []byte) (gopacket.Packet, string, string, uint8, bool) {
	switch payload[0] >> 4 {
	case 4:
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return nil, "", "", 0, false
		}

		ip := ipLayer.(*layers.IPv4) //nolint:forcetypeassert

		return packet, ip.SrcIP.String(), ip.DstIP.String(), uint8(ip.Protocol), true
	case 6:
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)

		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return nil, "", "", 0, false
		}

		ip6 := ip6Layer.(*layers.IPv6) //nolint:forcetypeassert

		return packet, ip6.SrcIP.String(), ip6.DstIP.String(), uint8(ip6.NextHeader), true
	default:
		return nil, "", "", 0, false
	}
}

// parsePacketInfo extracts network layer information from a raw packet payload.
// Supports both IPv4 and IPv6 packets.
func parsePacketInfo(payload []byte) PacketInfo {
	if len(payload) < minPacketSize {
		return PacketInfo{}
	}

	packet, srcIP, dstIP, protoNum, ok := parseIPLayer(payload)
	if !ok {
		return PacketInfo{}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP) //nolint:forcetypeassert

		return PacketInfo{
			Src:             fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort),
			Dst:             fmt.Sprintf("%s:%d", dstIP, tcp.DstPort),
			Protocol:        "TCP",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      int(tcp.SrcPort),
			DestinationPort: int(tcp.DstPort),
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP) //nolint:forcetypeassert

		return PacketInfo{
			Src:             fmt.Sprintf("%s:%d", srcIP, udp.SrcPort),
			Dst:             fmt.Sprintf("%s:%d", dstIP, udp.DstPort),
			Protocol:        "UDP",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      int(udp.SrcPort),
			DestinationPort: int(udp.DstPort),
		}
	}

	return PacketInfo{
		Src:           srcIP,
		Dst:           dstIP,
		Protocol:      strconv.Itoa(int(protoNum)),
		SourceIP:      srcIP,
		DestinationIP: dstIP,
	}
}

// mapPrefixToAction maps nftables log prefix strings to action types.
func mapPrefixToAction(prefix string) string {
	pl := strings.ToLower(prefix)

	switch {
	case strings.Contains(pl, "redirect"):
		return actions.ActionRedirected
	case strings.Contains(pl, "block"):
		return actions.ActionBlocked
	case strings.Contains(pl, "audit"):
		return actions.ActionAudit
	case strings.Contains(pl, "allow"):
		return actions.ActionAllowed
	default:
		return ""
	}
}

// buildLogFields constructs a slice of structured log fields from packet information.
func buildLogFields(
	src, dst, proto, sourceIP, destinationIP, flowID string, sourcePort, destinationPort, payloadLen int,
) []any {
	fields := []any{
		"protocol", proto,
		"payload_len", payloadLen,
	}

	if src != "" {
		fields = append(fields, "src", src)
	}

	if dst != "" {
		fields = append(fields, "dst", dst)
	}

	if sourceIP != "" {
		fields = append(fields, "source_ip", sourceIP)
	}

	if sourcePort != 0 {
		fields = append(fields, "source_port", sourcePort)
	}

	if destinationIP != "" {
		fields = append(fields, "destination_ip", destinationIP)
	}

	if destinationPort != 0 {
		fields = append(fields, "destination_port", destinationPort)
	}

	if flowID != "" {
		fields = append(fields, "flow_id", flowID)
	}

	return fields
}

// processActionEvent logs nflog events, suppressing duplicate synthetic events when appropriate.
func processActionEvent(
	lg *slog.Logger,
	action, flowID string,
	pkt PacketInfo,
	payloadLen int,
) {
	// If we have a recent synthetic for this flow, suppress kernel nflog REDIRECTED to avoid duplicates
	if action == actions.ActionRedirected && flowID != "" && actions.IsSyntheticRecent(flowID) {
		return // handled, skip logging
	}

	fields := buildLogFields(
		pkt.Src, pkt.Dst, pkt.Protocol, pkt.SourceIP, pkt.DestinationIP,
		flowID, pkt.SourcePort, pkt.DestinationPort, payloadLen,
	)
	fields = append(fields, "action", action)

	// Level policy: REDIRECTED and ALLOWED at DEBUG, BLOCKED at WARN
	if action == actions.ActionRedirected || action == actions.ActionAllowed {
		lg.Debug("nflog.event", fields...)
	} else {
		lg.Warn("nflog.event", fields...)
	}
}

// createNflogHook creates a callback function that processes each nflog packet and logs it.
func createNflogHook(lg *slog.Logger) func(nflog.Attribute) int {
	return func(attrs nflog.Attribute) int {
		prefix := ""
		if attrs.Prefix != nil {
			prefix = *attrs.Prefix
		}

		payloadLen := 0
		if attrs.Payload != nil {
			payloadLen = len(*attrs.Payload)
		}

		if payloadLen < minPacketSize {
			// Ignore tiny packets
			return 0
		}

		pkt := parsePacketInfo(*attrs.Payload)

		if pkt.Src == "" && pkt.Dst == "" {
			// Unsupported network layer
			return 0
		}

		action := mapPrefixToAction(prefix)

		// Compute flow id
		flowID := ""
		if pkt.SourceIP != "" && pkt.DestinationIP != "" {
			flowID = actions.FlowID(pkt.SourceIP, pkt.SourcePort, pkt.DestinationIP, pkt.DestinationPort, pkt.Protocol)
		}

		if action != "" {
			processActionEvent(lg, action, flowID, pkt, payloadLen)

			return 0
		}

		// Minimal debug for non-action packets (will include hostname/component from lg context)
		lg.Debug("nflog.packet",
			"prefix", prefix, "protocol", pkt.Protocol,
			"src", pkt.Src, "dst", pkt.Dst, "payload_len", payloadLen,
		)

		return 0
	}
}

// StreamNfLogWithLogger streams netfilter log events from group 0 using the provided logger until context is done.
func StreamNfLogWithLogger(ctx context.Context, lg *slog.Logger) error {
	dfltBuf, dfltQ := parseNflogConfig()
	lg = setupLogger(lg)

	config := nflog.Config{
		Group:    0,
		Copymode: nflog.CopyPacket,
		Bufsize:  dfltBuf,
		QThresh:  dfltQ,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		return fmt.Errorf("nflog open failed: %w", err)
	}

	defer func() { _ = nf.Close() }()

	// Error handler that silently continues on errors
	errFunc := func(_ error) int {
		return 0 // Return 0 to keep receiving messages
	}

	err = nf.RegisterWithErrorFunc(ctx, createNflogHook(lg), errFunc)
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	// Block until context is cancelled
	<-ctx.Done()

	return nil
}
