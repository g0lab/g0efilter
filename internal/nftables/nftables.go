// Package nftables provides netfilter nftables integration for g0efilter.
package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	actionRedirected = "REDIRECTED"
	modeSNI          = "sni"
	modeDNS          = "dns"
	minPacketSize    = 20
)

var errPortOutOfRange = errors.New("port out of range")

// ApplyNftRulesAuto applies nftables rules automatically using environment variables.
// It reads FILTER_MODE (defaults to "sni") and DNS_PORT (defaults to "53").
func ApplyNftRulesAuto(allowlist []string, httpsPortStr, httpPortStr string) error {
	dnsPortStr := strings.TrimSpace(os.Getenv("DNS_PORT"))
	if dnsPortStr == "" {
		dnsPortStr = "53"
	}

	return ApplyNftRules(allowlist, httpsPortStr, httpPortStr, dnsPortStr)
}

func validateAndParseRuleset(ruleset string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// nft -c -f -  (check only, does not modify kernel rules)
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

func applyRuleset(ruleset string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// nft -f - (apply)
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

// ApplyNftRules installs nftables rules for either SNI or DNS mode,
// selected by FILTER_MODE env var (default "sni").
//
// In "sni" mode:
//   - Redirects TCP/80 -> local HTTP proxy, TCP/443 -> local SNI proxy.
//   - No DNS redirection.
//
// In "dns" mode:
//   - Redirects UDP/TCP 53 -> local DNS proxy.
//   - No HTTP/HTTPS redirection.
//
// In both modes:
//   - Allows loopback and local proxy ports on 127.0.0.1.
//   - Exempts SO_MARK=0x1 traffic (set by the proxies) to avoid recursion.
//   - Allows egress to allow-listed destination IPs (ALLOW_DADDR_V4 set).

// ApplyNftRules installs nftables rules for either SNI or DNS mode.
func ApplyNftRules(allowlist []string, httpsPortStr, httpPortStr, dnsPortStr string) error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("FILTER_MODE")))
	if mode == "" {
		mode = modeSNI
	}

	parsePort := func(s, name string) (int, error) {
		port, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return 0, fmt.Errorf("invalid %s port %q: %w", name, s, err)
		}

		if port < 1 || port > 65535 {
			return 0, fmt.Errorf("%w: %s port %d", errPortOutOfRange, name, port)
		}

		return port, nil
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

	ruleset := GenerateNftRuleset(allowlist, httpsPort, httpPort, dnsPort, mode)
	if !strings.HasSuffix(ruleset, "\n") {
		ruleset += "\n"
	}

	err = validateAndParseRuleset(ruleset)
	if err != nil {
		return err
	}

	// Remove old tables (best-effort) then apply for real ---
	_ = deleteTableIfExists("ip", "filter_v4")
	_ = deleteTableIfExists("ip", "nat_v4")

	return applyRuleset(ruleset)
}

func generateDNSFilterRules(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip filter_v4 {
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

        # Block other DNS transports: DoT/DoQ (tcp/udp 853)
        tcp dport 853 drop
        udp dport 853 drop
    }
}
`, allowSet, dnsPort, dnsPort)
}

func generateSNIFilterRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip filter_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow local proxies on 127.0.0.1
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTP proxy
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTPS proxy

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

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

func generateDNSNATRules(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip nat_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

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
`, allowSet, dnsPort, dnsPort, dnsPort, dnsPort)
}

func generateSNINATRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip nat_v4 {
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

        # Redirect HTTP (80) to local HTTP proxy unless allow-listed IP
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  ip daddr != @allow_daddr_v4 redirect to :%d

        # Redirect HTTPS (443) to local SNI proxy unless allow-listed IP
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 ip daddr != @allow_daddr_v4 redirect to :%d
    }
}
`, allowSet, httpPort, httpsPort)
}

// GenerateNftRuleset generates nftables rules for the specified mode and ports.
func GenerateNftRuleset(allowlist []string, httpsPort, httpPort, dnsPort int, mode string) string {
	mode = strings.ToLower(mode)
	if mode != modeDNS {
		mode = modeSNI
	}

	allowSet := strings.Join(allowlist, ", ")
	if strings.TrimSpace(allowSet) == "" {
		allowSet = ""
	}

	var filterRules string
	if mode == modeDNS {
		filterRules = generateDNSFilterRules(allowSet, dnsPort)
	} else {
		filterRules = generateSNIFilterRules(allowSet, httpPort, httpsPort)
	}

	var natRules string
	if mode == modeDNS {
		natRules = generateDNSNATRules(allowSet, dnsPort)
	} else {
		natRules = generateSNINATRules(allowSet, httpPort, httpsPort)
	}

	return filterRules + "\n" + natRules
}

func deleteTableIfExists(family, table string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	probe := exec.CommandContext(ctx, "nft", "list", "table", family, table)

	var bout bytes.Buffer

	probe.Stdout = &bout

	probe.Stderr = &bout

	err := probe.Run()
	if err != nil {
		return nil // not found; nothing to delete
	}

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	del := exec.CommandContext(ctx, "nft", "delete", "table", family, table)

	err = del.Run()
	if err != nil {
		return fmt.Errorf("failed to delete table %s %s: %w", family, table, err)
	}

	return nil
}

// StreamNfLog streams netfilter log events using the default logger.
func StreamNfLog() error {
	return StreamNfLogWithLogger(context.Background(), slog.Default())
}

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

func parsePacketInfo(payload []byte) (string, string, string, string, string, int, int) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

	var src, dst, proto, sourceIP, destinationIP string

	var sourcePort, destinationPort int

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4) //nolint:forcetypeassert

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP) //nolint:forcetypeassert
			src = fmt.Sprintf("%s:%d", ip.SrcIP, tcp.SrcPort)
			dst = fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)
			proto = "TCP"
			sourceIP = ip.SrcIP.String()
			sourcePort = int(tcp.SrcPort)
			destinationIP = ip.DstIP.String()
			destinationPort = int(tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP) //nolint:forcetypeassert
			src = fmt.Sprintf("%s:%d", ip.SrcIP, udp.SrcPort)
			dst = fmt.Sprintf("%s:%d", ip.DstIP, udp.DstPort)
			proto = "UDP"
			sourceIP = ip.SrcIP.String()
			sourcePort = int(udp.SrcPort)
			destinationIP = ip.DstIP.String()
			destinationPort = int(udp.DstPort)
		} else {
			src = ip.SrcIP.String()
			dst = ip.DstIP.String()
			proto = strconv.Itoa(int(ip.Protocol))
			sourceIP = ip.SrcIP.String()
			destinationIP = ip.DstIP.String()
		}
	}

	return src, dst, proto, sourceIP, destinationIP, sourcePort, destinationPort
}

func mapPrefixToAction(prefix string) string {
	pl := strings.ToLower(prefix)

	switch {
	case strings.Contains(pl, "redirect"):
		return actionRedirected
	case strings.Contains(pl, "block") || strings.Contains(pl, "blocked"):
		return "BLOCKED"
	case strings.Contains(pl, "allow") || strings.Contains(pl, "allowed"):
		return "ALLOWED"
	default:
		return ""
	}
}

func buildLogFields(
	src, dst, proto, sourceIP, destinationIP, flowID string, sourcePort, destinationPort, payloadLen int,
) []any {
	now := time.Now().UTC().Format(time.RFC3339Nano)

	fields := []any{
		"time", now,
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

func processActionEvent(
	lg *slog.Logger,
	action, flowID string,
	src, dst, proto, sourceIP, destinationIP string,
	sourcePort, destinationPort, payloadLen int,
) {
	// If we have a recent synthetic for this flow, suppress kernel nflog REDIRECTED to avoid duplicates
	if action == actionRedirected && flowID != "" && filter.IsSyntheticRecent(flowID) {
		return // handled, skip logging
	}

	fields := buildLogFields(src, dst, proto, sourceIP, destinationIP, flowID, sourcePort, destinationPort, payloadLen)
	fields = append(fields, "action", action)

	// Level policy: REDIRECTED at DEBUG, ALLOWED/BLOCKED at INFO
	if action == actionRedirected {
		lg.Debug("nflog.event", fields...)
	} else {
		lg.Info("nflog.event", fields...)
	}
}

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

		src, dst, proto, sourceIP, destinationIP, sourcePort, destinationPort := parsePacketInfo(*attrs.Payload)

		if src == "" && dst == "" {
			// Unsupported network layer
			return 0
		}

		action := mapPrefixToAction(prefix)

		// Compute flow id
		flowID := ""
		if sourceIP != "" && destinationIP != "" {
			flowID = filter.FlowID(sourceIP, sourcePort, destinationIP, destinationPort, proto)
		}

		if action != "" {
			processActionEvent(
				lg, action, flowID,
				src, dst, proto, sourceIP, destinationIP,
				sourcePort, destinationPort, payloadLen,
			)

			return 0
		}

		// Minimal debug for non-action packets (will include hostname/component from lg context)
		lg.Debug("nflog.packet", "prefix", prefix, "protocol", proto, "src", src, "dst", dst, "payload_len", payloadLen)

		return 0
	}
}

// StreamNfLogWithLogger streams netfilter log events using the provided logger.
//
//nolint:cyclop,funlen,wrapcheck // Complexity and length from retry loops and context handling is acceptable
func StreamNfLogWithLogger(ctx context.Context, lg *slog.Logger) error {
	dfltBuf, dfltQ := parseNflogConfig()
	lg = setupLogger(lg)

	config := nflog.Config{
		Group:    0,
		Copymode: nflog.CopyPacket,
		Bufsize:  dfltBuf,
		QThresh:  dfltQ,
	}

	// Error handler that logs but continues
	errFunc := func(e error) int {
		lg.Warn("nflog.error", "err", e.Error())

		return 0 // Return 0 to keep receiving messages
	}

	for {
		// Check if context is cancelled before attempting operations
		select {
		case <-ctx.Done():
			lg.Info("nflog.shutdown", "reason", "context_cancelled")

			return ctx.Err()
		default:
		}

		nf, err := nflog.Open(&config)
		if err != nil {
			lg.Warn("nflog.open_failed", "err", err.Error())

			// Sleep with context awareness before retrying
			select {
			case <-ctx.Done():
				lg.Info("nflog.shutdown", "reason", "context_cancelled")

				return ctx.Err()
			case <-time.After(5 * time.Second):
			}

			continue
		}

		err = nf.RegisterWithErrorFunc(ctx, createNflogHook(lg), errFunc)

		// Close the nflog handle after registration returns (whether success or error)
		cerr := nf.Close()
		if cerr != nil {
			lg.Warn("nflog.close_failed", "err", cerr.Error())
		}

		if err != nil {
			lg.Warn("nflog.register_failed", "err", err.Error())

			// Sleep with context awareness before retrying
			select {
			case <-ctx.Done():
				lg.Info("nflog.shutdown", "reason", "context_cancelled")

				return ctx.Err()
			case <-time.After(5 * time.Second):
			}

			continue
		}

		// RegisterWithErrorFunc returned without error, likely due to context cancellation
		lg.Info("nflog.stopped", "reason", "register_returned")

		// Check if context was cancelled
		select {
		case <-ctx.Done():
			lg.Info("nflog.shutdown", "reason", "context_cancelled")

			return ctx.Err()
		default:
			// Connection dropped but context not cancelled - retry after delay
			lg.Warn("nflog.connection_lost", "action", "retrying")
			time.Sleep(5 * time.Second)
		}
	}
}
