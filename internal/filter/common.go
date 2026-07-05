//go:build linux

// Package filter provides network filtering utilities.
package filter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/g0lab/g0efilter/internal/actions"
	"github.com/g0lab/g0efilter/internal/netutil"
	"github.com/g0lab/g0efilter/internal/policy"
	"github.com/g0lab/g0efilter/internal/procinfo"
	"golang.org/x/net/idna"
	"golang.org/x/sys/unix"
)

const (
	defaultTTL            = 60              // DNS response TTL in seconds
	connectionReadTimeout = 5 * time.Second // Timeout for initial connection reads

	// Component names for logging.
	componentHTTPS = "https"
	componentHTTP  = "http"
)

var (
	errListenAddrEmpty = errors.New("listenAddr cannot be empty")
)

// Options contains configuration for network filtering.
type Options struct {
	ListenAddr  string
	DialTimeout int // ms
	IdleTimeout int // ms
	DropWithRST bool
	Logger      *slog.Logger

	// DefaultAllow inverts the policy stance: traffic passes unless it matches
	// Denylist, with the allowlist acting as an explicit override.
	DefaultAllow bool
	Denylist     []string

	// LearningMode never blocks; hosts/IPs not already covered by the allowlist
	// are reported through OnLearn so they can be recorded in the policy.
	LearningMode bool
	OnLearn      func(kind, value string) // kind is "domain" or "ip"

	// OnResolved receives the A/AAAA addresses from each allowed DNS answer
	// (dns-strict mode) so they can be pushed into the kernel's resolved set
	// before the response reaches the client.
	OnResolved func(ips []string, ttl uint32)

	// AuditMode is dry-run enforcement: traffic that would be blocked is logged
	// with the AUDIT action and allowed through, so a policy's impact can be
	// previewed before enforcing it.
	AuditMode bool

	// ProcInfo, when set, resolves the client process behind each logged flow
	// (requires a shared PID namespace). Lookups run only in the logging path.
	ProcInfo procinfo.Provider

	// DNSHardening enables anti-exfil checks in the DNS proxy: qname/label length
	// caps, NULL/oversized-TXT response rejection, and per-source rate limiting.
	// Under audit/learning mode violations are logged but not blocked (except the
	// rate limit, which protects the proxy itself).
	DNSHardening bool

	// DNSRateQPS/DNSRateBurst override the per-source DNS hardening bucket.
	DNSRateQPS   int
	DNSRateBurst int

	// denyMatcher avoids rebuilding Denylist matching state per connection.
	denyMatcher *hostMatcher
}

// procFields returns process-attribution log fields for a flow, degrading to
// process_name=unknown when the socket or PID cannot be resolved.
func procFields(opts Options, sourceIP string, sourcePort int, proto string) []any {
	if opts.ProcInfo == nil {
		return nil
	}

	info, ok := opts.ProcInfo.Lookup(sourceIP, sourcePort, proto)
	if !ok {
		return []any{"process_name", unknownValue}
	}

	return []any{
		"pid", info.PID,
		"process_name", info.Name,
		"cmdline", info.Cmdline,
		"executable", info.Executable,
	}
}

// audited reports whether a non-permitted host should pass anyway under audit mode.
func audited(permitted bool, opts Options) bool {
	return !permitted && opts.AuditMode
}

// normalizeDomain converts a domain to lowercase ASCII form. Regex patterns pass through untouched.
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if policy.IsRegexPattern(domain) {
		return domain
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "*" {
		return domain
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return domain
	}

	return ascii
}

// NormalizePatterns pre-normalizes a list of domain patterns for use with allowedHost.
func NormalizePatterns(patterns []string) []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = normalizeDomain(p)
	}

	return out
}

// regexCache holds compiled /regex/ and wildcard patterns. Patterns come from the
// validated policy file, so the cache is bounded by policy size. Regex keys start
// with '/' and wildcard keys don't, so the two kinds cannot collide.
var regexCache sync.Map //nolint:gochecknoglobals

func cachedCompile(pattern string, compile func(string) (*regexp.Regexp, error)) *regexp.Regexp {
	if cached, ok := regexCache.Load(pattern); ok {
		re, _ := cached.(*regexp.Regexp)

		return re
	}

	re, err := compile(pattern)
	if err != nil {
		re = nil
	}

	regexCache.Store(pattern, re)

	return re
}

// hostMatcher keeps exact matches O(1) and scans wildcard/regex patterns.
type hostMatcher struct {
	exact    map[string]struct{}
	patterns []string
}

// newMatcher normalizes patterns and splits exact entries from wildcard/regex ones.
func newMatcher(patterns []string) *hostMatcher {
	m := &hostMatcher{exact: make(map[string]struct{}, len(patterns)), patterns: nil}

	for _, p := range patterns {
		p = normalizeDomain(p)
		if strings.Contains(p, "*") || policy.IsRegexPattern(p) {
			m.patterns = append(m.patterns, p)
		} else {
			m.exact[p] = struct{}{}
		}
	}

	return m
}

// allows checks if a host matches the allowlist.
func (m *hostMatcher) allows(host string) bool {
	host = normalizeDomain(host)
	if _, ok := m.exact[host]; ok {
		return true
	}

	for _, pattern := range m.patterns {
		if matchPattern(host, pattern) {
			return true
		}
	}

	return false
}

// allowedHost checks if a host matches allowlist patterns. Hot paths hold a
// pre-built hostMatcher instead; this form exists for one-off checks and tests.
func allowedHost(host string, allowlist []string) bool {
	return newMatcher(allowlist).allows(host)
}

// matchPattern matches a normalized host against one exact, wildcard, or /regex/ pattern.
func matchPattern(host, pattern string) bool {
	if pattern == "*" {
		return true
	}

	switch {
	case policy.IsRegexPattern(pattern):
		re := cachedCompile(pattern, policy.CompileDomainPattern)

		return re != nil && re.MatchString(host)
	case strings.HasPrefix(pattern, "*.") && !strings.Contains(pattern[2:], "*"):
		suffix := pattern[1:] // e.g. ".google.com"

		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	case strings.Contains(pattern, "*"):
		// Mid-name wildcards, e.g. sub.*.sub.domain.com
		re := cachedCompile(pattern, policy.CompileWildcardPattern)

		return re != nil && re.MatchString(host)
	default:
		return host == pattern
	}
}

// hostPermittedBy applies learning/default-allow/default-deny policy for a host.
func hostPermittedBy(host string, allow *hostMatcher, opts Options) bool {
	if opts.LearningMode {
		return true
	}

	if !opts.DefaultAllow {
		return host != "" && allow.allows(host)
	}

	if host == "" || allow.allows(host) {
		return true
	}

	deny := opts.denyMatcher
	if deny == nil {
		deny = newMatcher(opts.Denylist)
	}

	return !deny.allows(host)
}

// hostPermitted is the []string form of hostPermittedBy, for one-off checks and tests.
func hostPermitted(host string, allowlist []string, opts Options) bool {
	return hostPermittedBy(host, newMatcher(allowlist), opts)
}

// maybeLearnHostBy reports a host to the learning callback when it is not already allowlisted.
func maybeLearnHostBy(host string, allow *hostMatcher, opts Options) {
	if !opts.LearningMode || opts.OnLearn == nil || host == "" {
		return
	}

	if !allow.allows(host) {
		opts.OnLearn("domain", host)
	}
}

// maybeLearnHost is the []string form of maybeLearnHostBy, for one-off checks and tests.
func maybeLearnHost(host string, allowlist []string, opts Options) {
	maybeLearnHostBy(host, newMatcher(allowlist), opts)
}

// maybeLearnIP reports a destination IP to the learning callback (used when no
// domain identifier is available for the connection).
func maybeLearnIP(destIP string, opts Options) {
	if !opts.LearningMode || opts.OnLearn == nil || destIP == "" {
		return
	}

	opts.OnLearn("ip", destIP)
}

// newDialerFromOptions creates a network dialer with the timeout from Options and SO_MARK set to bypass iptables.
func newDialerFromOptions(opts Options) *net.Dialer {
	return newMarkedDialer(time.Duration(opts.DialTimeout) * time.Millisecond)
}

// timeoutFromOptions returns the dial timeout from Options, or defaultTimeout if not configured.
func timeoutFromOptions(opts Options, defaultTimeout time.Duration) time.Duration {
	if opts.DialTimeout <= 0 {
		return defaultTimeout
	}

	return time.Duration(opts.DialTimeout) * time.Millisecond
}

// newMarkedDialer creates a network dialer with SO_MARK set to bypass iptables REDIRECT rules.
func newMarkedDialer(dialTimeout time.Duration) *net.Dialer {
	return netutil.MarkedDialer(dialTimeout)
}

// setConnTimeouts applies idle timeout deadlines to both client and backend connections if configured.
func setConnTimeouts(conn net.Conn, backend net.Conn, opts Options) {
	if opts.IdleTimeout > 0 {
		timeout := time.Duration(opts.IdleTimeout) * time.Millisecond
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_ = backend.SetDeadline(time.Now().Add(timeout))
	}
}

// bidirectionalCopy copies data in both directions between connections, using zero-copy splice when possible.
func bidirectionalCopy(conn net.Conn, backend net.Conn, reader io.Reader) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		// Check if we can use the splice optimization (reader is *bytes.Buffer)
		if buf, ok := reader.(*bytes.Buffer); ok {
			// Copy peeked bytes first
			_, _ = io.Copy(backend, buf)
			// Then copy rest directly from conn to enable splice(2) on Linux
			_, _ = io.Copy(backend, conn)
		} else {
			// For other reader types (e.g., bufio.Reader), use standard copy
			_, _ = io.Copy(backend, reader)
		}

		if btc, ok := backend.(*net.TCPConn); ok {
			_ = btc.CloseWrite()
		}

		wg.Done()
	}()

	go func() {
		_, _ = io.Copy(conn, backend)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}

		wg.Done()
	}()

	wg.Wait()
}

// bidirectionalCopyWithBufferedReader copies data in both directions, flushing buffered data then using splice.
func bidirectionalCopyWithBufferedReader(conn net.Conn, backend net.Conn, br *bufio.Reader) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		// First, copy any data already buffered by bufio.Reader
		if br.Buffered() > 0 {
			buffered := make([]byte, br.Buffered())
			_, _ = io.ReadFull(br, buffered)
			_, _ = backend.Write(buffered)
		}
		// Then copy rest directly from conn to enable splice(2) on Linux
		_, _ = io.Copy(backend, conn)

		if btc, ok := backend.(*net.TCPConn); ok {
			_ = btc.CloseWrite()
		}

		wg.Done()
	}()

	go func() {
		_, _ = io.Copy(conn, backend)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}

		wg.Done()
	}()

	wg.Wait()
}

const (
	soOriginalDst   = 80 // from linux/netfilter_ipv4.h (SO_ORIGINAL_DST)
	soOriginalDstV6 = 80 // from linux/netfilter_ipv6.h (IP6T_SO_ORIGINAL_DST)
)

// originalDstTCP retrieves the original destination address before iptables REDIRECT using SO_ORIGINAL_DST.
// Supports both IPv4 (AF_INET) and IPv6 (AF_INET6) connections.
func originalDstTCP(conn *net.TCPConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("syscallconn: %w", err)
	}

	var (
		out     string
		ctrlErr error
	)

	err = raw.Control(func(fd uintptr) {
		// Try IPv4 first
		out, ctrlErr = getOriginalDstV4(fd)
		if ctrlErr == nil {
			return
		}

		// Fall back to IPv6
		out, ctrlErr = getOriginalDstV6(fd)
	})
	if err != nil {
		return "", fmt.Errorf("raw.Control failed: %w", err)
	}

	if ctrlErr != nil {
		return "", fmt.Errorf("getsockopt failed: %w", ctrlErr)
	}

	return out, nil
}

// getsockoptDst performs a SYS_GETSOCKOPT syscall to retrieve a raw socket address option.
func getsockoptDst(fd, level, opt uintptr, p unsafe.Pointer, optlen *uint32) error { // #nosec G103
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		fd,
		level,
		opt,
		uintptr(p),                      // #nosec G103
		uintptr(unsafe.Pointer(optlen)), // #nosec G103
		0)
	if errno != 0 {
		return errno
	}

	return nil
}

// buildHostPort converts raw address bytes and a network-byte-order port into a host:port string.
func buildHostPort(addrBytes []byte, port uint16) string {
	p := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&port))[:])) // #nosec G103

	return net.JoinHostPort(net.IP(addrBytes).String(), strconv.Itoa(p))
}

// getOriginalDstV4 retrieves the original IPv4 destination via SO_ORIGINAL_DST.
func getOriginalDstV4(fd uintptr) (string, error) {
	var sa unix.RawSockaddrInet4

	optlen := uint32(unsafe.Sizeof(sa))

	err := getsockoptDst(fd, uintptr(unix.SOL_IP), uintptr(soOriginalDst), unsafe.Pointer(&sa), &optlen) // #nosec G103
	if err != nil {
		return "", err
	}

	if optlen < uint32(unsafe.Sizeof(sa)) {
		return "", syscall.EINVAL
	}

	if sa.Family != unix.AF_INET {
		return "", syscall.EAFNOSUPPORT
	}

	return buildHostPort(sa.Addr[:], sa.Port), nil
}

// getOriginalDstV6 retrieves the original IPv6 destination via IP6T_SO_ORIGINAL_DST.
func getOriginalDstV6(fd uintptr) (string, error) {
	var sa unix.RawSockaddrInet6

	optlen := uint32(unsafe.Sizeof(sa))

	err := getsockoptDst(fd, uintptr(unix.SOL_IPV6), uintptr(soOriginalDstV6), unsafe.Pointer(&sa), &optlen) // #nosec G103
	if err != nil {
		return "", err
	}

	if optlen < uint32(unsafe.Sizeof(sa)) {
		return "", syscall.EINVAL
	}

	if sa.Family != unix.AF_INET6 {
		return "", syscall.EAFNOSUPPORT
	}

	return buildHostPort(sa.Addr[:], sa.Port), nil
}

// parseHostPort splits a "host:port" string into host and port, returning the input as host and 0 on error.
func parseHostPort(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}

	portInt, _ := strconv.Atoi(portStr)

	return host, portInt
}

// sourceAddr extracts the remote client's IP address and port from a connection.
func sourceAddr(conn net.Conn) (string, int) {
	if conn == nil || conn.RemoteAddr() == nil {
		return "", 0
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		portInt, _ := strconv.Atoi(port)

		return host, portInt
	}

	return conn.RemoteAddr().String(), 0
}

// EmitSynthetic emits a synthetic nflog event for a TCP redirect and marks the flow to suppress duplicates.
func EmitSynthetic(logger *slog.Logger, component string, conn net.Conn, target string) string {
	if logger == nil || target == "" {
		return ""
	}

	destIP, destPort := parseHostPort(target)
	sourceIP, sourcePort := sourceAddr(conn)

	flowID := actions.FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")
	logger.Debug("nflog.synthetic",
		"component", component,
		"action", actions.ActionRedirected,
		"protocol", "TCP",
		"prefix", "redirected",
		"source_ip", sourceIP,
		"source_port", sourcePort,
		"destination_ip", destIP,
		"destination_port", destPort,
		"src", sourceIP+":"+strconv.Itoa(sourcePort),
		"dst", destIP+":"+strconv.Itoa(destPort),
		"flow_id", flowID,
	)
	actions.MarkSynthetic(flowID)

	return flowID
}

// EmitSyntheticUDP emits a synthetic nflog event for a UDP redirect (DNS) and marks the flow to suppress duplicates.
func EmitSyntheticUDP(logger *slog.Logger, component, sourceIP string, sourcePort int, dst string) string {
	if logger == nil || dst == "" {
		return ""
	}

	destIP, destPort := parseHostPort(dst)
	flowID := actions.FlowID(sourceIP, sourcePort, destIP, destPort, "udp")
	logger.Debug("nflog.synthetic",
		"component", component,
		"action", actions.ActionRedirected,
		"protocol", "UDP",
		"prefix", "dns_redirected",
		"source_ip", sourceIP,
		"source_port", sourcePort,
		"destination_ip", destIP,
		"destination_port", destPort,
		"src", sourceIP+":"+strconv.Itoa(sourcePort),
		"dst", dst,
		"flow_id", flowID,
	)
	actions.MarkSynthetic(flowID)

	return flowID
}

// serveTCP listens on a TCP address and handles each connection by calling the provided handler function.
func serveTCP(
	ctx context.Context,
	listenAddr string,
	logger *slog.Logger,
	handler func(net.Conn, *hostMatcher, Options) error,
	allowlist *hostMatcher,
	opts Options,
	protocol string,
) error {
	if listenAddr == "" {
		return errListenAddrEmpty
	}

	lc := &net.ListenConfig{} //nolint:exhaustruct

	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		if logger != nil {
			logger.Error("tcp.listen_error", "addr", listenAddr, "err", err.Error())
		}

		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	if logger != nil {
		logger.Info(protocol+".filter_listen", "addr", listenAddr)
	}

	go func() {
		<-ctx.Done()

		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if logger != nil {
					logger.Warn("tcp.accept_error", "err", err.Error())
				}

				continue
			}
		}

		go func() { _ = handler(conn, allowlist, opts) }()
	}
}

// baseLogFields builds the shared decision-log fields for a component.
func baseLogFields(component, action, identifier, sourceIP string, sourcePort int) []any {
	var identifierKey string

	switch component {
	case componentHTTPS:
		identifierKey = componentHTTPS
	case componentHTTP:
		identifierKey = "host"
	default:
		identifierKey = "identifier"
	}

	const fieldCap = 24 // room for dest/flow/proc fields appended by callers

	fields := make([]any, 0, fieldCap)

	return append(fields,
		"component", component,
		"action", action,
		identifierKey, identifier,
		"source_ip", sourceIP,
		"source_port", sourcePort,
	)
}

// logAllowedConnection logs when a connection is allowed through the filter.
func logAllowedConnection(opts Options, component, target, identifier string, conn net.Conn) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)
	flowID := actions.FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")

	fields := baseLogFields(component, actions.ActionAllowed, identifier, sourceIP, sourcePort)
	fields = append(fields,
		"destination_ip", destIP,
		"destination_port", destPort,
		"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
		"flow_id", flowID,
	)
	fields = append(fields, procFields(opts, sourceIP, sourcePort, "tcp")...)

	opts.Logger.Info(component+".allowed", fields...)
}

// logBlockedConnection logs when a connection is blocked by the filter.
func logBlockedConnection(
	opts Options, component, reason, identifier string, conn net.Conn, destIP string, destPort int,
) {
	logPolicyViolation(opts, component, actions.ActionBlocked, reason, identifier, conn, destIP, destPort)
}

// logAuditedConnection logs a would-be-blocked connection that audit mode let through.
func logAuditedConnection(
	opts Options, component, reason, identifier string, conn net.Conn, destIP string, destPort int,
) {
	logPolicyViolation(opts, component, actions.ActionAudit, reason, identifier, conn, destIP, destPort)
}

func logPolicyViolation(
	opts Options, component, action, reason, identifier string, conn net.Conn, destIP string, destPort int,
) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)

	fields := baseLogFields(component, action, identifier, sourceIP, sourcePort)
	fields = append(fields, "reason", reason)

	if destIP != "" {
		flowID := actions.FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")
		fields = append(fields,
			"destination_ip", destIP,
			"destination_port", destPort,
			"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
			"flow_id", flowID,
		)
	}

	fields = append(fields, procFields(opts, sourceIP, sourcePort, "tcp")...)

	opts.Logger.Warn(component+"."+strings.ToLower(action), fields...)
}

// logdstConnDialError logs when connecting to the destination target fails.
func logdstConnDialError(opts Options, component string, conn net.Conn, target string, err error) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)
	opts.Logger.Warn(component+".dst_conn_dial_error",
		"component", component,
		"destination_ip", destIP,
		"destination_port", destPort,
		"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
		"err", err.Error(),
		"source_ip", sourceIP,
		"source_port", sourcePort,
	)
}
