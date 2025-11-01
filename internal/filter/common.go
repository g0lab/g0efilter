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
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/idna"
	"golang.org/x/sys/unix"
)

const (
	bypassMark            = 0x1             // SO_MARK to bypass nftables REDIRECT
	defaultTTL            = 60              // DNS response TTL in seconds
	connectionReadTimeout = 5 * time.Second // Timeout for initial connection reads

	// ActionRedirected is logged when traffic is redirected.
	ActionRedirected = "REDIRECTED"

	// ModeHTTPS is the HTTPS-based filtering mode.
	ModeHTTPS = "https"
	// ModeDNS is the DNS-based filtering mode.
	ModeDNS = "dns"

	// Component names for logging.
	componentHTTPS = "https"
	componentHTTP  = "http"
)

var errListenAddrEmpty = errors.New("listenAddr cannot be empty")

// Options contains configuration for network filtering.
type Options struct {
	ListenAddr  string
	DialTimeout int // ms
	IdleTimeout int // ms
	DropWithRST bool
	Logger      *slog.Logger
}

// normalizeDomain converts a domain to lowercase ASCII form.
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(domain, ".")))
	if domain == "*" {
		return domain
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return domain
	}

	return ascii
}

// allowedHost checks if a host matches the allowlist patterns.
func allowedHost(host string, allowlist []string) bool {
	host = normalizeDomain(host)

	for _, pattern := range allowlist {
		normalizedPattern := normalizeDomain(pattern)

		if normalizedPattern == "*" {
			return true
		}

		if strings.HasPrefix(normalizedPattern, "*.") {
			suffix := normalizedPattern[1:] // e.g. ".google.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		} else if host == normalizedPattern {
			return true
		}
	}

	return false
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
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: func(_ string, _ string, rc syscall.RawConn) error {
			var serr error

			err := rc.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, bypassMark)
			})
			if err != nil {
				return fmt.Errorf("socket control error: %w", err)
			}

			if serr != nil {
				return fmt.Errorf("set socket mark: %w", serr)
			}

			return nil
		},
	}

	return dialer
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

const soOriginalDst = 80 // from linux/netfilter_ipv4.h

// originalDstTCP retrieves the original destination address before iptables REDIRECT using SO_ORIGINAL_DST.
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
		var sa unix.RawSockaddrInet4

		optlen := uint32(unsafe.Sizeof(sa))

		// getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &sa, &optlen)
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa)),     // #nosec G103
			uintptr(unsafe.Pointer(&optlen)), // #nosec G103
			0)
		if errno != 0 {
			ctrlErr = errno

			return
		}

		// Expect a full sockaddr_in (16 bytes on Linux)
		if optlen < uint32(unsafe.Sizeof(sa)) {
			ctrlErr = syscall.EINVAL

			return
		}

		// Validate address family
		if sa.Family != unix.AF_INET {
			ctrlErr = syscall.EAFNOSUPPORT

			return
		}

		// sin_port is network byte order (big-endian)
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])) // #nosec G103
		ip := net.IP(sa.Addr[:]).String()
		out = net.JoinHostPort(ip, strconv.Itoa(port))
	})
	if err != nil {
		return "", fmt.Errorf("raw.Control failed: %w", err)
	}

	if ctrlErr != nil {
		return "", fmt.Errorf("getsockopt failed: %w", ctrlErr)
	}

	return out, nil
}

// FlowID generates a deterministic hash identifier for a network flow using source, destination, and protocol.
func FlowID(sourceIP string, sourcePort int, destinationIP string, destinationPort int, proto string) string {
	hasher := fnv.New32a()
	// simple canonical representation - hash.Write never fails
	_, _ = hasher.Write([]byte(sourceIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(sourcePort)))
	_, _ = hasher.Write([]byte("->"))
	_, _ = hasher.Write([]byte(destinationIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(destinationPort)))
	_, _ = hasher.Write([]byte("|"))
	_, _ = hasher.Write([]byte(strings.ToUpper(proto)))

	return strconv.FormatUint(uint64(hasher.Sum32()), 16)
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

//nolint:gochecknoglobals
var (
	// recentSynthetic stores flow_id -> timestamp of last synthetic event to dedupe nflog events.
	recentSynthetic = struct {
		m     map[string]time.Time
		mutex sync.Mutex
	}{m: make(map[string]time.Time)}
)

// suppressWindow is how long to suppress kernel nflog events after seeing a synthetic redirect.
const suppressWindow = 5 * time.Second

// MarkSynthetic records that a synthetic log event was emitted for this flow to prevent duplicate nflog events.
func MarkSynthetic(flowID string) {
	if flowID == "" {
		return
	}

	recentSynthetic.mutex.Lock()
	defer recentSynthetic.mutex.Unlock()

	recentSynthetic.m[flowID] = time.Now()
	// prune old entries occasionally
	cutoff := time.Now().Add(-suppressWindow * 4)
	for k, v := range recentSynthetic.m {
		if v.Before(cutoff) {
			delete(recentSynthetic.m, k)
		}
	}
}

// IsSyntheticRecent returns true if a synthetic log was emitted for this flow within the suppress window.
func IsSyntheticRecent(flowID string) bool {
	if flowID == "" {
		return false
	}

	recentSynthetic.mutex.Lock()
	defer recentSynthetic.mutex.Unlock()

	if lastTime, ok := recentSynthetic.m[flowID]; ok {
		return time.Since(lastTime) <= suppressWindow
	}

	return false
}

// EmitSynthetic emits a synthetic nflog event for a TCP redirect and marks the flow to suppress duplicates.
func EmitSynthetic(logger *slog.Logger, component string, conn net.Conn, target string) string {
	if logger == nil || target == "" {
		return ""
	}

	destIP, destPort := parseHostPort(target)
	sourceIP, sourcePort := sourceAddr(conn)

	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")
	logger.Debug("nflog.synthetic",
		"time", time.Now().UTC().Format(time.RFC3339Nano),
		"component", component,
		"action", ActionRedirected,
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
	MarkSynthetic(flowID)

	return flowID
}

// EmitSyntheticUDP emits a synthetic nflog event for a UDP redirect (DNS) and marks the flow to suppress duplicates.
func EmitSyntheticUDP(logger *slog.Logger, component, sourceIP string, sourcePort int, dst string) string {
	if logger == nil || dst == "" {
		return ""
	}

	destIP, destPort := parseHostPort(dst)
	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "udp")
	logger.Debug("nflog.synthetic",
		"time", time.Now().UTC().Format(time.RFC3339Nano),
		"component", component,
		"action", ActionRedirected,
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
	MarkSynthetic(flowID)

	return flowID
}

// serveTCP listens on a TCP address and handles each connection by calling the provided handler function.
func serveTCP(
	ctx context.Context,
	listenAddr string,
	logger *slog.Logger,
	handler func(net.Conn, []string, Options) error,
	allowlist []string,
	opts Options,
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
		logger.Info("tcp.listen", "addr", listenAddr)
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

// logAllowedConnection logs when a connection is allowed through the filter.
func logAllowedConnection(opts Options, component, target, identifier string, conn net.Conn) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)
	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")

	var identifierKey string

	switch component {
	case componentHTTPS:
		identifierKey = componentHTTPS
	case componentHTTP:
		identifierKey = "host"
	default:
		identifierKey = "identifier"
	}

	opts.Logger.Info(component+".allowed",
		"component", component,
		"action", "ALLOWED",
		identifierKey, identifier,
		"source_ip", sourceIP,
		"source_port", sourcePort,
		"destination_ip", destIP,
		"destination_port", destPort,
		"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
		"flow_id", flowID,
	)
}

// logBlockedConnection logs when a connection is blocked by the filter.
func logBlockedConnection(
	opts Options, component, reason, identifier string, conn net.Conn, destIP string, destPort int,
) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")

	var identifierKey string

	switch component {
	case componentHTTPS:
		identifierKey = componentHTTPS
	case componentHTTP:
		identifierKey = "host"
	default:
		identifierKey = "identifier"
	}

	fields := []any{
		"time", time.Now().UTC().Format(time.RFC3339Nano),
		"component", component,
		"action", "BLOCKED",
		identifierKey, identifier,
		"reason", reason,
		"source_ip", sourceIP,
		"source_port", sourcePort,
		"flow_id", flowID,
	}

	if destIP != "" {
		fields = append(fields,
			"destination_ip", destIP,
			"destination_port", destPort,
			"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
		)
	}

	opts.Logger.Info(component+".blocked", fields...)
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
