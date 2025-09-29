//go:build linux

// Package filter provides common network filtering utilities including domain validation,
// connection handling, and synthetic event emission for network flow tracking.
package filter

import (
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
	bypassMark            = 0x1 // SO_MARK value to bypass nftables REDIRECT rules
	actionRedirected      = "REDIRECTED"
	defaultTTL            = 60              // default TTL for DNS responses in seconds
	connectionReadTimeout = 5 * time.Second // timeout for initial connection reads

	// Component names for logging.
	componentSNI  = "sni"
	componentHTTP = "http"
)

var errListenAddrEmpty = errors.New("listenAddr cannot be empty")

// Options contains configuration parameters for network filtering operations.
type Options struct {
	ListenAddr  string
	DialTimeout int // ms
	IdleTimeout int // ms
	DropWithRST bool
	Logger      *slog.Logger
}

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

// newDialerFromOptions creates a marked dialer using Options timeout in milliseconds.
func newDialerFromOptions(opts Options) *net.Dialer {
	return newMarkedDialer(time.Duration(opts.DialTimeout) * time.Millisecond)
}

// timeoutFromOptions converts Options.DialTimeout to time.Duration with default fallback.
func timeoutFromOptions(opts Options, defaultTimeout time.Duration) time.Duration {
	if opts.DialTimeout <= 0 {
		return defaultTimeout
	}

	return time.Duration(opts.DialTimeout) * time.Millisecond
}

// newMarkedDialer creates a net.Dialer with SO_MARK set to bypass iptables rules.
// This allows outbound connections to bypass the transparent proxy rules.
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

// setConnTimeouts sets idle timeouts if configured for both connections.
func setConnTimeouts(conn net.Conn, backend net.Conn, opts Options) {
	if opts.IdleTimeout > 0 {
		timeout := time.Duration(opts.IdleTimeout) * time.Millisecond
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_ = backend.SetDeadline(time.Now().Add(timeout))
	}
}

// bidirectionalCopy performs bidirectional data copying between connections.
func bidirectionalCopy(conn net.Conn, backend net.Conn, reader io.Reader) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		_, _ = io.Copy(backend, reader)
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

// originalDstTCP (IPv4 only) returns "ip:port" that the app originally dialled (before REDIRECT).
// Uses SO_ORIGINAL_DST via getsockopt() with proper type-safe sockaddr_in structure.
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

// FlowID returns a deterministic identifier for a network flow based on
// source IP/port, destination IP/port and protocol. It's suitable for
// correlating NFLOG records with in-app events.
func FlowID(sourceIP string, sourcePort int, destinationIP string, destinationPort int, proto string) string {
	hasher := fnv.New32a()
	// simple canonical representation
	_, _ = hasher.Write([]byte(sourceIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(sourcePort)))
	_, _ = hasher.Write([]byte("->"))
	_, _ = hasher.Write([]byte(destinationIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(destinationPort)))
	_, _ = hasher.Write([]byte("|"))

	// best-effort logging; ignore write errors explicitly
	err := func() error {
		_, writeErr := hasher.Write([]byte(strings.ToUpper(proto)))
		if writeErr != nil {
			return fmt.Errorf("hash write failed: %w", writeErr)
		}

		return nil
	}()
	_ = err

	return strconv.FormatUint(uint64(hasher.Sum32()), 16)
}

// --- small helpers to remove duplication ---

// parseHostPort returns host and port from a "host:port" string.
// On error, returns the input string as host and 0 as port.
func parseHostPort(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}

	portInt, _ := strconv.Atoi(portStr)

	return host, portInt
}

// sourceAddr extracts the remote client's IP and port, tolerant of non-standard forms.
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

// MarkSynthetic records that a synthetic event for flowID was emitted now.
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

// IsSyntheticRecent returns true if a synthetic event for flowID was recorded within suppressWindow.
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

// EmitSynthetic recovers client and destination fields and emits a synthetic nflog.synthetic
// log via the provided logger, marks the flow for suppression, and returns the computed flowID.
// component is e.g. "http" or "sni"; dst is the original destination value (ip:port).
func EmitSynthetic(logger *slog.Logger, component string, conn net.Conn, _ *net.TCPConn, target string) string {
	if logger == nil || target == "" {
		return ""
	}

	destIP, destPort := parseHostPort(target)
	sourceIP, sourcePort := sourceAddr(conn)

	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")
	logger.Debug("nflog.synthetic", // was Info
		"time", time.Now().UTC().Format(time.RFC3339Nano),
		"component", component,
		"action", actionRedirected,
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

// EmitSyntheticUDP helper to centralise UDP synthetic emission for DNS flows.
func EmitSyntheticUDP(logger *slog.Logger, component, sourceIP string, sourcePort int, dst string) string {
	if logger == nil || dst == "" {
		return ""
	}

	destIP, destPort := parseHostPort(dst)
	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "udp")
	logger.Debug("nflog.synthetic", // was Info
		"time", time.Now().UTC().Format(time.RFC3339Nano),
		"component", component,
		"action", actionRedirected,
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

// serveTCP is a shared function for TCP-based filters (HTTP Host, SNI).
// It handles listening, accepting connections, and calling the provided handler.
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
	// Use ListenConfig to allow context-aware shutdown. Suppress exhaustruct here.
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

// logAllowedConnection logs an allowed connection with common fields.
func logAllowedConnection(opts Options, component, target, identifier string, conn net.Conn) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)
	flowID := FlowID(sourceIP, sourcePort, destIP, destPort, "tcp")

	var identifierKey string

	switch component {
	case componentSNI:
		identifierKey = componentSNI
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

// logBlockedConnection logs a blocked connection with common fields.
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
	case componentSNI:
		identifierKey = componentSNI
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

// logBackendDialError logs backend dial/connect errors for TCP backends.
func logBackendDialError(opts Options, component string, conn net.Conn, target string, err error) {
	if opts.Logger == nil {
		return
	}

	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)
	opts.Logger.Warn(component+".backend_dial_error",
		"component", component,
		"destination_ip", destIP,
		"destination_port", destPort,
		"dst", net.JoinHostPort(destIP, strconv.Itoa(destPort)),
		"err", err.Error(),
		"source_ip", sourceIP,
		"source_port", sourcePort,
	)
}
