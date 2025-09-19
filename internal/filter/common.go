// Package filter provides common network filtering utilities including domain validation,
// connection handling, and synthetic event emission for network flow tracking.
package filter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/idna"
)

const (
	actionRedirected = "REDIRECTED"
	socketMarkValue  = 0x1 // mark value to set on redirected packets
	defaultTTL       = 60  // default TTL for DNS responses in seconds
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

const soOriginalDst = 80 // from linux/netfilter_ipv4.h

// originalDstTCP returns "ip:port" that the app originally dialled (before REDIRECT).
func originalDstTCP(conn *net.TCPConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("syscallconn: %w", err)
	}

	var out string

	var ctrlErr error

	err = raw.Control(func(fd uintptr) {
		var buffer [128]byte

		bufferLen := uint32(len(buffer))

		// getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &buffer[0], &bufferLen)
		_, _, syscallErr := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&buffer[0])), // #nosec G103
			uintptr(unsafe.Pointer(&bufferLen)), // #nosec G103
			0)
		if syscallErr != 0 {
			ctrlErr = syscallErr

			return
		}

		if bufferLen < 8 {
			ctrlErr = syscall.EINVAL

			return
		}

		port := int(binary.BigEndian.Uint16(buffer[2:4]))
		ip := net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7]).String()
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
