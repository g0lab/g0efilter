package filter

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/safeio"
)

// Serve80 starts an HTTP Host-based egress filter on opts.ListenAddr.
// Behaviour mirrors the SNI filter: allow/deny, original dst, SO_MARK, splice.
func Serve80(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":8080" // typical HTTP redirect port
	}

	return serveTCP(ctx, opts.ListenAddr, opts.Logger, handleHost, allowlist, opts)
}

func handleHost(conn net.Conn, allowlist []string, opts Options) error {
	var err error
	defer safeio.CloseWithErr(&err, conn)

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	// 1) Parse request line + headers via textproto; extract Host
	_ = conn.SetReadDeadline(time.Now().Add(connectionReadTimeout))
	br := bufio.NewReader(conn)
	host, headBytes, err := readHeadWithTextproto(br)
	_ = conn.SetReadDeadline(time.Time{})

	// Normalise remote client address
	sourceIP, sourcePort := sourceAddr(conn)

	if err != nil || host == "" || !allowedHost(host, allowlist) {
		handleBlockedHost(conn, tc, host, err, sourceIP, sourcePort, opts)

		return nil
	}

	// Handle allowed host
	return handleAllowedHost(conn, tc, host, headBytes, br, opts)
}

// handleBlockedHost handles HTTP requests that are blocked.
func handleBlockedHost(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	parseErr error,
	sourceIP string,
	sourcePort int,
	opts Options,
) {
	if opts.Logger == nil {
		return
	}

	logBlockedHost(conn, tc, host, parseErr, sourceIP, sourcePort, opts)

	if opts.DropWithRST {
		_ = tc.SetLinger(0)
	}
}

// logBlockedHost logs blocked host information.
func logBlockedHost(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	parseErr error,
	sourceIP string,
	sourcePort int,
	opts Options,
) {
	reason := "not-allowlisted"
	if parseErr != nil {
		reason = "parse-failed"
	}

	if host == "" {
		reason = "no-host"
	}

	// Try to recover original dst so we can compute flow_id and emit synthetic redirect
	_, destIP, destPort := getDestinationInfo(conn, tc, sourceIP, sourcePort, opts)

	// Emitting normalised fields for ingestion; include flow_id when available
	logBlockedConnection(opts, componentHTTP, reason, host, conn, destIP, destPort)
}

// getDestinationInfo recovers destination information for logging.
func getDestinationInfo(
	conn net.Conn,
	tc *net.TCPConn,
	sourceIP string,
	sourcePort int,
	opts Options,
) (string, string, int) {
	tgt, derr := originalDstTCP(tc)
	if derr == nil {
		flowID := EmitSynthetic(opts.Logger, "http", conn, tc, tgt)
		destIP, destPort := parseHostPort(tgt)

		return flowID, destIP, destPort
	}

	// optional: log original dst recovery failure at debug
	opts.Logger.Debug("http.orig_dst_unavailable_for_blocked",
		"err", derr.Error(),
		"source_ip", sourceIP,
		"source_port", sourcePort,
	)

	return "", "", 0
}

// handleAllowedHost handles HTTP requests that are allowed through.
func handleAllowedHost(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	headBytes []byte,
	br *bufio.Reader,
	opts Options,
) error {
	// 2) Recover original destination (ip:port) before REDIRECT
	target, err := originalDstTCP(tc)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Warn("http.orig_dst_error", "err", err.Error())
		}

		return err
	}

	// Emit a synthetic REDIRECTED event so we have an early producer timestamp
	if opts.Logger != nil {
		_ = EmitSynthetic(opts.Logger, "http", conn, tc, target)
		logAllowedHost(conn, target, host, opts)
	}

	// 3) Connect and splice
	backend, err := createHTTPDialer(opts).Dial("tcp", target)
	if err != nil {
		logBackendDialError(opts, componentHTTP, conn, target, err)

		return fmt.Errorf("dial backend: %w", err)
	}

	defer func() { _ = backend.Close() }()

	setConnTimeouts(conn, backend, opts)

	// Write collected header+body to the backend
	if len(headBytes) > 0 {
		_, writeErr := backend.Write(headBytes)
		if writeErr != nil {
			if opts.Logger != nil {
				opts.Logger.Debug("http.backend_head_write_error", "err", writeErr.Error())
			}
		}
	}

	bidirectionalCopy(conn, backend, br)

	return nil
}

// createHTTPDialer creates a dialer for HTTP backend connections.
func createHTTPDialer(opts Options) *net.Dialer {
	return newDialerFromOptions(opts)
}

// logHTTPBackendError logs HTTP backend connection errors.
// removed: use common.logBackendDialError

// logAllowedHost logs allowed HTTP connections.
func logAllowedHost(conn net.Conn, target, host string, opts Options) {
	logAllowedConnection(opts, componentHTTP, target, host, conn)
}

// readHeadWithTextproto parses the request line and MIME headers using textproto,
// returns normalised host (lowercase, trailing dot trimmed, port stripped for checks)
// and the raw bytes that were consumed (to replay to backend).
func readHeadWithTextproto(br *bufio.Reader) (string, []byte, error) {
	var buf bytes.Buffer

	tr := io.TeeReader(br, &buf)
	tp := textproto.NewReader(bufio.NewReader(tr))

	_, err := tp.ReadLine()
	if err != nil {
		return "", nil, fmt.Errorf("read request line: %w", err)
	}

	mh, err := tp.ReadMIMEHeader()
	if err != nil {
		return "", nil, fmt.Errorf("read MIME header: %w", err)
	}

	host := mh.Get("Host")
	if host != "" {
		// Strip port for allowlist checking
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}

		host = strings.TrimSuffix(strings.ToLower(host), ".")
	}

	return host, buf.Bytes(), nil
}
