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

// Serve80 starts an HTTP Host-based egress filter.
func Serve80(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":8080" // typical HTTP redirect port
	}

	return serveTCP(ctx, opts.ListenAddr, opts.Logger, handleHTTP, allowlist, opts, "http")
}

// handleHTTP processes an individual HTTP connection for Host header filtering.
func handleHTTP(conn net.Conn, allowlist []string, opts Options) error {
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

	// Emit synthetic event early if we have a valid host
	if opts.Logger != nil && host != "" && err == nil {
		// Recover original destination for synthetic event
		target, targetErr := originalDstTCP(tc)
		if targetErr == nil {
			_ = EmitSynthetic(opts.Logger, "http", conn, target)
		}

		// Debug: Log host extraction
		opts.Logger.Debug("http.host_extracted",
			"host", host,
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	}

	allowed := allowedHost(host, allowlist)
	if opts.Logger != nil {
		opts.Logger.Debug("http.allowlist_check", "host", host, "allowed", allowed)
	}

	if err != nil || host == "" || !allowed {
		handleBlockedHTTP(conn, tc, host, err, sourceIP, sourcePort, opts)

		return nil
	}

	// Handle allowed host
	return handleAllowedHTTP(conn, tc, host, headBytes, br, opts)
}

// handleBlockedHTTP handles HTTP requests that are blocked.
func handleBlockedHTTP(
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

	logBlockedHTTP(conn, tc, host, parseErr, sourceIP, sourcePort, opts)

	if opts.DropWithRST {
		_ = tc.SetLinger(0)
	}
}

// logBlockedHTTP logs blocked host information.
func logBlockedHTTP(
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
		flowID := EmitSynthetic(opts.Logger, "http", conn, tgt)
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

// handleAllowedHTTP handles allowed HTTP requests.
func handleAllowedHTTP(
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

	// Log allowed connection
	if opts.Logger != nil {
		logAllowedConnection(opts, componentHTTP, target, host, conn)
	}

	// 3) Connect and splice
	backend, err := newDialerFromOptions(opts).Dial("tcp", target)
	if err != nil {
		logdstConnDialError(opts, componentHTTP, conn, target, err)

		return fmt.Errorf("dial backend: %w", err)
	}

	defer func() { _ = backend.Close() }()

	if opts.Logger != nil {
		opts.Logger.Debug("http.splice_start",
			"target", target,
			"host", host,
			"buffered_bytes", len(headBytes),
		)
	}

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

	// For splice optimization: if br has buffered data, copy it first,
	// then copy directly from conn to enable splice(2) on Linux
	bidirectionalCopyWithBufferedReader(conn, backend, br)

	return nil
}

// readHeadWithTextproto parses HTTP headers and returns normalized host and raw bytes.
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
