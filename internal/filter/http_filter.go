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

	opts.Denylist = NormalizePatterns(opts.Denylist)
	opts.denyMatcher = newMatcher(opts.Denylist)

	return serveTCP(ctx, opts.ListenAddr, opts.Logger, handleHTTP, newMatcher(allowlist), opts, "http")
}

// handleHTTP processes an individual HTTP connection for Host header filtering.
func handleHTTP(conn net.Conn, allowlist *hostMatcher, opts Options) error {
	var err error
	defer safeio.CloseWithErr(&err, conn)

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	host, headBytes, br, parseErr := parseAndValidateHTTP(conn, tc, opts)

	// A parse failure always yields an empty host, so hostPermitted covers it:
	// blocked under default-deny, forwarded under default-allow/learning.
	permitted := hostPermittedBy(host, allowlist, opts)
	if opts.Logger != nil {
		opts.Logger.Debug("http.allowlist_check", "host", host, "allowed", permitted)
	}

	sourceIP, sourcePort := sourceAddr(conn)
	wasAudited := audited(permitted, opts)

	if wasAudited {
		logAuditedHTTP(conn, tc, host, parseErr, sourceIP, sourcePort, opts)
	} else if !permitted {
		handleBlockedHTTP(conn, tc, host, parseErr, sourceIP, sourcePort, opts)

		return nil
	}

	maybeLearnHostBy(host, allowlist, opts)

	return handleAllowedHTTP(conn, tc, host, headBytes, br, opts, !wasAudited)
}

func parseAndValidateHTTP(conn net.Conn, tc *net.TCPConn, opts Options) (string, []byte, *bufio.Reader, error) {
	_ = conn.SetReadDeadline(time.Now().Add(connectionReadTimeout))
	br := bufio.NewReader(conn)
	host, headBytes, err := readHeadWithTextproto(br)
	_ = conn.SetReadDeadline(time.Time{})

	sourceIP, sourcePort := sourceAddr(conn)

	host = validateAndSanitizeHost(host, sourceIP, sourcePort, opts)

	if opts.Logger != nil && host != "" && err == nil {
		emitHTTPSyntheticEvent(conn, tc, host, sourceIP, sourcePort, opts)
	}

	return host, headBytes, br, err
}

// validateAndSanitizeHost validates the host and returns sanitized version or empty string.
func validateAndSanitizeHost(host, sourceIP string, sourcePort int, opts Options) string {
	sanitized, valid := sanitizeHostWithLogger(host, opts.Logger, "http")
	if valid {
		return sanitized
	}

	if host != "" && opts.Logger != nil {
		opts.Logger.Debug("http.host_invalid",
			"raw_host", host,
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	}

	return ""
}

func emitHTTPSyntheticEvent(conn net.Conn, tc *net.TCPConn, host, sourceIP string, sourcePort int, opts Options) {
	target, targetErr := originalDstTCP(tc)
	if targetErr == nil {
		_ = EmitSynthetic(opts.Logger, "http", conn, target)
	}

	opts.Logger.Debug("http.host_extracted",
		"host", host,
		"source_ip", sourceIP,
		"source_port", sourcePort,
	)
}

func handleBlockedHTTP(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	parseErr error,
	sourceIP string,
	sourcePort int,
	opts Options,
) {
	logBlockedHTTP(conn, tc, host, parseErr, sourceIP, sourcePort, opts)

	if opts.DropWithRST {
		_ = tc.SetLinger(0)
	}
}

func logBlockedHTTP(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	parseErr error,
	sourceIP string,
	sourcePort int,
	opts Options,
) {
	reason := httpViolationReason(host, parseErr, opts)

	// Try to recover original dst so we can compute flow_id and emit synthetic redirect
	destIP, destPort := getDestinationInfo(conn, tc, host, sourceIP, sourcePort, opts)

	// Emitting normalised fields for ingestion; include flow_id when available
	logBlockedConnection(opts, componentHTTP, reason, host, conn, destIP, destPort)
}

// logAuditedHTTP logs a would-be-blocked HTTP request that audit mode lets through.
func logAuditedHTTP(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	parseErr error,
	sourceIP string,
	sourcePort int,
	opts Options,
) {
	reason := httpViolationReason(host, parseErr, opts)
	destIP, destPort := getDestinationInfo(conn, tc, host, sourceIP, sourcePort, opts)
	logAuditedConnection(opts, componentHTTP, reason, host, conn, destIP, destPort)
}

func httpViolationReason(host string, parseErr error, opts Options) string {
	reason := "not-allowlisted"
	if opts.DefaultAllow {
		reason = "denylisted"
	}

	if parseErr != nil {
		reason = "parse-failed"
	}

	if host == "" {
		reason = "no-host"
	}

	return reason
}

func getDestinationInfo(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	sourceIP string,
	sourcePort int,
	opts Options,
) (string, int) {
	tgt, derr := originalDstTCP(tc)
	if derr == nil {
		// Only emit synthetic here when host is empty (no-Host case); valid host
		// connections already had EmitSynthetic called in emitHTTPSyntheticEvent.
		if host == "" {
			_ = EmitSynthetic(opts.Logger, "http", conn, tgt)
		}

		destIP, destPort := parseHostPort(tgt)

		return destIP, destPort
	}

	// optional: log original dst recovery failure at debug
	if opts.Logger != nil {
		opts.Logger.Debug("http.orig_dst_unavailable_for_blocked",
			"err", derr.Error(),
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	}

	return "", 0
}

// handleAllowedHTTP forwards a permitted connection. logAllowed is false for
// audited flows, which already logged their AUDIT verdict.
func handleAllowedHTTP(
	conn net.Conn,
	tc *net.TCPConn,
	host string,
	headBytes []byte,
	br *bufio.Reader,
	opts Options,
	logAllowed bool,
) error {
	target, err := originalDstTCP(tc)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Warn("http.orig_dst_error", "err", err.Error())
		}

		return err
	}

	// No Host header to learn from - record the destination IP instead
	if host == "" {
		destIP, _ := parseHostPort(target)
		maybeLearnIP(destIP, opts)
	}

	if opts.Logger != nil && logAllowed {
		logAllowedConnection(opts, componentHTTP, target, host, conn)
	}

	return connectAndSpliceHTTP(conn, host, target, headBytes, br, opts)
}

// connectAndSpliceHTTP dials the original destination, replays the parsed head, and splices.
func connectAndSpliceHTTP(
	conn net.Conn, host, target string, headBytes []byte, br *bufio.Reader, opts Options,
) error {
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

	if len(headBytes) > 0 {
		_, writeErr := backend.Write(headBytes)
		if writeErr != nil && opts.Logger != nil {
			opts.Logger.Debug("http.backend_head_write_error", "err", writeErr.Error())
		}
	}

	// For splice optimization: if br has buffered data, copy it first,
	// then copy directly from conn to enable splice(2) on Linux
	bidirectionalCopyWithBufferedReader(conn, backend, br)

	return nil
}

// readHeadWithTextproto parses HTTP headers and returns normalized host and raw bytes.
// Consumed bytes are returned even on parse error so the connection can still be
// forwarded under default-allow/learning mode.
func readHeadWithTextproto(br *bufio.Reader) (string, []byte, error) {
	var buf bytes.Buffer

	tr := io.TeeReader(br, &buf)
	tp := textproto.NewReader(bufio.NewReader(tr))

	_, err := tp.ReadLine()
	if err != nil {
		return "", buf.Bytes(), fmt.Errorf("read request line: %w", err)
	}

	mh, err := tp.ReadMIMEHeader()
	if err != nil {
		return "", buf.Bytes(), fmt.Errorf("read MIME header: %w", err)
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
