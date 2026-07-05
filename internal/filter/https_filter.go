package filter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/safeio"
)

// Serve443 starts the TLS HTTPS filter.
func Serve443(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":8443"
	}

	opts.Denylist = NormalizePatterns(opts.Denylist)
	opts.denyMatcher = newMatcher(opts.Denylist)

	return serveTCP(ctx, opts.ListenAddr, opts.Logger, handle, newMatcher(allowlist), opts, "https")
}

// handle processes an individual TLS connection for HTTPS filtering.
func handle(conn net.Conn, allowlist *hostMatcher, opts Options) error {
	defer safeio.CloseWithErr(nil, conn)

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	// 1) Extract SNI from ClientHello
	sni, buf := extractSNIFromConnection(conn, opts)

	// 2) Apply policy
	permitted := hostPermittedBy(sni, allowlist, opts)
	if opts.Logger != nil {
		opts.Logger.Debug("https.allowlist_check", "sni", sni, "allowed", permitted)
	}

	wasAudited := audited(permitted, opts)

	if wasAudited {
		logAuditedHTTPS(conn, tc, sni, opts)
	} else if !permitted {
		handleBlockedHTTPS(conn, tc, sni, opts)

		return nil
	}

	maybeLearnHostBy(sni, allowlist, opts)

	// 3) Handle allowed HTTPS connection (audited flows already logged their verdict)
	return handleAllowedHTTPS(conn, tc, buf, sni, opts, !wasAudited)
}

// extractSNIFromConnection extracts SNI from TLS ClientHello.
func extractSNIFromConnection(conn net.Conn, opts Options) (string, *bytes.Buffer) {
	_ = conn.SetReadDeadline(time.Now().Add(connectionReadTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	rawSNI, buf, err := peekClientHello(conn)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Debug("https.peek_failed",
				"err", err.Error(),
				"src", conn.RemoteAddr().String(),
			)
		}

		// Return empty SNI with whatever bytes were consumed: under default-deny
		// handle() falls through to handleBlockedHTTPS, under default-allow or
		// learning mode the buffered bytes let the connection still be forwarded.
		return "", buf
	}

	sni := strings.TrimSuffix(strings.ToLower(rawSNI), ".")

	// Validate and sanitize SNI
	sanitized, valid := sanitizeHostWithLogger(sni, opts.Logger, "https")
	if valid {
		sni = sanitized
	} else if sni != "" {
		// SNI was present but invalid - treat as blocked
		if opts.Logger != nil {
			opts.Logger.Debug("https.sni_invalid",
				"raw_sni", sni,
				"src", conn.RemoteAddr().String(),
			)
		}

		sni = "" // Treat invalid SNI as empty
	}

	// Emit synthetic event early if we have a valid SNI
	if opts.Logger != nil && sni != "" {
		// Get original destination for synthetic event
		if tc, ok := conn.(*net.TCPConn); ok {
			target, targetErr := originalDstTCP(tc)
			if targetErr == nil {
				_ = EmitSynthetic(opts.Logger, "https", conn, target)
			}
		}

		// Debug: Log SNI extraction
		opts.Logger.Debug("https.sni_extracted",
			"sni", sni,
			"src", conn.RemoteAddr().String(),
		)
	}

	return sni, buf
}

// handleBlockedHTTPS handles blocked HTTPS connections.
func handleBlockedHTTPS(conn net.Conn, tc *net.TCPConn, sni string, opts Options) {
	logBlockedHTTPS(conn, tc, sni, opts)

	if opts.DropWithRST {
		_ = tc.SetLinger(0)
	}
}

// logBlockedHTTPS logs blocked HTTPS attempts.
func logBlockedHTTPS(conn net.Conn, tc *net.TCPConn, sni string, opts Options) {
	reason, destIP, destPort := httpsViolationContext(conn, tc, sni, opts)
	logBlockedConnection(opts, componentHTTPS, reason, sni, conn, destIP, destPort)
}

// logAuditedHTTPS logs a would-be-blocked HTTPS attempt that audit mode lets through.
func logAuditedHTTPS(conn net.Conn, tc *net.TCPConn, sni string, opts Options) {
	reason, destIP, destPort := httpsViolationContext(conn, tc, sni, opts)
	logAuditedConnection(opts, componentHTTPS, reason, sni, conn, destIP, destPort)
}

func httpsViolationContext(conn net.Conn, tc *net.TCPConn, sni string, opts Options) (string, string, int) {
	reason := "not-allowlisted"
	if opts.DefaultAllow {
		reason = "denylisted"
	}

	if sni == "" {
		reason = "no-sni"
	}

	sourceIP, sourcePort := sourceAddr(conn)

	var destIP string

	var destPort int

	tgt, derr := originalDstTCP(tc)
	if derr == nil {
		// Only emit synthetic here for the no-SNI case; valid SNI connections
		// already had EmitSynthetic called in extractSNIFromConnection.
		if sni == "" {
			_ = EmitSynthetic(opts.Logger, "https", conn, tgt)
		}

		destIP, destPort = parseHostPort(tgt)
	} else if opts.Logger != nil {
		opts.Logger.Debug("https.orig_dst_unavailable_for_blocked",
			"err", derr.Error(),
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	}

	return reason, destIP, destPort
}

// handleAllowedHTTPS handles allowed HTTPS connections. logAllowed is false for
// audited flows, which already logged their AUDIT verdict.
func handleAllowedHTTPS(
	conn net.Conn, tc *net.TCPConn, buf *bytes.Buffer, sni string, opts Options, logAllowed bool,
) error {
	// Recover original destination
	target, err := originalDstTCP(tc)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Warn("https.orig_dst_error", "err", err.Error())
		}

		return err
	}

	// No SNI to learn from - record the destination IP instead
	if sni == "" {
		destIP, _ := parseHostPort(target)
		maybeLearnIP(destIP, opts)
	}

	// Log allowed connection
	if opts.Logger != nil && logAllowed {
		logAllowedConnection(opts, componentHTTPS, target, sni, conn)
	}

	// Connect and splice
	return connectAndSpliceHTTPS(conn, buf, target, opts)
}

// connectAndSpliceHTTPS connects to destination server and splices data.
func connectAndSpliceHTTPS(conn net.Conn, buf *bytes.Buffer, target string, opts Options) error {
	dstConn, err := newDialerFromOptions(opts).Dial("tcp", target)
	if err != nil {
		logdstConnDialError(opts, componentHTTPS, conn, target, err)

		return fmt.Errorf("dial dstConn %s: %w", target, err)
	}

	defer func() { _ = dstConn.Close() }()

	if opts.Logger != nil {
		opts.Logger.Debug("https.splice_start",
			"target", target,
			"buffered_bytes", buf.Len(),
			"src", conn.RemoteAddr().String(),
		)
	}

	setConnTimeouts(conn, dstConn, opts)
	bidirectionalCopy(conn, dstConn, buf)

	return nil
}

// peekClientHello extracts the SNI from a TLS ClientHello while preserving the
// data. The buffer is returned even on error so consumed bytes can still be
// forwarded. Parsing lives in clienthello.go.
func peekClientHello(reader io.Reader) (string, *bytes.Buffer, error) {
	buf := new(bytes.Buffer)

	sni, err := readClientHelloSNI(io.TeeReader(reader, buf))
	if err != nil {
		return "", buf, err
	}

	return sni, buf, nil
}
