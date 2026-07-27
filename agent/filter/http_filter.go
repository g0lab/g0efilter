package filter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/agent/safeio"
)

// Serve80 starts an HTTP Host-based egress filter.
func Serve80(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":65080"
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

	// Un-redirected connections to our own listener (e.g. the healthcheck) would
	// loop back through the proxy in audit/learning/default-allow modes.
	if isSelfConnection(conn, tc) {
		if opts.Logger != nil {
			opts.Logger.Debug("http.self_connection_dropped", "src", conn.RemoteAddr().String())
		}

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

	return handleAllowedHTTP(conn, tc, host, headBytes, br, allowlist, parseErr, opts, !wasAudited)
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
	allowlist *hostMatcher,
	parseErr error,
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

	return connectAndSpliceHTTP(conn, host, target, headBytes, br, allowlist, parseErr, opts)
}

// connectAndSpliceHTTP dials the original destination and forwards the connection.
func connectAndSpliceHTTP(
	conn net.Conn, host, target string, headBytes []byte, br *bufio.Reader,
	allowlist *hostMatcher, parseErr error, opts Options,
) error {
	if errors.Is(parseErr, errHTTPHeadTooLarge) {
		if opts.Logger != nil {
			opts.Logger.Debug("http.head_too_large", "host", host, "bytes", len(headBytes))
		}

		return nil
	}

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

	// Parse failed: we can't frame later requests, so replay the consumed bytes
	// and raw-splice (only reached under default-allow/learning).
	if parseErr != nil {
		if len(headBytes) > 0 {
			_, writeErr := backend.Write(headBytes)
			if writeErr != nil && opts.Logger != nil {
				opts.Logger.Debug("http.backend_head_write_error", "err", writeErr.Error())
			}
		}

		bidirectionalCopyWithBufferedReader(conn, backend, br)

		return nil
	}

	forwardHTTPRequests(conn, backend, headBytes, br, allowlist, target, opts)

	return nil
}

// forwardHTTPRequests re-authorises the Host of every request on a persistent
// connection so a keep-alive client cannot switch to an unpermitted authority
// after the first request.
func forwardHTTPRequests(
	conn net.Conn, backend net.Conn, headBytes []byte, br *bufio.Reader,
	allowlist *hostMatcher, target string, opts Options,
) {
	done := make(chan struct{})
	upgraded := make(chan bool, 1)

	go func() {
		defer close(done)

		relayResponses(conn, backend, upgraded)
		closeWrite(conn)
	}()

	defer func() {
		closeWrite(backend)

		<-done
	}()

	// The first request head was already consumed for the initial decision, so
	// prepend it to reconstruct the full client request stream.
	reqReader := bufio.NewReader(io.MultiReader(bytes.NewReader(headBytes), br))

	filterRequestStream(conn, backend, reqReader, br, allowlist, target, upgraded, opts)
}

// filterRequestStream relays each request on a persistent connection, applying
// policy to every authority after the first.
func filterRequestStream(
	conn net.Conn, backend net.Conn, reqReader, br *bufio.Reader,
	allowlist *hostMatcher, target string, upgraded <-chan bool, opts Options,
) {
	sourceIP, sourcePort := sourceAddr(conn)
	destIP, destPort := parseHostPort(target)

	first := true

	for {
		req, rawHead, err := readRawHTTPRequestHead(reqReader)
		if err != nil {
			return
		}

		host := validateAndSanitizeHost(normalizeHost(req.Host), sourceIP, sourcePort, opts)

		wasFirst := first

		// The first request was already authorised and logged by handleHTTP.
		if !wasFirst && !authoriseForwardedRequest(conn, host, allowlist, destIP, destPort, opts) {
			return
		}

		first = false

		_, err = io.Copy(backend, bytes.NewReader(rawHead))
		if err != nil {
			return
		}

		err = copyRawHTTPRequestBody(backend, reqReader, req)
		if err != nil {
			return
		}

		if !isHTTPUpgrade(req) {
			continue
		}

		if !tunnelUpgrade(wasFirst, reqReader, br, upgraded) {
			return
		}

		_, _ = io.Copy(backend, reqReader)

		return
	}
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// tunnelUpgrade reports whether an upgrade request may take the stream off HTTP.
// Splicing an upgrade the backend never accepted would hand the rest of the
// connection through unchecked.
func tunnelUpgrade(wasFirst bool, reqReader, br *bufio.Reader, upgraded <-chan bool) bool {
	// A genuine upgrade is the first request, with nothing pipelined behind it.
	if !wasFirst || reqReader.Buffered() > 0 || br.Buffered() > 0 {
		return false
	}

	return <-upgraded
}

// relayResponses copies the backend's stream to the client, reporting on upgraded
// whether the first final response was a 101. Only heads up to that verdict are
// parsed; the rest is copied off the bare conn so it stays splice-eligible.
func relayResponses(conn net.Conn, backend net.Conn, upgraded chan<- bool) {
	br := bufio.NewReader(backend)

	accepted := false

	// upgraded is buffered, so the verdict lands even if the request loop is gone.
	defer func() {
		upgraded <- accepted

		if n := br.Buffered(); n > 0 {
			_, err := io.CopyN(conn, br, int64(n))
			if err != nil {
				return
			}
		}

		_, _ = io.Copy(conn, backend)
	}()

	for {
		head, err := readRawHTTPHeadBytes(br)

		if len(head) > 0 {
			_, writeErr := conn.Write(head)
			if writeErr != nil {
				return
			}
		}

		if err != nil {
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(head)), nil)
		if err != nil {
			return
		}

		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusSwitchingProtocols {
			accepted = true

			return
		}

		// A 1xx other than 101 is interim: the final response is still to come.
		if resp.StatusCode >= http.StatusOK {
			return
		}
	}
}

func readRawHTTPRequestHead(br *bufio.Reader) (*http.Request, []byte, error) {
	head, err := readRawHTTPHeadBytes(br)
	if err != nil {
		return nil, head, err
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return nil, head, fmt.Errorf("parse HTTP request: %w", err)
	}

	return req, head, nil
}

// maxHTTPHeadBytes bounds a single request or response head. Without it a peer
// that never sends the terminating blank line grows the buffer until the
// connection deadline, which defaults to ten minutes.
const maxHTTPHeadBytes = 64 << 10

// readRawHTTPHeadBytes accumulates the head verbatim. ReadSlice rather than
// ReadString so a single endless header line is bounded too.
func readRawHTTPHeadBytes(br *bufio.Reader) ([]byte, error) {
	var head bytes.Buffer

	for {
		chunk, err := br.ReadSlice('\n')

		if head.Len()+len(chunk) > maxHTTPHeadBytes {
			return head.Bytes(), errHTTPHeadTooLarge
		}

		head.Write(chunk)

		// A partial line: the head is longer than bufio's buffer, not malformed.
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		if err != nil {
			return head.Bytes(), fmt.Errorf("read HTTP request head: %w", err)
		}

		if string(chunk) == "\r\n" || string(chunk) == "\n" {
			return head.Bytes(), nil
		}
	}
}

func copyRawHTTPRequestBody(dst io.Writer, src *bufio.Reader, req *http.Request) error {
	if slices.Contains(req.TransferEncoding, "chunked") {
		return copyRawChunkedBody(dst, src)
	}

	if req.ContentLength <= 0 {
		return nil
	}

	_, err := io.CopyN(dst, src, req.ContentLength)
	if err != nil {
		return fmt.Errorf("copy HTTP request body: %w", err)
	}

	return nil
}

func copyRawChunkedBody(dst io.Writer, src *bufio.Reader) error {
	for {
		line, err := copyRawLine(dst, src)
		if err != nil {
			return err
		}

		size, err := parseChunkSize(line)
		if err != nil {
			return err
		}

		if size == 0 {
			return copyRawTrailers(dst, src)
		}

		_, err = io.CopyN(dst, src, size)
		if err != nil {
			return fmt.Errorf("copy HTTP chunk: %w", err)
		}

		line, err = copyRawLine(dst, src)
		if err != nil {
			return err
		}

		if line != "\r\n" && line != "\n" {
			return errInvalidChunkTerminator
		}
	}
}

var (
	errInvalidChunkSize       = errors.New("invalid HTTP chunk size")
	errInvalidChunkTerminator = errors.New("invalid HTTP chunk terminator")
	errHTTPHeadTooLarge       = errors.New("HTTP head exceeds the maximum size")
)

func parseChunkSize(line string) (int64, error) {
	sizeText, _, _ := strings.Cut(strings.TrimSpace(line), ";")

	size, err := strconv.ParseInt(sizeText, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse HTTP chunk size: %w", err)
	}

	if size < 0 {
		return 0, errInvalidChunkSize
	}

	return size, nil
}

func copyRawTrailers(dst io.Writer, src *bufio.Reader) error {
	for {
		line, err := copyRawLine(dst, src)
		if err != nil {
			return err
		}

		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func copyRawLine(dst io.Writer, src *bufio.Reader) (string, error) {
	line, err := src.ReadString('\n')
	if len(line) > 0 {
		_, writeErr := io.WriteString(dst, line)
		if writeErr != nil {
			return line, fmt.Errorf("write raw HTTP line: %w", writeErr)
		}
	}

	if err != nil {
		return line, fmt.Errorf("read raw HTTP line: %w", err)
	}

	return line, nil
}

// authoriseForwardedRequest applies policy to a later request on a persistent
// connection. It returns false when forwarding must stop (blocked, not audit).
func authoriseForwardedRequest(
	conn net.Conn, host string, allowlist *hostMatcher, destIP string, destPort int, opts Options,
) bool {
	permitted := hostPermittedBy(host, allowlist, opts)
	reason := httpViolationReason(host, nil, opts)

	switch {
	case permitted:
		if opts.Logger != nil {
			logAllowedConnection(opts, componentHTTP, net.JoinHostPort(destIP, strconv.Itoa(destPort)), host, conn)
		}

		maybeLearnHostBy(host, allowlist, opts)
	case audited(permitted, opts):
		logAuditedConnection(opts, componentHTTP, reason, host, conn, destIP, destPort)
	default:
		logBlockedConnection(opts, componentHTTP, reason, host, conn, destIP, destPort)

		return false
	}

	return true
}

// isHTTPUpgrade reports whether a request switches the connection off HTTP/1.1
// (CONNECT tunnels or Connection: Upgrade, e.g. WebSocket).
func isHTTPUpgrade(req *http.Request) bool {
	if req.Method == http.MethodConnect {
		return true
	}

	for v := range strings.SplitSeq(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}

	return false
}

// readHeadWithTextproto parses HTTP headers and returns normalized host and raw bytes.
// Consumed bytes are returned even on parse error so the connection can still be
// forwarded under default-allow/learning mode.
func readHeadWithTextproto(br *bufio.Reader) (string, []byte, error) {
	head, err := readRawHTTPHeadBytes(br)
	if err != nil {
		return "", head, err
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(head)))

	_, err = tp.ReadLine()
	if err != nil {
		return "", head, fmt.Errorf("read request line: %w", err)
	}

	mh, err := tp.ReadMIMEHeader()
	if err != nil {
		return "", head, fmt.Errorf("read MIME header: %w", err)
	}

	return normalizeHost(mh.Get("Host")), head, nil
}

// normalizeHost strips any port, lowercases, and trims a trailing dot so the
// value can be matched against the allowlist.
func normalizeHost(host string) string {
	if host == "" {
		return ""
	}

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	return strings.TrimSuffix(strings.ToLower(host), ".")
}
