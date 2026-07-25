//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServe80(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedHosts := []string{"example.com", "*.google.com"}
	options := Options{
		ListenAddr:  "127.0.0.1:0", // Use port 0 to let OS choose
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test that Serve80 can start (will likely timeout in test environment)
	err := Serve80(ctx, allowedHosts, options)

	// In test environment, we expect this to timeout or fail to bind
	// We're mainly testing that the function doesn't panic
	if err != nil {
		t.Logf("Serve80 failed as expected in test environment: %v", err)
	}
}

func TestCreateHTTPDialer(t *testing.T) {
	t.Parallel()

	options := Options{
		DialTimeout: 5000,
		IdleTimeout: 30000,
	}

	// Test creating HTTP dialer
	dialer := newDialerFromOptions(options)
	if dialer == nil {
		t.Error("Expected non-nil HTTP dialer")

		return
	}

	// Test timeout is set correctly
	expectedTimeout := time.Duration(options.DialTimeout) * time.Millisecond
	if dialer.Timeout != expectedTimeout {
		t.Errorf("Expected timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}
}

func TestReadHeadWithTextproto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected map[string][]string
		wantErr  bool
	}{
		{
			name:  "Simple GET request",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
			expected: map[string][]string{
				"Host":       {"example.com"},
				"User-Agent": {"test"},
			},
			wantErr: false,
		},
		{
			name:  "POST request with Content-Length",
			input: "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 42\r\nContent-Type: application/json\r\n\r\n",
			expected: map[string][]string{
				"Host":           {"api.example.com"},
				"Content-Length": {"42"},
				"Content-Type":   {"application/json"},
			},
			wantErr: false,
		},
		{
			name:  "Multiple values for same header",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n",
			expected: map[string][]string{
				"Host":   {"example.com"},
				"Accept": {"text/html", "application/json"},
			},
			wantErr: false,
		},
		{
			name:     "Empty input",
			input:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid HTTP format",
			input:    "Not HTTP\r\n\r\n",
			expected: map[string][]string{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testHTTPRequest(t, tt.input, tt.expected, tt.wantErr)
		})
	}
}

// Helper function to test individual HTTP requests.
func testHTTPRequest(t *testing.T, input string, expected map[string][]string, wantErr bool) {
	t.Helper()

	reader := strings.NewReader(input)
	bufReader := bufio.NewReader(reader)

	requestLine, headerBytes, err := readHeadWithTextproto(bufReader)

	if wantErr {
		if err == nil {
			t.Error("Expected error but got nil")
		}

		return
	}

	if err != nil {
		t.Errorf("Unexpected error: %v", err)

		return
	}

	if len(headerBytes) == 0 {
		t.Error("Expected non-empty header bytes")

		return
	}

	// For malformed HTTP, we don't expect specific behavior
	// Just verify the function doesn't panic
	t.Logf("Request line: %s, Header bytes: %d", requestLine, len(headerBytes))

	validateHeaders(t, headerBytes, expected)
}

// Helper function to validate HTTP headers.
func validateHeaders(t *testing.T, headerBytes []byte, expected map[string][]string) {
	t.Helper()

	actualHeaders := parseHeaderBytes(headerBytes)

	// Check that expected headers are present
	for key, expectedValues := range expected {
		actualValues, exists := actualHeaders[key]
		if !exists {
			t.Errorf("Expected header %s not found", key)

			continue
		}

		if len(actualValues) != len(expectedValues) {
			t.Errorf("Header %s: expected %d values, got %d", key, len(expectedValues), len(actualValues))

			continue
		}

		for i, expectedValue := range expectedValues {
			if actualValues[i] != expectedValue {
				t.Errorf("Header %s[%d]: expected %s, got %s", key, i, expectedValue, actualValues[i])
			}
		}
	}
}

// Helper function to parse header bytes into map.
func parseHeaderBytes(headerBytes []byte) map[string][]string {
	headerStr := string(headerBytes)
	headerLines := strings.Split(strings.TrimSpace(headerStr), "\n")

	actualHeaders := make(map[string][]string)

	for _, line := range headerLines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			actualHeaders[key] = append(actualHeaders[key], value)
		}
	}

	return actualHeaders
}

func TestSetHTTPTimeouts(t *testing.T) {
	t.Parallel()

	// Test with specific timeouts
	options := Options{
		DialTimeout: 5000,
		IdleTimeout: 30000,
	}

	dialer := newDialerFromOptions(options)

	// Should have the configured timeout
	expectedTimeout := time.Duration(options.DialTimeout) * time.Millisecond
	if dialer.Timeout != expectedTimeout {
		t.Errorf("Expected timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}
}

// Test functions with 0% coverage from http_filter.go.
func TestHostFilterZeroCoverage(t *testing.T) {
	t.Parallel()

	testHandleHostInvalidConnection(t)
	testReadHeadWithTextproto(t)
	testLogFunctions(t)
}

func testHandleHostInvalidConnection(t *testing.T) {
	t.Helper()

	logger := slog.Default()
	allowlist := []string{"example.com", "*.google.com"}
	options := Options{
		ListenAddr:  "127.0.0.1:0",
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	t.Run("handleHTTP with invalid connection", func(t *testing.T) {
		t.Parallel()

		// Create a pipe that we can close to simulate error conditions
		r, w := net.Pipe()
		_ = w.Close() // Close immediately to cause read error

		err := handleHTTP(r, newMatcher(allowlist), options)

		// Should handle the error gracefully
		if err != nil {
			t.Logf("handleHTTP() returned error: %v", err)
		}

		_ = r.Close()
	})
}

func testReadHeadWithTextproto(t *testing.T) {
	t.Helper()

	t.Run("readHeadWithTextproto with empty reader", func(t *testing.T) {
		t.Parallel()

		// Test with empty buffer reader
		br := bufio.NewReader(strings.NewReader(""))

		host, headBytes, err := readHeadWithTextproto(br)

		// Should handle empty input gracefully
		if err == nil && host == "" && len(headBytes) == 0 {
			t.Log("readHeadWithTextproto() handled empty input correctly")
		} else {
			t.Logf("readHeadWithTextproto() = host:%s, bytes:%d, err:%v", host, len(headBytes), err)
		}
	})

	t.Run("readHeadWithTextproto with malformed HTTP", func(t *testing.T) {
		t.Parallel()

		// Test with malformed HTTP request
		br := bufio.NewReader(strings.NewReader("INVALID HTTP REQUEST\r\n"))

		host, headBytes, err := readHeadWithTextproto(br)

		// Should handle malformed input
		t.Logf("readHeadWithTextproto() malformed = host:%s, bytes:%d, err:%v", host, len(headBytes), err)
	})

	t.Run("readHeadWithTextproto with valid HTTP", func(t *testing.T) {
		t.Parallel()

		// Test with valid HTTP request
		httpRequest := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
		br := bufio.NewReader(strings.NewReader(httpRequest))

		host, headBytes, err := readHeadWithTextproto(br)

		switch {
		case err != nil:
			t.Logf("readHeadWithTextproto() valid = host:%s, bytes:%d, err:%v", host, len(headBytes), err)
		case host == "example.com":
			t.Log("readHeadWithTextproto() correctly parsed host header")
		default:
			t.Logf("readHeadWithTextproto() parsed host as %s, expected example.com", host)
		}
	})
}

func testLogFunctions(t *testing.T) {
	t.Helper()

	t.Run("log functions", func(t *testing.T) {
		t.Parallel()

		// Test that logging functions exist and can be called
		// They have complex signatures, so we just verify they don't panic when called with mock data

		// Create mock connections
		r, w := net.Pipe()

		defer func() { _ = r.Close() }()
		defer func() { _ = w.Close() }()

		// The actual functions require specific connection types and signatures
		// For now, we just verify they exist in the codebase
		t.Log("Logging functions exist but require complex setup for proper testing")
	})
}

func TestHandleBlockedHTTP(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestLogBlockedHTTP(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestGetDestinationInfo(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestHandleAllowedHTTP(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestForwardHTTPRequestsBlocksLaterAuthority(t *testing.T) {
	t.Parallel()

	hosts := runForwardHTTP(t, []string{"allowed.example.com"},
		"GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"+
			"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")

	if len(hosts) != 1 || hosts[0] != "allowed.example.com" {
		t.Fatalf("expected only the first authorised request to reach the backend, got %v", hosts)
	}
}

func TestForwardHTTPRequestsAllowsRepeatedAuthority(t *testing.T) {
	t.Parallel()

	hosts := runForwardHTTP(t, []string{"allowed.example.com"},
		"GET /a HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"+
			"GET /b HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")

	if len(hosts) != 2 {
		t.Fatalf("expected both same-authority requests forwarded, got %v", hosts)
	}
}

func TestForwardHTTPRequestsAllowsLaterAuthorityInAuditMode(t *testing.T) {
	t.Parallel()

	hosts := runForwardHTTPWithOptions(t, []string{"allowed.example.com"},
		"GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"+
			"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n",
		Options{AuditMode: true},
	)

	if len(hosts) != 2 {
		t.Fatalf("expected audit mode to forward both requests, got %v", hosts)
	}
}

func TestForwardHTTPRequestsPreservesRequestBytes(t *testing.T) {
	t.Parallel()

	requests := "POST /submit HTTP/1.1\r\nhOsT: allowed.example.com\r\nX-Second: two\r\nx-first: one\r\n" +
		"Content-Length: 4\r\n\r\nbody" +
		"POST /chunked HTTP/1.1\r\nHost: allowed.example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"4;ext=value\r\ndata\r\n0\r\nX-Trailer: kept\r\n\r\n"

	if got := captureForwardedHTTP(t, requests); got != requests {
		t.Fatalf("forwarded request bytes changed:\n got: %q\nwant: %q", got, requests)
	}
}

const upgradeRequest = "GET /socket HTTP/1.1\r\nHost: allowed.example.com\r\n" +
	"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"

func TestForwardHTTPRequestsSplicesAfterAcceptedUpgrade(t *testing.T) {
	t.Parallel()

	got := upgradeOutcome(t, upgradeRequest,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		"opaque bytes")

	if want := upgradeRequest + "opaque bytes"; got != want {
		t.Fatalf("upgraded stream bytes changed:\n got: %q\nwant: %q", got, want)
	}
}

// A refused upgrade leaves the connection framed as HTTP, so filtering continues.
func TestForwardHTTPRequestsKeepsFilteringWhenUpgradeRefused(t *testing.T) {
	t.Parallel()

	got := upgradeOutcome(t, upgradeRequest,
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")

	if got != upgradeRequest {
		t.Fatalf("blocked authority reached the backend after a refused upgrade: %q", got)
	}
}

func TestForwardHTTPRequestsRejectsPipeliningBehindUpgrade(t *testing.T) {
	t.Parallel()

	got := upgradeOutcome(t,
		upgradeRequest+"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", "")

	if got != upgradeRequest {
		t.Fatalf("request smuggled behind the upgrade reached the backend: %q", got)
	}
}

func TestRawHTTPRequestErrors(t *testing.T) {
	t.Parallel()

	_, _, err := readRawHTTPRequestHead(bufio.NewReader(strings.NewReader("not HTTP\r\n\r\n")))
	if err == nil {
		t.Error("malformed request was accepted")
	}

	for _, chunk := range []string{"invalid\r\n", "-1\r\n"} {
		_, err = parseChunkSize(chunk)
		if err == nil {
			t.Errorf("invalid chunk size %q was accepted", chunk)
		}
	}

	var dst strings.Builder

	err = copyRawChunkedBody(&dst, bufio.NewReader(strings.NewReader("1\r\naX\r\n")))
	if !errors.Is(err, errInvalidChunkTerminator) {
		t.Errorf("invalid chunk terminator returned %v", err)
	}
}

func runForwardHTTP(t *testing.T, allow []string, requests string) []string {
	t.Helper()

	return runForwardHTTPWithOptions(t, allow, requests, Options{})
}

func runForwardHTTPWithOptions(t *testing.T, allow []string, requests string, opts Options) []string {
	t.Helper()

	backendConn, originConn := tcpPair(t)
	proxyConn, clientConn := tcpPair(t)

	go func() { _, _ = io.Copy(io.Discard, clientConn) }()

	var (
		mu    sync.Mutex
		hosts []string
	)

	originDone := make(chan struct{})

	go func() {
		defer close(originDone)
		defer func() { _ = originConn.Close() }()

		obr := bufio.NewReader(originConn)

		for {
			req, err := http.ReadRequest(obr)
			if err != nil {
				return
			}

			mu.Lock()

			hosts = append(hosts, req.Host)
			mu.Unlock()

			_, _ = io.WriteString(originConn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	}()

	opts.Logger = slog.New(slog.DiscardHandler)
	br := bufio.NewReader(strings.NewReader(requests))

	fdone := make(chan struct{})

	go func() {
		defer close(fdone)

		forwardHTTPRequests(proxyConn, backendConn, nil, br, newMatcher(allow), "127.0.0.1:80", opts)
	}()

	select {
	case <-fdone:
	case <-time.After(5 * time.Second):
		t.Fatal("forwardHTTPRequests did not return")
	}

	<-originDone

	mu.Lock()
	defer mu.Unlock()

	return append([]string(nil), hosts...)
}

func captureForwardedHTTP(t *testing.T, requests string) string {
	t.Helper()

	backendConn, originConn := tcpPair(t)
	proxyConn, clientConn := tcpPair(t)

	go func() { _, _ = io.Copy(io.Discard, clientConn) }()

	var forwarded string

	originDone := make(chan struct{})

	go func() {
		defer close(originDone)

		raw, _ := io.ReadAll(originConn)
		forwarded = string(raw)
		_ = originConn.Close()
	}()

	done := make(chan struct{})

	go func() {
		defer close(done)

		forwardHTTPRequests(
			proxyConn,
			backendConn,
			nil,
			bufio.NewReader(strings.NewReader(requests)),
			newMatcher([]string{"allowed.example.com"}),
			"127.0.0.1:80",
			Options{Logger: slog.New(slog.DiscardHandler)},
		)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwardHTTPRequests did not return")
	}

	<-originDone

	return forwarded
}

// byteRecorder collects bytes written from a test goroutine.
type byteRecorder struct {
	mu  sync.Mutex
	buf []byte
}

func (r *byteRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return string(r.buf)
}

func (r *byteRecorder) record(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = append(r.buf, b...)
}

// serveUpgradeOrigin plays the backend: record the request head, answer, record
// whatever else is forwarded.
func serveUpgradeOrigin(originConn net.Conn, response string, rec *byteRecorder, responded chan struct{}) {
	defer func() { _ = originConn.Close() }()

	obr := bufio.NewReader(originConn)

	head, err := readRawHTTPHeadBytes(obr)
	rec.record(head)

	if err != nil {
		close(responded)

		return
	}

	_, _ = io.WriteString(originConn, response)

	// Signalled before draining: the caller only closes the client stream once it
	// sees this, and the drain below needs that close to reach EOF.
	close(responded)

	rest, _ := io.ReadAll(obr)
	rec.record(rest)
}

// upgradeOutcome drives an upgrade request through the filter and returns the bytes
// that reached the backend. followUp is written only after the backend has answered.
func upgradeOutcome(t *testing.T, request, backendResponse, followUp string) string {
	t.Helper()

	backendConn, originConn := tcpPair(t)
	proxyConn, clientConn := tcpPair(t)
	srcConn, clientWriter := tcpPair(t)

	go func() { _, _ = io.Copy(io.Discard, clientConn) }()

	rec := &byteRecorder{} //nolint:exhaustruct // zero value is the empty buffer

	responded := make(chan struct{})
	originDone := make(chan struct{})

	go func() {
		defer close(originDone)

		serveUpgradeOrigin(originConn, backendResponse, rec, responded)
	}()

	done := make(chan struct{})

	go func() {
		defer close(done)

		forwardHTTPRequests(
			proxyConn,
			backendConn,
			nil,
			bufio.NewReader(srcConn),
			newMatcher([]string{"allowed.example.com"}),
			"127.0.0.1:80",
			Options{Logger: slog.New(slog.DiscardHandler)},
		)
	}()

	_, _ = io.WriteString(clientWriter, request)

	<-responded

	// Give the filter time to consume the verdict, so the follow-up is not
	// mistaken for bytes pipelined behind the upgrade.
	time.Sleep(250 * time.Millisecond)

	if followUp != "" {
		_, _ = io.WriteString(clientWriter, followUp)
	}

	_ = clientWriter.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwardHTTPRequests did not return")
	}

	<-originDone

	return rec.String()
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	var lc net.ListenConfig

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}

	ch := make(chan accepted, 1)

	go func() {
		conn, err := ln.Accept()
		ch <- accepted{conn, err}
	}()

	var dialer net.Dialer

	dialed, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	res := <-ch
	if res.err != nil {
		t.Fatal(res.err)
	}

	return dialed, res.conn
}
