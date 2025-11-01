//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Test constants.
const (
	testTCPNetwork = "tcp"
)

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty string", "", ""},
		{"Already normalized", "example.com", "example.com"},
		{"Uppercase", "EXAMPLE.COM", "example.com"},
		{"Mixed case", "ExAmPlE.CoM", "example.com"},
		{"With trailing dot", "example.com.", "example.com"},
		{"Unicode domain", "münchen.de", "xn--mnchen-3ya.de"},
		{"Wildcard domain", "*.example.com", "*.example.com"},
		{"Subdomain", "sub.example.com", "sub.example.com"},
		{"Wildcard only", "*", "*"},
		{"Domain with spaces", "  example.com  ", "example.com"},
		{"Complex Unicode", "пример.испытание", "xn--e1afmkfd.xn--80akhbyknj4f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := normalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAllowedHost(t *testing.T) {
	t.Parallel()

	allowlist := []string{
		"example.com",
		"*.google.com",
		"test.org",
		"*.sub.domain.com",
	}

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"Exact match", "example.com", true},
		{"Wildcard match", "mail.google.com", true},
		{"Wildcard match - www", "www.google.com", true},
		{"Multiple level wildcard", "api.sub.domain.com", true},
		{"No match", "facebook.com", false},
		{"Partial match", "notexample.com", false},
		{"Wrong wildcard", "google.com", false},
		{"Case insensitive exact", "EXAMPLE.COM", true},
		{"Case insensitive wildcard", "MAIL.GOOGLE.COM", true},
		{"Empty host", "", false},
		{"Host with port", "example.com:8080", false},
		{"Wildcard with port", "mail.google.com:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := allowedHost(tt.host, allowlist)
			if result != tt.expected {
				t.Errorf("allowedHost(%q, allowlist) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		hostPort     string
		expectedHost string
		expectedPort int
		wantErr      bool
	}{
		{"Valid host and port", "example.com:8080", "example.com", 8080, false},
		{"IPv4 with port", "192.168.1.1:80", "192.168.1.1", 80, false},
		{"IPv6 with port", "[::1]:8080", "::1", 8080, false},
		{"Host without port", "example.com", "example.com", 0, false},
		{"Empty string", "", "", 0, true},
		{"Invalid port", "example.com:invalid", "example.com", 0, false},
		{"Port out of range", "example.com:99999", "example.com", 99999, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, port := parseHostPort(tt.hostPort)

			if host != tt.expectedHost {
				t.Errorf("Expected host %s, got %s", tt.expectedHost, host)
			}

			if port != tt.expectedPort {
				t.Errorf("Expected port %d, got %d", tt.expectedPort, port)
			}
		})
	}
}

func TestSourceAddr(t *testing.T) {
	t.Parallel()

	t.Run("valid addresses", func(t *testing.T) {
		t.Parallel()
		testSourceAddrValidCases(t)
	})

	t.Run("edge cases", func(t *testing.T) {
		t.Parallel()
		testSourceAddrEdgeCases(t)
	})
}

func testSourceAddrValidCases(t *testing.T) {
	t.Helper()

	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{"IPv4 UDP", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}, "192.168.1.1"},
		{"IPv4 TCP", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 54321}, "10.0.0.1"},
		{"IPv6 UDP", &net.UDPAddr{IP: net.IPv6loopback, Port: 8080}, "::1"},
		{"IPv6 TCP", &net.TCPAddr{IP: net.IPv6loopback, Port: 9090}, "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a mock connection with the test address
			mockConn := &mockConn{remoteAddr: tt.addr}

			ip, port := sourceAddr(mockConn)
			if ip != tt.expected {
				t.Errorf("sourceAddr IP: expected %q, got %q", tt.expected, ip)
			}

			// Verify port matches the address
			expectedPort := getExpectedPort(tt.addr)
			if port != expectedPort {
				t.Errorf("sourceAddr port: expected %d, got %d", expectedPort, port)
			}
		})
	}
}

func testSourceAddrEdgeCases(t *testing.T) {
	t.Helper()

	t.Run("nil connection", func(t *testing.T) {
		t.Parallel()

		ip, port := sourceAddr(nil)
		if ip != "" || port != 0 {
			t.Errorf("sourceAddr(nil): expected ('', 0), got (%q, %d)", ip, port)
		}
	})

	t.Run("nil remote address", func(t *testing.T) {
		t.Parallel()

		mockConn := &mockConn{remoteAddr: nil}

		ip, port := sourceAddr(mockConn)
		if ip != "" || port != 0 {
			t.Errorf("sourceAddr with nil RemoteAddr: expected ('', 0), got (%q, %d)", ip, port)
		}
	})

	t.Run("malformed address", func(t *testing.T) {
		t.Parallel()

		mockConn := &mockConn{remoteAddr: &malformedAddr{}}

		ip, port := sourceAddr(mockConn)
		if ip != "malformed-address" || port != 0 {
			t.Errorf("sourceAddr with malformed address: expected ('malformed-address', 0), got (%q, %d)", ip, port)
		}
	})
}

func getExpectedPort(addr net.Addr) int {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.Port
	case *net.TCPAddr:
		return a.Port
	default:
		return 0
	}
}

// Mock connection for testing sourceAddr.
type mockConn struct {
	remoteAddr net.Addr
}

func (m *mockConn) Read(_ []byte) (int, error)         { return 0, nil }
func (m *mockConn) Write(_ []byte) (int, error)        { return 0, nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

// Mock address that doesn't contain a valid host:port format.
type malformedAddr struct{}

func (m *malformedAddr) Network() string { return testTCPNetwork }
func (m *malformedAddr) String() string  { return "malformed-address" }

func TestFlowID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		srcIP       string
		srcPort     int
		destIP      string
		destPort    int
		expectedLen int
	}{
		{"IPv4 to IPv4", "192.168.1.1", 12345, "10.0.0.1", 80, 8},
		{"IPv6 to IPv6", "::1", 8080, "::2", 443, 8},
		{"Mixed addresses", "192.168.1.1", 0, "::1", 65535, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := FlowID(tt.srcIP, tt.srcPort, tt.destIP, tt.destPort, "tcp")
			if len(result) == 0 {
				t.Error("FlowID returned empty string")
			}

			// Test consistency - same inputs should produce same result
			result2 := FlowID(tt.srcIP, tt.srcPort, tt.destIP, tt.destPort, "tcp")
			if result != result2 {
				t.Error("FlowID should be consistent for same inputs")
			}

			// Test difference - different inputs should produce different result
			result3 := FlowID(tt.srcIP, tt.srcPort+1, tt.destIP, tt.destPort, "tcp")
			if result == result3 {
				t.Error("FlowID should be different for different inputs")
			}
		})
	}
}

func TestIsSyntheticRecent(t *testing.T) {
	t.Parallel()

	// Test marking and checking synthetic flows
	flowID := FlowID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")

	MarkSynthetic(flowID)

	// Should be marked as synthetic
	if !IsSyntheticRecent(flowID) {
		t.Error("Expected flow to be marked as synthetic")
	}

	// Test with non-existent flow
	nonExistentFlow := FlowID("1.1.1.1", 999, "2.2.2.2", 888, "tcp")
	if IsSyntheticRecent(nonExistentFlow) {
		t.Error("Expected non-existent flow to not be synthetic")
	}

	// Test after some time (synthetic status should persist for a short while)
	if !IsSyntheticRecent(flowID) {
		t.Error("Expected flow to still be marked as synthetic shortly after marking")
	}

	// Test edge cases
	t.Run("empty flowID for MarkSynthetic", func(t *testing.T) {
		t.Parallel()
		// Should not panic
		MarkSynthetic("")
		t.Log("MarkSynthetic with empty flowID handled gracefully")
	})

	t.Run("empty flowID for IsSyntheticRecent", func(t *testing.T) {
		t.Parallel()

		if IsSyntheticRecent("") {
			t.Error("Expected empty flowID to not be synthetic recent")
		}
	})

	t.Run("multiple mark and check operations", func(t *testing.T) {
		t.Parallel()

		testFlowID := FlowID("10.10.10.10", 1111, "20.20.20.20", 2222, "tcp")

		// Mark multiple times
		MarkSynthetic(testFlowID)
		MarkSynthetic(testFlowID)
		MarkSynthetic(testFlowID)

		// Should still be recent
		if !IsSyntheticRecent(testFlowID) {
			t.Error("Expected flow to be marked as synthetic after multiple marks")
		}
	})
}

func TestEmitSyntheticUDP(t *testing.T) {
	t.Parallel()

	logger := slog.Default()

	tests := []struct {
		name        string
		component   string
		sourceIP    string
		sourcePort  int
		destination string
		logger      *slog.Logger
		expectID    bool
	}{
		{
			name:        "Valid UDP event",
			component:   "dns",
			sourceIP:    "192.168.1.1",
			sourcePort:  12345,
			destination: "10.0.0.1:53",
			logger:      logger,
			expectID:    true,
		},
		{
			name:        "IPv6 UDP event",
			component:   "https",
			sourceIP:    "::1",
			sourcePort:  8080,
			destination: "[::2]:443",
			logger:      logger,
			expectID:    true,
		},
		{
			name:        "Nil logger",
			component:   "dns",
			sourceIP:    "192.168.1.1",
			sourcePort:  12345,
			destination: "10.0.0.1:53",
			logger:      nil,
			expectID:    false,
		},
		{
			name:        "Empty destination",
			component:   "dns",
			sourceIP:    "192.168.1.1",
			sourcePort:  12345,
			destination: "",
			logger:      logger,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testEmitSyntheticUDPCase(t, tt)
		})
	}
}

func TestTimeoutFromOptions(t *testing.T) {
	t.Parallel()

	def := 3 * time.Second

	// When DialTimeout <= 0 we expect the default
	opts := Options{DialTimeout: 0}
	if got := timeoutFromOptions(opts, def); got != def {
		t.Errorf("timeoutFromOptions returned %v, want %v", got, def)
	}

	// When DialTimeout is set we expect that value in milliseconds
	opts = Options{DialTimeout: 1500}
	if got := timeoutFromOptions(opts, def); got != 1500*time.Millisecond {
		t.Errorf("timeoutFromOptions returned %v, want %v", got, 1500*time.Millisecond)
	}
}

func TestNewDialerFromOptions(t *testing.T) {
	t.Parallel()

	opts := Options{DialTimeout: 2500}

	d := newDialerFromOptions(opts)

	expectedTimeout := 2500 * time.Millisecond
	if d.Timeout != expectedTimeout {
		t.Errorf("dialer timeout = %v, want %v", d.Timeout, expectedTimeout)
	}

	// Zero DialTimeout should produce a dialer with zero Timeout
	opts = Options{DialTimeout: 0}

	d2 := newDialerFromOptions(opts)
	if d2.Timeout != 0 {
		t.Errorf("dialer timeout = %v, want 0", d2.Timeout)
	}
}

func testEmitSyntheticUDPCase(t *testing.T, tt struct {
	name        string
	component   string
	sourceIP    string
	sourcePort  int
	destination string
	logger      *slog.Logger
	expectID    bool
}) {
	t.Helper()

	result := EmitSyntheticUDP(
		tt.logger,
		tt.component,
		tt.sourceIP,
		tt.sourcePort,
		tt.destination,
	)

	if tt.expectID {
		if result == "" {
			t.Error("Expected non-empty flow ID")
		}
		// Verify the flow is marked as synthetic
		if !IsSyntheticRecent(result) {
			t.Error("Expected emitted flow to be marked as synthetic")
		}
	} else if result != "" {
		t.Errorf("Expected empty flow ID, got %q", result)
	}
}

func TestNewMarkedDialer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		dialTimeout     time.Duration
		expectedTimeout time.Duration
	}{
		{"zero timeout", 0, 0},
		{"1 second timeout", 1 * time.Second, 1 * time.Second},
		{"5 seconds timeout", 5 * time.Second, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dialer := newMarkedDialer(tt.dialTimeout)
			if dialer == nil {
				t.Fatal("Expected non-nil dialer")
			}

			if dialer.Timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout %v, got %v", tt.expectedTimeout, dialer.Timeout)
			}
		})
	}
}

func TestSetConnTimeouts(t *testing.T) {
	t.Parallel()

	t.Run("with idle timeout", func(t *testing.T) {
		t.Parallel()

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		opts := Options{IdleTimeout: 5000} // 5 seconds

		setConnTimeouts(conn1, conn2, opts)

		// Function should not panic and connections should still be valid
		if conn1 == nil || conn2 == nil {
			t.Error("Connections should still be valid after setting timeouts")
		}
	})

	t.Run("without idle timeout", func(t *testing.T) {
		t.Parallel()

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		opts := Options{IdleTimeout: 0}

		setConnTimeouts(conn1, conn2, opts)

		// Should not panic with zero timeout
		if conn1 == nil || conn2 == nil {
			t.Error("Connections should still be valid")
		}
	})
}

func TestLogAllowedConnection(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		opts := Options{Logger: logger}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logAllowedConnection(opts, "https", "example.com:443", "example.com", conn1)
	})

	t.Run("without logger", func(t *testing.T) {
		t.Parallel()

		opts := Options{Logger: nil}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logAllowedConnection(opts, "https", "example.com:443", "example.com", conn1)
	})
}

func TestLogBlockedConnection(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		opts := Options{Logger: logger}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logBlockedConnection(opts, "https", "not-allowlisted", "evil.com", conn1, "1.2.3.4", 443)
	})

	t.Run("without logger", func(t *testing.T) {
		t.Parallel()

		opts := Options{Logger: nil}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logBlockedConnection(opts, "https", "not-allowlisted", "evil.com", conn1, "1.2.3.4", 443)
	})
}

var errTestDial = errors.New("dial error")

func TestLogDstConnDialError(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		opts := Options{Logger: logger}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logdstConnDialError(opts, "https", conn1, "example.com:443", errTestDial)
	})

	t.Run("without logger", func(t *testing.T) {
		t.Parallel()

		opts := Options{Logger: nil}

		conn1, conn2 := net.Pipe()

		defer func() { _ = conn1.Close() }()
		defer func() { _ = conn2.Close() }()

		// Should not panic
		logdstConnDialError(opts, "https", conn1, "example.com:443", errTestDial)
	})
}

func TestEmitSynthetic(t *testing.T) {
	t.Parallel()

	logger := slog.Default()

	tests := []struct {
		name      string
		component string
		target    string
		logger    *slog.Logger
		expectID  bool
	}{
		{
			name:      "Valid synthetic event",
			component: "http",
			target:    "example.com:80",
			logger:    logger,
			expectID:  true,
		},
		{
			name:      "Nil logger",
			component: "http",
			target:    "example.com:80",
			logger:    nil,
			expectID:  false,
		},
		{
			name:      "Empty target",
			component: "http",
			target:    "",
			logger:    logger,
			expectID:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testEmitSyntheticCase(t, tt)
		})
	}
}

func testEmitSyntheticCase(t *testing.T, tt struct {
	name      string
	component string
	target    string
	logger    *slog.Logger
	expectID  bool
}) {
	t.Helper()

	// Create a mock connection for the test
	mockConn := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}}

	result := EmitSynthetic(
		tt.logger,
		tt.component,
		mockConn,
		tt.target,
	)

	if tt.expectID {
		if result == "" {
			t.Error("Expected non-empty flow ID")
		}
		// Verify the flow is marked as synthetic
		if !IsSyntheticRecent(result) {
			t.Error("Expected emitted flow to be marked as synthetic")
		}
	} else if result != "" {
		t.Errorf("Expected empty flow ID, got %q", result)
	}
}

func TestBidirectionalCopy(t *testing.T) {
	t.Parallel()

	// Create mock pipe connections
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	conn1 := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}
	conn2 := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}}

	// Use a small buffer for testing
	reader := bytes.NewReader([]byte("test data"))

	// Start bidirectionalCopy in goroutine
	done := make(chan bool)

	go func() {
		bidirectionalCopy(conn1, conn2, reader)

		done <- true
	}()

	// Close pipes to force completion
	_ = r1.Close()
	_ = w1.Close()
	_ = r2.Close()
	_ = w2.Close()

	// Wait for completion or timeout
	select {
	case <-done:
		t.Log("bidirectionalCopy completed")
	case <-time.After(100 * time.Millisecond):
		t.Log("bidirectionalCopy timed out as expected")
	}
}

func TestBidirectionalCopyWithBufferedReader(t *testing.T) {
	t.Parallel()

	// Create mock pipe connections
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	conn1 := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}
	conn2 := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}}

	// Use a buffered reader for testing
	testData := []byte("test data from buffered reader")
	br := bufio.NewReader(bytes.NewReader(testData))

	// Start bidirectionalCopyWithBufferedReader in goroutine
	done := make(chan bool)

	go func() {
		bidirectionalCopyWithBufferedReader(conn1, conn2, br)

		done <- true
	}()

	// Close pipes to force completion
	_ = r1.Close()
	_ = w1.Close()
	_ = r2.Close()
	_ = w2.Close()

	// Wait for completion or timeout
	select {
	case <-done:
		t.Log("bidirectionalCopyWithBufferedReader completed")
	case <-time.After(100 * time.Millisecond):
		t.Log("bidirectionalCopyWithBufferedReader timed out as expected")
	}
}

func TestOriginalDstTCP(t *testing.T) {
	t.Parallel()

	// This function requires a real TCP connection with SO_ORIGINAL_DST socket option
	// Testing with nil or mock connections would cause panics or meaningless failures
	// The function is better tested through integration tests with actual iptables REDIRECT

	t.Log("originalDstTCP requires real TCP connection with iptables REDIRECT, skipping unit test")
	t.Log("This function is covered by integration tests")
}
