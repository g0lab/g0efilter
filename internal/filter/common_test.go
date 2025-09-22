//nolint:testpackage // Need access to internal implementation details
package filter

import (
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
		nil, // backend connection can be nil
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
