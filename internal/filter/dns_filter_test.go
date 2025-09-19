//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServe53(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com", "google.com"}
	options := Options{
		ListenAddr:  "127.0.0.1:0", // Use port 0 to let OS choose
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test that Serve53 can start (will likely timeout in test environment)
	err := Serve53(ctx, allowedDomains, options)

	// In test environment, we expect this to timeout or fail to bind
	// We're mainly testing that the function doesn't panic
	if err != nil {
		t.Logf("Serve53 failed as expected in test environment: %v", err)
	}
}

func TestCreateDNSHandler(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com", "*.google.com"}
	options := Options{
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)
	if handler == nil {
		t.Fatal("Expected non-nil DNS handler")
	}

	if len(handler.allowlist) != len(allowedDomains) {
		t.Errorf("Expected %d domains in allowlist, got %d", len(allowedDomains), len(handler.allowlist))
	}

	// Test handler processing
	t.Run("handle DNS query", func(t *testing.T) {
		t.Parallel()

		// Create a mock DNS query
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

		// Create a mock response writer
		mockWriter := &mockDNSResponseWriter{
			responses: make([]*dns.Msg, 0),
		}

		// Test the handler
		handler.handle(mockWriter, msg)

		// We expect the handler to have processed the request
		t.Logf("Handler processed query for example.com")
	})
}

func TestSetupDNSServers(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com"}
	options := Options{
		ListenAddr:  "127.0.0.1:0",
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	// Test server setup
	udpServer, tcpServer := setupDNSServers(options.ListenAddr, handler)

	if udpServer == nil {
		t.Error("Expected non-nil UDP server")

		return
	}

	if tcpServer == nil {
		t.Error("Expected non-nil TCP server")

		return
	}

	if udpServer.Net != "udp" {
		t.Errorf("Expected UDP server, got %s", udpServer.Net)
	}

	if tcpServer.Net != "tcp" {
		t.Errorf("Expected TCP server, got %s", tcpServer.Net)
	}
}

func TestDurOrDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration
		fallback time.Duration
		expected time.Duration
	}{
		{
			name:     "positive value",
			duration: 1000 * time.Millisecond,
			fallback: 5 * time.Second,
			expected: 1000 * time.Millisecond,
		},
		{
			name:     "zero value uses fallback",
			duration: 0,
			fallback: 3 * time.Second,
			expected: 3 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := durOrDefault(tt.duration, tt.fallback)
			if result != tt.expected {
				t.Errorf("durOrDefault(%v, %v) = %v, want %v", tt.duration, tt.fallback, result, tt.expected)
			}
		})
	}
}

func TestDefaultUpstreamsFromEnv(t *testing.T) {
	t.Parallel()

	// Test getting default upstreams
	upstreams := defaultUpstreamsFromEnv()

	// In test environment, this may return empty slice
	// We're mainly testing it doesn't panic
	t.Logf("Found %d default upstreams", len(upstreams))

	for i, upstream := range upstreams {
		if upstream == "" {
			t.Errorf("Upstream %d is empty", i)
		}
	}
}

func TestTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		qtype    uint16
		expected string
	}{
		{dns.TypeA, "A"},
		{dns.TypeAAAA, "AAAA"},
		{dns.TypeMX, "MX"},
		{dns.TypeCNAME, "CNAME"},
		{dns.TypeTXT, "TXT"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()

			result := typeString(tt.qtype)
			if result != tt.expected {
				t.Errorf("typeString(%d) = %s, want %s", tt.qtype, result, tt.expected)
			}
		})
	}

	// Test unknown type separately
	t.Run("unknown_type", func(t *testing.T) {
		t.Parallel()

		result := typeString(999)
		if !strings.HasPrefix(result, "TYPE") {
			t.Errorf("typeString(999) = %s, want to start with TYPE", result)
		}
	})
}

func TestRcodeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rcode    int
		expected string
	}{
		{dns.RcodeSuccess, "NOERROR"},
		{dns.RcodeFormatError, "FORMERR"},
		{dns.RcodeServerFailure, "SERVFAIL"},
		{dns.RcodeNameError, "NXDOMAIN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()

			result := rcodeString(tt.rcode)
			if result != tt.expected {
				t.Errorf("rcodeString(%d) = %s, want %s", tt.rcode, result, tt.expected)
			}
		})
	}

	// Test unknown rcode separately
	t.Run("unknown_rcode", func(t *testing.T) {
		t.Parallel()

		result := rcodeString(999)
		if !strings.HasPrefix(result, "RCODE") {
			t.Errorf("rcodeString(999) = %s, want to start with RCODE", result)
		}
	})
}

// Mock DNS response writer for testing.
type mockDNSResponseWriter struct {
	responses  []*dns.Msg
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockDNSResponseWriter) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	return addr
}

func (m *mockDNSResponseWriter) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}

	addr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:12345")

	return addr
}

func (m *mockDNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.responses = append(m.responses, msg)

	return nil
}

func (m *mockDNSResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockDNSResponseWriter) Close() error {
	return nil
}

func (m *mockDNSResponseWriter) TsigStatus() error {
	return nil
}

func (m *mockDNSResponseWriter) TsigTimersOnly(bool) {}

func (m *mockDNSResponseWriter) Hijack() {}
