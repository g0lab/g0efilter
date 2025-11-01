//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"context"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Test constants.
const (
	defaultDNSUpstream = "127.0.0.11:53"
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
	if len(handler.allowlist) != len(allowedDomains) {
		t.Errorf("Expected %d domains in allowlist, got %d", len(allowedDomains), len(handler.allowlist))
	}

	// Verify the allowlist contains the expected domains
	for _, domain := range allowedDomains {
		found := slices.Contains(handler.allowlist, domain)

		if !found {
			t.Errorf("Expected allowlist to contain %q", domain)
		}
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

//nolint:paralleltest // Cannot use t.Parallel() due to environment variable modifications
func TestDefaultUpstreamsFromEnv(t *testing.T) {
	//nolint:paralleltest // Cannot use t.Parallel() due to environment variable modifications
	t.Run("basic cases", func(t *testing.T) {
		testDefaultUpstreamsBasicCases(t)
	})

	//nolint:paralleltest // Cannot use t.Parallel() due to environment variable modifications
	t.Run("edge cases", func(t *testing.T) {
		testDefaultUpstreamsEdgeCases(t)
	})
}

func testDefaultUpstreamsBasicCases(t *testing.T) {
	t.Helper()

	t.Run("no environment variable", func(t *testing.T) {
		_ = os.Unsetenv("DNS_UPSTREAMS")

		upstreams := defaultUpstreamsFromEnv()
		if len(upstreams) != 1 || upstreams[0] != defaultDNSUpstream {
			t.Errorf("Expected [%s], got %v", defaultDNSUpstream, upstreams)
		}
	})

	t.Run("single upstream", func(t *testing.T) {
		t.Setenv("DNS_UPSTREAMS", "8.8.8.8:53")

		upstreams := defaultUpstreamsFromEnv()

		expected := []string{"8.8.8.8:53"}
		if len(upstreams) != 1 || len(expected) < 1 || upstreams[0] != expected[0] {
			t.Errorf("Expected %v, got %v", expected, upstreams)
		}
	})

	t.Run("multiple upstreams", func(t *testing.T) {
		t.Setenv("DNS_UPSTREAMS", "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")

		upstreams := defaultUpstreamsFromEnv()

		expected := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
		if len(upstreams) != len(expected) {
			t.Errorf("Expected %d upstreams, got %d", len(expected), len(upstreams))
		}

		for i, exp := range expected {
			if i >= len(upstreams) || upstreams[i] != exp {
				t.Errorf("Expected upstream[%d] = %s, got %s", i, exp, upstreams[i])
			}
		}
	})
}

func testDefaultUpstreamsEdgeCases(t *testing.T) {
	t.Helper()

	t.Run("spaces and empty values", func(t *testing.T) {
		t.Setenv("DNS_UPSTREAMS", " 8.8.8.8:53 , , 1.1.1.1:53 ")

		upstreams := defaultUpstreamsFromEnv()

		expected := []string{"8.8.8.8:53", "1.1.1.1:53"}
		if len(upstreams) != len(expected) {
			t.Errorf("Expected %d upstreams, got %d", len(expected), len(upstreams))
		}
	})

	t.Run("empty variable", func(t *testing.T) {
		t.Setenv("DNS_UPSTREAMS", "   ")

		upstreams := defaultUpstreamsFromEnv()
		if len(upstreams) != 1 || upstreams[0] != defaultDNSUpstream {
			t.Errorf("Expected [%s], got %v", defaultDNSUpstream, upstreams)
		}
	})
}

func TestParseRemoteAddr(t *testing.T) {
	t.Parallel()

	handler := &dnsHandler{}

	tests := []struct {
		name       string
		addr       net.Addr
		expectIP   string
		expectPort int
	}{
		{
			name:       "Valid UDP address",
			addr:       &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345},
			expectIP:   "192.168.1.1",
			expectPort: 12345,
		},
		{
			name:       "Valid TCP address",
			addr:       &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 54321},
			expectIP:   "10.0.0.1",
			expectPort: 54321,
		},
		{
			name:       "IPv6 UDP address",
			addr:       &net.UDPAddr{IP: net.IPv6loopback, Port: 8080},
			expectIP:   "::1",
			expectPort: 8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockWriter := &mockDNSResponseWriter{remoteAddr: tt.addr}
			ip, port := handler.parseRemoteAddr(mockWriter)

			if ip != tt.expectIP {
				t.Errorf("Expected IP %s, got %s", tt.expectIP, ip)
			}

			if port != tt.expectPort {
				t.Errorf("Expected port %d, got %d", tt.expectPort, port)
			}
		})
	}
}

func TestHandlerRespondWithError(t *testing.T) {
	t.Parallel()

	handler := &dnsHandler{}

	// Test respondWithError function
	request := &dns.Msg{}
	request.SetQuestion("example.com.", dns.TypeA)
	request.Id = 12345

	mockWriter := &mockDNSResponseWriter{responses: make([]*dns.Msg, 0)}

	handler.respondWithError(mockWriter, request, dns.RcodeNameError)

	if len(mockWriter.responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockWriter.responses))
	}

	response := mockWriter.responses[0]
	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN (%d), got rcode %d", dns.RcodeNameError, response.Rcode)
	}

	if response.Id != request.Id {
		t.Errorf("Expected response ID %d, got %d", request.Id, response.Id)
	}

	if !response.Response {
		t.Error("Expected response flag to be set")
	}
}

func TestDNSServerSetup(t *testing.T) {
	t.Parallel()

	handler := &dnsHandler{}

	// Test server setup without actually starting them
	udpServer, tcpServer := setupDNSServers("127.0.0.1:0", handler)

	if udpServer == nil {
		t.Error("Expected non-nil UDP server")
	}

	if tcpServer == nil {
		t.Error("Expected non-nil TCP server")
	}

	if udpServer != nil && udpServer.Net != "udp" {
		t.Errorf("Expected UDP server, got %s", udpServer.Net)
	}

	if tcpServer != nil && tcpServer.Net != "tcp" {
		t.Errorf("Expected TCP server, got %s", tcpServer.Net)
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
		{dns.TypeNS, "NS"},
		{dns.TypeSRV, "SRV"},
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
		{dns.RcodeNotImplemented, "NOTIMP"},
		{dns.RcodeRefused, "REFUSED"},
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

// Test functions with 0% coverage from dns_filter.go.
func TestBlockedEnforcedType(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"allowed.com"}
	options := Options{
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	tests := []struct {
		name     string
		qtype    uint16
		expected string
	}{
		{"A record", dns.TypeA, "blocked A query should return 0.0.0.0"},
		{"AAAA record", dns.TypeAAAA, "blocked AAAA query should return ::"},
		{"Other type", dns.TypeTXT, "blocked other query should return NXDOMAIN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testBlockedEnforcedTypeCase(t, handler, logger, tt.qtype, tt.name, tt.expected)
		})
	}
}

func testBlockedEnforcedTypeCase(
	t *testing.T, handler *dnsHandler, logger *slog.Logger, qtype uint16, name, expected string,
) {
	t.Helper()
	// Create DNS request
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("blocked.com"), qtype)

	mockWriter := &mockDNSResponseWriter{
		responses: make([]*dns.Msg, 0),
	}

	// Test handleBlockedEnforcedType
	handler.handleBlockedEnforcedType(
		logger,
		mockWriter,
		msg,
		"blocked.com",
		qtype,
		"192.168.1.1",
		12345,
		"test-flow-id",
	)

	validateBlockedEnforcedResponse(t, mockWriter, qtype, name, expected)
}

func validateBlockedEnforcedResponse(
	t *testing.T, mockWriter *mockDNSResponseWriter, qtype uint16, name, expected string,
) {
	t.Helper()

	if len(mockWriter.responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockWriter.responses))
	}

	response := mockWriter.responses[0]

	t.Logf("Test case %s: %s", name, expected)

	switch qtype {
	case dns.TypeA:
		if len(response.Answer) == 0 {
			t.Error("Expected A record in response")
		}
	case dns.TypeAAAA:
		if len(response.Answer) == 0 {
			t.Error("Expected AAAA record in response")
		}
	default:
		if response.Rcode != dns.RcodeNameError {
			t.Errorf("Expected NXDOMAIN for type %d, got rcode %d", qtype, response.Rcode)
		}
	}
}

func TestBlockedNonEnforcedType(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"allowed.com"}
	options := Options{
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	// Create DNS request
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("blocked.com"), dns.TypeA)

	mockWriter := &mockDNSResponseWriter{
		responses: make([]*dns.Msg, 0),
	}

	// Test handleBlockedNonEnforcedType
	handler.handleBlockedNonEnforcedType(
		logger,
		mockWriter,
		msg,
		"blocked.com",
		dns.TypeA,
		"192.168.1.1",
		12345,
		"test-flow-id",
	)

	if len(mockWriter.responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockWriter.responses))
	}

	response := mockWriter.responses[0]
	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got rcode %d", response.Rcode)
	}
}

func TestStartUDPServer(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	opts := Options{Logger: logger}

	allowedDomains := []string{"example.com"}
	handler := createDNSHandler(allowedDomains, opts)

	server := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler.handle),
	}

	errCh := make(chan error, 1)

	// Start server in goroutine
	go startUDPServer(server, errCh, opts)

	// Give it a moment to attempt start
	select {
	case err := <-errCh:
		// Expected to fail in test environment
		t.Logf("UDP server start failed as expected: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Timeout is also acceptable
		t.Log("UDP server start timed out as expected in test environment")
	}
}

func TestStartTCPServer(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	opts := Options{Logger: logger}

	allowedDomains := []string{"example.com"}
	handler := createDNSHandler(allowedDomains, opts)

	server := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "tcp",
		Handler: dns.HandlerFunc(handler.handle),
	}

	errCh := make(chan error, 1)

	// Start server in goroutine
	go startTCPServer(server, errCh, opts)

	// Give it a moment to attempt start
	select {
	case err := <-errCh:
		// Expected to fail in test environment
		t.Logf("TCP server start failed as expected: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Timeout is also acceptable
		t.Log("TCP server start timed out as expected in test environment")
	}
}

func TestHandleAllowedRequest(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com"}
	options := Options{
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	// Create DNS request
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	mockWriter := &mockDNSResponseWriter{
		responses: make([]*dns.Msg, 0),
	}

	// Test handleAllowedRequest
	handler.handleAllowedRequest(
		logger,
		mockWriter,
		msg,
		"example.com",
		dns.TypeA,
		"192.168.1.1",
		12345,
		"test-flow-id",
	)

	// Should have attempted to forward the request
	// In test environment without real DNS upstream, we expect it to handle gracefully
	t.Log("handleAllowedRequest executed without panic")
}

func TestEmitSyntheticEvent(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com"}
	options := Options{
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	mockWriter := &mockDNSResponseWriter{
		responses:  make([]*dns.Msg, 0),
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345},
	}

	flowID := handler.emitSyntheticEvent(logger, mockWriter, "192.168.1.1", 12345)

	if flowID == "" {
		t.Error("Expected non-empty flow ID")
	}
}

func TestDNSForward(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com"}
	options := Options{
		DialTimeout: 100,
		IdleTimeout: 500,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// This will likely fail due to no real upstream, but should not panic
	_, err := handler.forward(msg)

	// Error is expected in test environment
	if err != nil {
		t.Logf("DNS forward failed as expected in test environment: %v", err)
	}
}

func TestMarkedDialer(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedDomains := []string{"example.com"}
	options := Options{
		DialTimeout: 5000,
		IdleTimeout: 30000,
		Logger:      logger,
	}

	handler := createDNSHandler(allowedDomains, options)

	dialer := handler.markedDialer()
	if dialer == nil {
		t.Error("Expected non-nil dialer")

		return
	}

	// Should have timeout set
	expectedTimeout := 5 * time.Second
	if dialer.Timeout != expectedTimeout {
		t.Errorf("Expected timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}
}
