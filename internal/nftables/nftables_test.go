//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/internal/actions"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	version, err := Version(ctx)
	if err != nil {
		t.Skipf("nft not available: %v", err)
	}

	if version == "" {
		t.Error("expected non-empty version string")
	}

	// Version should contain a version number
	if !strings.Contains(version, "v") && !strings.Contains(version, ".") {
		t.Errorf("version string doesn't look like a version: %q", version)
	}

	t.Logf("nftables version: %s", version)
}

func TestApplyNftRulesAuto(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getApplyNftRulesAutoTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for test
			if tt.dnsPort != "" {
				t.Setenv("DNS_PORT", tt.dnsPort)
			}

			// This would normally call nft command, so we expect it to fail in test environment
			err := ApplyNftRulesAuto(tt.allowlist, tt.httpsPort, tt.httpPort)

			// We expect errors since nft command likely isn't available in test environment
			// Just verify the function doesn't panic and handles parameters correctly
			if tt.expectError && err == nil {
				t.Error("ApplyNftRulesAuto() expected error, got nil")
			}
		})
	}
}

func getApplyNftRulesAutoTests() []struct {
	name        string
	allowlist   []string
	httpsPort   string
	httpPort    string
	dnsPort     string
	expectError bool
} {
	return []struct {
		name        string
		allowlist   []string
		httpsPort   string
		httpPort    string
		dnsPort     string
		expectError bool
	}{
		{
			name:        "default dns port",
			allowlist:   []string{"1.1.1.1", "8.8.8.8"},
			httpsPort:   "8443",
			httpPort:    "8080",
			dnsPort:     "",
			expectError: true, // nft command not available in test
		},
		{
			name:        "custom dns port",
			allowlist:   []string{"192.168.1.1"},
			httpsPort:   "9443",
			httpPort:    "9080",
			dnsPort:     "5353",
			expectError: true,
		},
		{
			name:        "empty allowlist",
			allowlist:   []string{},
			httpsPort:   "8443",
			httpPort:    "8080",
			dnsPort:     "53",
			expectError: true,
		},
	}
}

func TestApplyNftRules(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getApplyNftRulesTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.filterMode != "" {
				t.Setenv("FILTER_MODE", tt.filterMode)
			}

			err := ApplyNftRules(tt.allowlist, tt.httpsPort, tt.httpPort, tt.dnsPort)

			if tt.expectError {
				if err == nil {
					t.Error("ApplyNftRules() expected error, got nil")
				}
			}
		})
	}
}

func getApplyNftRulesTests() []struct {
	name        string
	allowlist   []string
	httpsPort   string
	httpPort    string
	dnsPort     string
	filterMode  string
	expectError bool
} {
	return []struct {
		name        string
		allowlist   []string
		httpsPort   string
		httpPort    string
		dnsPort     string
		filterMode  string
		expectError bool
	}{
		{
			name:        "https mode",
			allowlist:   []string{"1.1.1.1"},
			httpsPort:   "8443",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "https",
			expectError: true,
		},
		{
			name:        "dns mode",
			allowlist:   []string{"8.8.8.8"},
			httpsPort:   "8443",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "dns",
			expectError: true,
		},
		{
			name:        "invalid https port",
			allowlist:   []string{"1.1.1.1"},
			httpsPort:   "invalid",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "https",
			expectError: true,
		},
		{
			name:        "port out of range",
			allowlist:   []string{"1.1.1.1"},
			httpsPort:   "99999",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "https",
			expectError: true,
		},
	}
}

func TestGenerateNftRuleset(t *testing.T) {
	t.Parallel()

	tests := getGenerateNftRulesetTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ruleset := GenerateNftRuleset(tt.v4, tt.v6, tt.httpsPort, tt.httpPort, tt.dnsPort, tt.mode)

			if ruleset == "" {
				t.Error("GenerateNftRuleset() returned empty ruleset")
			}

			// Check for expected content in ruleset
			for _, expected := range tt.expectedContains {
				if !strings.Contains(ruleset, expected) {
					t.Errorf("GenerateNftRuleset() ruleset missing %q\nRuleset:\n%s", expected, ruleset)
				}
			}

			// Check that v4 allowlist IPs are included if provided
			for _, ip := range tt.v4 {
				if !strings.Contains(ruleset, ip) {
					t.Errorf("GenerateNftRuleset() ruleset missing v4 allowlist IP %q", ip)
				}
			}

			// Check that v6 allowlist IPs are included if provided
			for _, ip := range tt.v6 {
				if !strings.Contains(ruleset, ip) {
					t.Errorf("GenerateNftRuleset() ruleset missing v6 allowlist IP %q", ip)
				}
			}
		})
	}
}

type generateNftRulesetTest struct {
	name             string
	v4               []string
	v6               []string
	httpsPort        int
	httpPort         int
	dnsPort          int
	mode             string
	expectedContains []string
}

func getGenerateNftRulesetTests() []generateNftRulesetTest {
	tests := getHTTPSModeTests()
	tests = append(tests, getDNSModeTests()...)
	tests = append(tests, getDefaultModeTests()...)
	tests = append(tests, getIPv6ModeTests()...)

	return tests
}

func getHTTPSModeTests() []generateNftRulesetTest {
	return []generateNftRulesetTest{
		{
			name:      "https mode with v4 allowlist",
			v4:        []string{"1.1.1.1", "8.8.8.8"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "https",
			expectedContains: []string{
				"table ip g0efilter_v4",
				"table ip g0efilter_nat_v4",
				"table ip6 g0efilter_v6",
				"allow_daddr_v4",
				"tcp dport 80",
				"tcp dport 443",
				"redirect to :8080",
				"redirect to :8443",
			},
		},
	}
}

func getDNSModeTests() []generateNftRulesetTest {
	return []generateNftRulesetTest{
		{
			name:      "dns mode with v4 allowlist",
			v4:        []string{"9.9.9.9"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   5353,
			mode:      "dns",
			expectedContains: []string{
				"table ip g0efilter_v4",
				"table ip g0efilter_nat_v4",
				"allow_daddr_v4",
				"udp dport 53",
				"tcp dport 53",
				"redirect to :5353",
			},
		},
	}
}

func getDefaultModeTests() []generateNftRulesetTest {
	return []generateNftRulesetTest{
		{
			name:      "empty allowlist defaults to https",
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "invalid",
			expectedContains: []string{
				"table ip g0efilter_v4",
				"table ip g0efilter_nat_v4",
				"table ip6 g0efilter_v6",
				"tcp dport 80",
				"tcp dport 443",
			},
		},
	}
}

func getIPv6ModeTests() []generateNftRulesetTest {
	return []generateNftRulesetTest{
		{
			name:      "https mode with mixed v4 and v6 allowlist",
			v4:        []string{"1.1.1.1"},
			v6:        []string{"2001:db8::1", "2606:4700::/32"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "https",
			expectedContains: []string{
				"table ip g0efilter_v4",
				"table ip g0efilter_nat_v4",
				"table ip6 g0efilter_v6",
				"table ip6 g0efilter_nat_v6",
				"allow_daddr_v4",
				"allow_daddr_v6",
				"type ipv6_addr",
				"ip6 daddr",
				"icmpv6 type echo-request",
			},
		},
		{
			name:      "dns mode with v6 allowlist",
			v4:        []string{"8.8.8.8"},
			v6:        []string{"2001:4860:4860::8888"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   5353,
			mode:      "dns",
			expectedContains: []string{
				"table ip g0efilter_v4",
				"table ip6 g0efilter_v6",
				"table ip6 g0efilter_nat_v6",
				"allow_daddr_v6",
				"type ipv6_addr",
				"ip6 daddr ::1",
			},
		},
		{
			// With no IPv6 IPs in the policy, ::1 is used as a placeholder so the
			// allow_daddr_v6 set is never empty. Traffic is redirected through the
			// proxy (which enforces domain policy) rather than blanket-dropped.
			name:      "v4 only uses ::1 placeholder for v6 proxy redirect",
			v4:        []string{"1.1.1.1"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "https",
			expectedContains: []string{
				"table ip6 g0efilter_v6",
				"policy drop",
				"allow_daddr_v6",
				"::1",
				"table ip6 g0efilter_nat_v6",
			},
		},
	}
}

func TestParseNflogConfig(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getParseNflogConfigTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.bufsize != "" {
				t.Setenv("NFLOG_BUFSIZE", tt.bufsize)
			}

			if tt.qthresh != "" {
				t.Setenv("NFLOG_QTHRESH", tt.qthresh)
			}

			bufsize, qthresh := parseNflogConfig()

			if int(bufsize) != tt.expectedBufsize {
				t.Errorf("parseNflogConfig() bufsize = %d, want %d", bufsize, tt.expectedBufsize)
			}

			if int(qthresh) != tt.expectedQthresh {
				t.Errorf("parseNflogConfig() qthresh = %d, want %d", qthresh, tt.expectedQthresh)
			}
		})
	}
}

func getParseNflogConfigTests() []struct {
	name            string
	bufsize         string
	qthresh         string
	expectedBufsize int
	expectedQthresh int
} {
	return []struct {
		name            string
		bufsize         string
		qthresh         string
		expectedBufsize int
		expectedQthresh int
	}{
		{
			name:            "default values",
			bufsize:         "",
			qthresh:         "",
			expectedBufsize: 96,
			expectedQthresh: 50,
		},
		{
			name:            "custom values",
			bufsize:         "128",
			qthresh:         "100",
			expectedBufsize: 128,
			expectedQthresh: 100,
		},
		{
			name:            "invalid values use defaults",
			bufsize:         "invalid",
			qthresh:         "invalid",
			expectedBufsize: 96,
			expectedQthresh: 50,
		},
		{
			name:            "zero values use defaults",
			bufsize:         "0",
			qthresh:         "0",
			expectedBufsize: 96,
			expectedQthresh: 50,
		},
	}
}

func TestSetupLogger(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getSetupLoggerTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.hostname != "" {
				t.Setenv("HOSTNAME", tt.hostname)
			}

			if tt.tenantID != "" {
				t.Setenv("TENANT_ID", tt.tenantID)
			}

			logger := slog.Default()
			result := setupLogger(logger)

			if result == nil {
				t.Error("setupLogger() returned nil logger")
			}
		})
	}
}

func getSetupLoggerTests() []struct {
	name     string
	hostname string
	tenantID string
} {
	return []struct {
		name     string
		hostname string
		tenantID string
	}{
		{
			name:     "no environment variables",
			hostname: "",
			tenantID: "",
		},
		{
			name:     "with hostname",
			hostname: "test-host",
			tenantID: "",
		},
		{
			name:     "with tenant id",
			hostname: "",
			tenantID: "test-tenant",
		},
		{
			name:     "with both hostname and tenant id",
			hostname: "test-host",
			tenantID: "test-tenant",
		},
	}
}

func TestMapPrefixToAction(t *testing.T) {
	t.Parallel()

	tests := getMapPrefixToActionTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := mapPrefixToAction(tt.prefix)

			if result != tt.expected {
				t.Errorf("mapPrefixToAction(%q) = %q, want %q", tt.prefix, result, tt.expected)
			}
		})
	}
}

func getMapPrefixToActionTests() []struct {
	name     string
	prefix   string
	expected string
} {
	return []struct {
		name     string
		prefix   string
		expected string
	}{
		{
			name:     "redirect prefix",
			prefix:   "redirected",
			expected: "REDIRECTED",
		},
		{
			name:     "redirect uppercase",
			prefix:   "REDIRECT",
			expected: "REDIRECTED",
		},
		{
			name:     "blocked prefix",
			prefix:   "blocked",
			expected: "BLOCKED",
		},
		{
			name:     "block prefix",
			prefix:   "block",
			expected: "BLOCKED",
		},
		{
			name:     "allowed prefix",
			prefix:   "allowed",
			expected: "ALLOWED",
		},
		{
			name:     "allow prefix",
			prefix:   "allow",
			expected: "ALLOWED",
		},
		{
			name:     "unknown prefix",
			prefix:   "unknown",
			expected: "",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			expected: "",
		},
	}
}

func TestBuildLogFields(t *testing.T) {
	t.Parallel()

	tests := getBuildLogFieldsTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fields := buildLogFields(
				tt.src, tt.dst, tt.proto, tt.sourceIP, tt.destinationIP,
				tt.flowID, tt.sourcePort, tt.destinationPort, tt.payloadLen,
			)

			validateBasicFields(t, fields)
			fieldMap := convertFieldsToMap(t, fields)
			validateRequiredFields(t, fieldMap)
			validateConditionalFields(t, fieldMap, tt)
		})
	}
}

func validateBasicFields(t *testing.T, fields []any) {
	t.Helper()

	// Check that we got a slice of fields
	if len(fields) == 0 {
		t.Error("buildLogFields() returned empty fields")
	}

	// Check that fields come in key-value pairs
	if len(fields)%2 != 0 {
		t.Error("buildLogFields() returned odd number of fields (should be key-value pairs)")
	}
}

func convertFieldsToMap(t *testing.T, fields []any) map[string]any {
	t.Helper()

	fieldMap := make(map[string]any)

	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			t.Errorf("buildLogFields() field key at index %d is not a string", i)

			continue
		}

		value := fields[i+1]
		fieldMap[key] = value
	}

	return fieldMap
}

func validateRequiredFields(t *testing.T, fieldMap map[string]any) {
	t.Helper()

	requiredFields := []string{"protocol", "payload_len"}
	for _, field := range requiredFields {
		if _, exists := fieldMap[field]; !exists {
			t.Errorf("buildLogFields() missing '%s' field", field)
		}
	}
}

func validateConditionalFields(t *testing.T, fieldMap map[string]any, tt struct {
	name            string
	src             string
	dst             string
	proto           string
	sourceIP        string
	destinationIP   string
	flowID          string
	sourcePort      int
	destinationPort int
	payloadLen      int
},
) {
	t.Helper()

	optional := []struct {
		key     string
		present bool
	}{
		{"src", tt.src != ""},
		{"dst", tt.dst != ""},
		{"source_ip", tt.sourceIP != ""},
		{"destination_ip", tt.destinationIP != ""},
		{"source_port", tt.sourcePort != 0},
		{"destination_port", tt.destinationPort != 0},
		{"flow_id", tt.flowID != ""},
	}

	for _, o := range optional {
		_, exists := fieldMap[o.key]

		if o.present && !exists {
			t.Errorf("buildLogFields() missing expected field %q", o.key)
		}

		if !o.present && exists {
			t.Errorf("buildLogFields() has unexpected field %q", o.key)
		}
	}
}

func getBuildLogFieldsTests() []struct {
	name            string
	src             string
	dst             string
	proto           string
	sourceIP        string
	destinationIP   string
	flowID          string
	sourcePort      int
	destinationPort int
	payloadLen      int
} {
	return []struct {
		name            string
		src             string
		dst             string
		proto           string
		sourceIP        string
		destinationIP   string
		flowID          string
		sourcePort      int
		destinationPort int
		payloadLen      int
	}{
		{
			name:            "complete fields",
			src:             "192.168.1.1:80",
			dst:             "192.168.1.2:8080",
			proto:           "TCP",
			sourceIP:        "192.168.1.1",
			destinationIP:   "192.168.1.2",
			flowID:          "test-flow-id",
			sourcePort:      80,
			destinationPort: 8080,
			payloadLen:      1500,
		},
		{
			name:       "minimal fields",
			src:        "",
			dst:        "",
			proto:      "ICMP",
			payloadLen: 64,
		},
		{
			name:            "no ports",
			src:             "192.168.1.1",
			dst:             "192.168.1.2",
			proto:           "ICMP",
			sourceIP:        "192.168.1.1",
			destinationIP:   "192.168.1.2",
			sourcePort:      0,
			destinationPort: 0,
			payloadLen:      64,
		},
	}
}

func TestCreateNflogHook(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	hook := createNflogHook(logger)

	if hook == nil {
		t.Error("createNflogHook() returned nil hook")
	}

	// Test hook with minimal attributes
	attrs := nflog.Attribute{}
	result := hook(attrs)

	// Hook should return 0 (continue processing)
	if result != 0 {
		t.Errorf("createNflogHook() hook returned %d, want 0", result)
	}
}

func TestStreamNfLogWithLogger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nflog stream test in short mode")
	}

	t.Parallel()

	// Create a context that will be cancelled after 100ms
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	logger := slog.Default()
	err := StreamNfLogWithLogger(ctx, logger)

	// In test environment without nflog support, we expect an error from nflog.Open()
	// The function should fail fast at startup, not hang
	if err == nil {
		t.Error("StreamNfLogWithLogger() expected error in test environment without nflog, got nil")
	}

	// Verify error is about nflog open failure, not context timeout
	if err != nil && !strings.Contains(err.Error(), "nflog open failed") {
		t.Logf("Got error (expected): %v", err)
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Test that constants have expected values
	if actions.ActionRedirected != "REDIRECTED" {
		t.Errorf("Expected ActionRedirected to be 'REDIRECTED', got %s", actions.ActionRedirected)
	}

	if actions.ModeHTTPS != "https" {
		t.Errorf("Expected ModeHTTPS to be 'https', got %s", actions.ModeHTTPS)
	}

	if actions.ModeDNS != "dns" {
		t.Errorf("Expected ModeDNS to be 'dns', got %s", actions.ModeDNS)
	}

	if minPacketSize != 20 {
		t.Errorf("Expected minPacketSize to be 20, got %d", minPacketSize)
	}
}

func TestErrPortOutOfRange(t *testing.T) {
	t.Parallel()

	if errPortOutOfRange == nil {
		t.Error("errPortOutOfRange should not be nil")
	}

	expectedMsg := "port out of range"
	if errPortOutOfRange.Error() != expectedMsg {
		t.Errorf("errPortOutOfRange.Error() = %q, want %q", errPortOutOfRange.Error(), expectedMsg)
	}
}

// Test functions with 0% coverage.
func TestApplyRuleset(t *testing.T) {
	t.Parallel()

	// Test with simple ruleset (will fail in test environment but shouldn't panic)
	ruleset := `
table ip test_table {
	chain test_chain {
		type filter hook forward priority 0;
		accept
	}
}
`

	err := applyRuleset(context.Background(), ruleset)

	// We expect an error since nft command likely isn't available in test environment
	// Just verify the function doesn't panic and handles the command execution
	if err == nil {
		t.Log("applyRuleset() unexpectedly succeeded (might have nft available)")
	} else {
		t.Logf("applyRuleset() failed as expected: %v", err)
	}
}

func TestAtomicReplacePreamble(t *testing.T) {
	t.Parallel()

	for _, table := range []string{
		"ip g0efilter_v4", "ip g0efilter_nat_v4",
		"ip6 g0efilter_v6", "ip6 g0efilter_nat_v6",
	} {
		declare := strings.Index(atomicReplacePreamble, "table "+table+"\n")
		remove := strings.Index(atomicReplacePreamble, "delete table "+table+"\n")

		if declare == -1 || remove == -1 || remove < declare {
			t.Errorf("preamble must declare then delete table %s", table)
		}
	}
}

func TestParsePacketInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		payload     []byte
		expectSrc   string
		expectDst   string
		expectProto string
	}{
		{
			name:        "empty payload",
			payload:     []byte{},
			expectSrc:   "",
			expectDst:   "",
			expectProto: "",
		},
		{
			name:        "invalid payload",
			payload:     []byte{0x01, 0x02, 0x03},
			expectSrc:   "",
			expectDst:   "",
			expectProto: "",
		},
		{
			name:        "valid IPv4 TCP SYN packet",
			payload:     buildIPv4TCPPacket(t),
			expectSrc:   "10.0.0.1:12345",
			expectDst:   "10.0.0.2:443",
			expectProto: "TCP",
		},
		{
			name:        "valid IPv6 TCP SYN packet",
			payload:     buildIPv6TCPPacket(t),
			expectSrc:   "2001:db8::1:12345",
			expectDst:   "2001:db8::2:443",
			expectProto: "TCP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkt := parsePacketInfo(tt.payload)

			if pkt.Src != tt.expectSrc || pkt.Dst != tt.expectDst || pkt.Protocol != tt.expectProto {
				t.Errorf("parsePacketInfo() = src:%s, dst:%s, proto:%s, want src:%s, dst:%s, proto:%s",
					pkt.Src, pkt.Dst, pkt.Protocol, tt.expectSrc, tt.expectDst, tt.expectProto)
			}
		})
	}
}

// buildIPv4TCPPacket constructs a minimal IPv4+TCP packet for testing.
func buildIPv4TCPPacket(t *testing.T) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
	}

	_ = tcp.SetNetworkLayerForChecksum(ipv4)

	err := gopacket.SerializeLayers(buf, opts, ipv4, tcp)
	if err != nil {
		t.Fatalf("failed to serialize IPv4 TCP packet: %v", err)
	}

	return buf.Bytes()
}

// buildIPv6TCPPacket constructs a minimal IPv6+TCP packet for testing.
func buildIPv6TCPPacket(t *testing.T) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ipv6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
	}

	_ = tcp.SetNetworkLayerForChecksum(ipv6)

	err := gopacket.SerializeLayers(buf, opts, ipv6, tcp)
	if err != nil {
		t.Fatalf("failed to serialize IPv6 TCP packet: %v", err)
	}

	return buf.Bytes()
}

func TestSplitByFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowlist  []string
		expectedV4 []string
		expectedV6 []string
	}{
		{
			name:       "only IPv4",
			allowlist:  []string{"1.1.1.1", "10.0.0.0/8"},
			expectedV4: []string{"1.1.1.1", "10.0.0.0/8"},
			expectedV6: nil,
		},
		{
			name:       "only IPv6",
			allowlist:  []string{"2001:db8::1", "2606:4700::/32"},
			expectedV4: nil,
			expectedV6: []string{"2001:db8::1", "2606:4700::/32"},
		},
		{
			name:       "mixed",
			allowlist:  []string{"1.1.1.1", "2001:db8::1", "10.0.0.0/8", "fd00::/8"},
			expectedV4: []string{"1.1.1.1", "10.0.0.0/8"},
			expectedV6: []string{"2001:db8::1", "fd00::/8"},
		},
		{
			name:       "empty allowlist",
			allowlist:  []string{},
			expectedV4: nil,
			expectedV6: nil,
		},
		{
			name:       "invalid entries skipped",
			allowlist:  []string{"1.1.1.1", "not-an-ip", "2001:db8::1"},
			expectedV4: []string{"1.1.1.1"},
			expectedV6: []string{"2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v4, v6 := splitByFamily(tt.allowlist)

			if !slicesEqualOrBothNil(v4, tt.expectedV4) {
				t.Errorf("splitByFamily() v4 = %v, want %v", v4, tt.expectedV4)
			}

			if !slicesEqualOrBothNil(v6, tt.expectedV6) {
				t.Errorf("splitByFamily() v6 = %v, want %v", v6, tt.expectedV6)
			}
		})
	}
}

func slicesEqualOrBothNil(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// BLOCKED nflog events log at WARN so they survive LOG_LEVEL=WARN.
//
//nolint:exhaustruct
func TestProcessActionEventLevels(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	pkt := PacketInfo{Src: "10.0.0.1:1234", Dst: "1.2.3.4:443", Protocol: "TCP"}

	processActionEvent(logger, "BLOCKED", "flow-1", pkt, 64)

	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Errorf("BLOCKED nflog event must log at WARN, got: %s", buf.String())
	}

	buf.Reset()
	processActionEvent(logger, "ALLOWED", "flow-2", pkt, 64)

	if buf.Len() != 0 {
		t.Errorf("ALLOWED nflog event must stay at DEBUG (filtered at INFO), got: %s", buf.String())
	}
}

func TestProcessActionEvent(t *testing.T) {
	t.Parallel()

	tests := getProcessActionEventTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := slog.Default()

			// This function just logs, so we call it to exercise the code path
			processActionEvent(logger, tt.action, tt.flowID, tt.pkt, tt.payloadLen)

			// If we reach here without panic, the test passes
			t.Logf("processActionEvent() completed for action %s", tt.action)
		})
	}
}

type processActionEventTest struct {
	name       string
	action     string
	flowID     string
	pkt        PacketInfo
	payloadLen int
}

func getProcessActionEventTests() []processActionEventTest {
	return []processActionEventTest{
		{
			name:   "redirected action",
			action: "REDIRECTED",
			flowID: "test-flow-1",
			pkt: PacketInfo{
				Src: "192.168.1.1:80", Dst: "192.168.1.2:8080",
				Protocol: "TCP", SourceIP: "192.168.1.1", DestinationIP: "192.168.1.2",
				SourcePort: 80, DestinationPort: 8080,
			},
			payloadLen: 1500,
		},
		{
			name:   "blocked action",
			action: "BLOCKED",
			flowID: "test-flow-2",
			pkt: PacketInfo{
				Src: "192.168.1.1:53", Dst: "8.8.8.8:53",
				Protocol: "UDP", SourceIP: "192.168.1.1", DestinationIP: "8.8.8.8",
				SourcePort: 53, DestinationPort: 53,
			},
			payloadLen: 512,
		},
		{
			name:   "allowed action",
			action: "ALLOWED",
			pkt: PacketInfo{
				Src: "10.0.0.1", Dst: "10.0.0.2",
				Protocol: "ICMP", SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2",
			},
			payloadLen: 64,
		},
	}
}
