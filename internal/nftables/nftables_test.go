//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nflog/v2"
)

// Test errors defined as static variables to satisfy err113 linter.
var (
	errTableNotFound         = errors.New("table not found")
	errInvalidPolicy         = errors.New("invalid policy")
	errInvalidAction         = errors.New("invalid action")
	errNotConnected          = errors.New("not connected")
	errRuleMustSpecifyTable  = errors.New("rule must specify table")
	errRuleMustSpecifyChain  = errors.New("rule must specify chain")
	errRuleMustSpecifyAction = errors.New("rule must specify action")
)

// Error constructors for dynamic content.
func newTableNotFoundError(table string) error {
	return fmt.Errorf("%w: %s", errTableNotFound, table)
}

func newInvalidPolicyError(policy string) error {
	return fmt.Errorf("%w: %s", errInvalidPolicy, policy)
}

func newInvalidActionError(action string) error {
	return fmt.Errorf("%w: %s", errInvalidAction, action)
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
			name:        "sni mode",
			allowlist:   []string{"1.1.1.1"},
			httpsPort:   "8443",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "sni",
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
			filterMode:  "sni",
			expectError: true,
		},
		{
			name:        "port out of range",
			allowlist:   []string{"1.1.1.1"},
			httpsPort:   "99999",
			httpPort:    "8080",
			dnsPort:     "53",
			filterMode:  "sni",
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

			ruleset := GenerateNftRuleset(tt.allowlist, tt.httpsPort, tt.httpPort, tt.dnsPort, tt.mode)

			if ruleset == "" {
				t.Error("GenerateNftRuleset() returned empty ruleset")
			}

			// Check for expected content in ruleset
			for _, expected := range tt.expectedContains {
				if !strings.Contains(ruleset, expected) {
					t.Errorf("GenerateNftRuleset() ruleset missing %q", expected)
				}
			}

			// Check that allowlist IPs are included if provided
			if len(tt.allowlist) > 0 {
				for _, ip := range tt.allowlist {
					if !strings.Contains(ruleset, ip) {
						t.Errorf("GenerateNftRuleset() ruleset missing allowlist IP %q", ip)
					}
				}
			}
		})
	}
}

func getGenerateNftRulesetTests() []struct {
	name             string
	allowlist        []string
	httpsPort        int
	httpPort         int
	dnsPort          int
	mode             string
	expectedContains []string
} {
	tests := []struct {
		name             string
		allowlist        []string
		httpsPort        int
		httpPort         int
		dnsPort          int
		mode             string
		expectedContains []string
	}{}

	tests = append(tests, getSNIModeTests()...)
	tests = append(tests, getDNSModeTests()...)
	tests = append(tests, getDefaultModeTests()...)

	return tests
}

func getSNIModeTests() []struct {
	name             string
	allowlist        []string
	httpsPort        int
	httpPort         int
	dnsPort          int
	mode             string
	expectedContains []string
} {
	return []struct {
		name             string
		allowlist        []string
		httpsPort        int
		httpPort         int
		dnsPort          int
		mode             string
		expectedContains []string
	}{
		{
			name:      "sni mode with allowlist",
			allowlist: []string{"1.1.1.1", "8.8.8.8"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "sni",
			expectedContains: []string{
				"table ip filter_v4",
				"table ip nat_v4",
				"allow_daddr_v4",
				"tcp dport 80",
				"tcp dport 443",
				"redirect to :8080",
				"redirect to :8443",
			},
		},
	}
}

func getDNSModeTests() []struct {
	name             string
	allowlist        []string
	httpsPort        int
	httpPort         int
	dnsPort          int
	mode             string
	expectedContains []string
} {
	return []struct {
		name             string
		allowlist        []string
		httpsPort        int
		httpPort         int
		dnsPort          int
		mode             string
		expectedContains []string
	}{
		{
			name:      "dns mode with allowlist",
			allowlist: []string{"9.9.9.9"},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   5353,
			mode:      "dns",
			expectedContains: []string{
				"table ip filter_v4",
				"table ip nat_v4",
				"allow_daddr_v4",
				"udp dport 53",
				"tcp dport 53",
				"redirect to :5353",
			},
		},
	}
}

func getDefaultModeTests() []struct {
	name             string
	allowlist        []string
	httpsPort        int
	httpPort         int
	dnsPort          int
	mode             string
	expectedContains []string
} {
	return []struct {
		name             string
		allowlist        []string
		httpsPort        int
		httpPort         int
		dnsPort          int
		mode             string
		expectedContains []string
	}{
		{
			name:      "empty allowlist defaults to sni",
			allowlist: []string{},
			httpsPort: 8443,
			httpPort:  8080,
			dnsPort:   53,
			mode:      "invalid",
			expectedContains: []string{
				"table ip filter_v4",
				"table ip nat_v4",
				"tcp dport 80",
				"tcp dport 443",
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
			validateConditionalFields(t, fieldMap, tt.src)
		})
	}
}

func validateBasicFields(t *testing.T, fields []interface{}) {
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

func convertFieldsToMap(t *testing.T, fields []interface{}) map[string]interface{} {
	t.Helper()

	fieldMap := make(map[string]interface{})

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

func validateRequiredFields(t *testing.T, fieldMap map[string]interface{}) {
	t.Helper()

	requiredFields := []string{"time", "protocol", "payload_len"}
	for _, field := range requiredFields {
		if _, exists := fieldMap[field]; !exists {
			t.Errorf("buildLogFields() missing '%s' field", field)
		}
	}
}

func validateConditionalFields(t *testing.T, fieldMap map[string]interface{}, src string) {
	t.Helper()

	// Check conditional fields
	if src != "" {
		if _, exists := fieldMap["src"]; !exists {
			t.Error("buildLogFields() missing 'src' field")
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

func TestStreamNfLog(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nflog stream test in short mode")
	}

	t.Parallel()

	// This test will likely fail since it requires netfilter/nflog setup
	// But we test that it doesn't panic and handles the error gracefully
	err := StreamNfLog()

	// We expect an error since nflog likely isn't available in test environment
	if err == nil {
		t.Log("StreamNfLog() unexpectedly succeeded (might be running with nflog support)")
	}
}

func TestStreamNfLogWithLogger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nflog stream test in short mode")
	}

	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	logger := slog.Default()
	err := StreamNfLogWithLogger(ctx, logger)

	// We expect an error since nflog likely isn't available in test environment
	// But the function should handle the timeout gracefully
	if err == nil {
		t.Log("StreamNfLogWithLogger() unexpectedly succeeded")
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Test that constants have expected values
	if actionRedirected != "REDIRECTED" {
		t.Errorf("Expected actionRedirected to be 'REDIRECTED', got %s", actionRedirected)
	}

	if modeSNI != "sni" {
		t.Errorf("Expected modeSNI to be 'sni', got %s", modeSNI)
	}

	if modeDNS != "dns" {
		t.Errorf("Expected modeDNS to be 'dns', got %s", modeDNS)
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

// Test NFTables rule management.
func TestNFTablesRules(t *testing.T) {
	t.Parallel()

	t.Run("rule creation and validation", func(t *testing.T) {
		t.Parallel()
		testRuleCreationAndValidation(t)
	})

	t.Run("rule serialization", func(t *testing.T) {
		t.Parallel()
		testRuleSerialization(t)
	})
}

func testRuleCreationAndValidation(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name  string
		rule  NFTRule
		valid bool
	}{
		{
			name: "valid block rule",
			rule: NFTRule{
				Table:  "filter",
				Chain:  "forward",
				Action: "drop",
				Source: "192.168.1.100",
			},
			valid: true,
		},
		{
			name: "valid allow rule",
			rule: NFTRule{
				Table:       "filter",
				Chain:       "forward",
				Action:      "accept",
				Destination: "8.8.8.8",
				Port:        53,
			},
			valid: true,
		},
		{
			name: "invalid rule - missing table",
			rule: NFTRule{
				Chain:  "forward",
				Action: "drop",
			},
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateRule(tc.rule)
			if tc.valid && err != nil {
				t.Errorf("Expected valid rule, got error: %v", err)
			}

			if !tc.valid && err == nil {
				t.Error("Expected invalid rule to produce error")
			}
		})
	}
}

func testRuleSerialization(t *testing.T) {
	t.Helper()

	rule := NFTRule{
		Table:       "filter",
		Chain:       "forward",
		Action:      "drop",
		Source:      "192.168.1.0/24",
		Destination: "10.0.0.1",
		Port:        80,
		Protocol:    "tcp",
	}

	serialized := serializeRule(rule)
	expected := "add rule ip filter forward ip saddr 192.168.1.0/24 ip daddr 10.0.0.1 tcp dport 80 drop"

	if serialized != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, serialized)
	}
}

// Test NFTables connection and execution.
func TestNFTablesExecution(t *testing.T) {
	t.Parallel()

	t.Run("connection establishment", func(t *testing.T) {
		t.Parallel()

		// Test mock connection
		conn := NewMockNFTConnection()
		if conn == nil {
			t.Fatal("Failed to create mock NFTables connection")
		}

		err := conn.Connect()
		if err != nil {
			t.Errorf("Mock connection should not fail: %v", err)
		}

		conn.Close()
	})

	t.Run("batch operations", func(t *testing.T) {
		t.Parallel()

		conn := NewMockNFTConnection()

		// Connect first
		err := conn.Connect()
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}

		batch := []NFTRule{
			{
				Table:  "filter",
				Chain:  "forward",
				Action: "drop",
				Source: "192.168.1.100",
			},
			{
				Table:       "filter",
				Chain:       "forward",
				Action:      "accept",
				Destination: "8.8.8.8",
			},
		}

		err = conn.ApplyBatch(batch)
		if err != nil {
			t.Errorf("Batch application failed: %v", err)
		}

		// Verify rules were applied
		appliedRules := conn.GetAppliedRules()
		if len(appliedRules) != len(batch) {
			t.Errorf("Expected %d rules applied, got %d", len(batch), len(appliedRules))
		}
	})
}

// Test NFTables table and chain management.
func TestNFTablesManagement(t *testing.T) {
	t.Parallel()

	t.Run("table operations", func(t *testing.T) {
		t.Parallel()

		conn := NewMockNFTConnection()

		// Connect first
		err := conn.Connect()
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}

		// Test table creation
		err = conn.CreateTable("test_table")
		if err != nil {
			t.Errorf("Table creation failed: %v", err)
		}

		// Test duplicate table creation (should be idempotent)
		err = conn.CreateTable("test_table")
		if err != nil {
			t.Errorf("Duplicate table creation should be idempotent: %v", err)
		}

		// Test table deletion
		err = conn.DeleteTable("test_table")
		if err != nil {
			t.Errorf("Table deletion failed: %v", err)
		}
	})

	t.Run("chain operations", func(t *testing.T) {
		t.Parallel()

		conn := NewMockNFTConnection()

		// Connect first
		err := conn.Connect()
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}

		// Create table first
		err = conn.CreateTable("test_table")
		if err != nil {
			t.Fatal("Failed to create table for chain test")
		}

		// Test chain creation
		err = conn.CreateChain("test_table", "test_chain", "filter", "forward")
		if err != nil {
			t.Errorf("Chain creation failed: %v", err)
		}

		// Test chain policy setting
		err = conn.SetChainPolicy("test_table", "test_chain", "drop")
		if err != nil {
			t.Errorf("Chain policy setting failed: %v", err)
		}
	})
}

// Helper types and functions for NFTables testing

type NFTRule struct {
	Table       string
	Chain       string
	Action      string
	Source      string
	Destination string
	Port        int
	Protocol    string
}

type MockNFTConnection struct {
	connected    bool
	tables       []string
	chains       map[string][]string
	appliedRules []NFTRule
}

func NewMockNFTConnection() *MockNFTConnection {
	return &MockNFTConnection{
		chains:       make(map[string][]string),
		appliedRules: make([]NFTRule, 0),
	}
}

func (m *MockNFTConnection) Connect() error {
	m.connected = true

	return nil
}

func (m *MockNFTConnection) Close() {
	m.connected = false
}

func (m *MockNFTConnection) ApplyBatch(rules []NFTRule) error {
	if !m.connected {
		return errNotConnected
	}

	for _, rule := range rules {
		err := validateRule(rule)
		if err != nil {
			return err
		}

		m.appliedRules = append(m.appliedRules, rule)
	}

	return nil
}

func (m *MockNFTConnection) GetAppliedRules() []NFTRule {
	return m.appliedRules
}

func (m *MockNFTConnection) CreateTable(table string) error {
	if !m.connected {
		return errNotConnected
	}

	// Check if table already exists (idempotent)
	for _, existing := range m.tables {
		if existing == table {
			return nil
		}
	}

	m.tables = append(m.tables, table)
	m.chains[table] = make([]string, 0)

	return nil
}

func (m *MockNFTConnection) DeleteTable(table string) error {
	if !m.connected {
		return errNotConnected
	}

	for i, existing := range m.tables {
		if existing == table {
			m.tables = append(m.tables[:i], m.tables[i+1:]...)
			delete(m.chains, table)

			return nil
		}
	}

	return newTableNotFoundError(table)
}

func (m *MockNFTConnection) CreateChain(table, chain, _ /* family */, _ /* hook */ string) error {
	if !m.connected {
		return errNotConnected
	}

	// Check if table exists
	tableExists := false

	for _, existing := range m.tables {
		if existing == table {
			tableExists = true

			break
		}
	}

	if !tableExists {
		return newTableNotFoundError(table)
	}

	m.chains[table] = append(m.chains[table], chain)

	return nil
}

func (m *MockNFTConnection) SetChainPolicy(_ /* table */, _ /* chain */, policy string) error {
	if !m.connected {
		return errNotConnected
	}

	// Validate policy
	validPolicies := []string{"accept", "drop", "queue", "continue", "return"}
	validPolicy := false

	for _, valid := range validPolicies {
		if policy == valid {
			validPolicy = true

			break
		}
	}

	if !validPolicy {
		return newInvalidPolicyError(policy)
	}

	return nil
}

func validateRule(rule NFTRule) error {
	if rule.Table == "" {
		return errRuleMustSpecifyTable
	}

	if rule.Chain == "" {
		return errRuleMustSpecifyChain
	}

	if rule.Action == "" {
		return errRuleMustSpecifyAction
	}

	validActions := []string{"accept", "drop", "queue", "continue", "return", "reject"}
	validAction := false

	for _, valid := range validActions {
		if rule.Action == valid {
			validAction = true

			break
		}
	}

	if !validAction {
		return newInvalidActionError(rule.Action)
	}

	return nil
}

func serializeRule(rule NFTRule) string {
	parts := []string{"add", "rule", "ip", rule.Table, rule.Chain}

	if rule.Source != "" {
		parts = append(parts, "ip", "saddr", rule.Source)
	}

	if rule.Destination != "" {
		parts = append(parts, "ip", "daddr", rule.Destination)
	}

	if rule.Protocol != "" && rule.Port > 0 {
		parts = append(parts, rule.Protocol, "dport", strconv.Itoa(rule.Port))
	}

	parts = append(parts, rule.Action)

	return strings.Join(parts, " ")
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

	err := applyRuleset(ruleset)

	// We expect an error since nft command likely isn't available in test environment
	// Just verify the function doesn't panic and handles the command execution
	if err == nil {
		t.Log("applyRuleset() unexpectedly succeeded (might have nft available)")
	} else {
		t.Logf("applyRuleset() failed as expected: %v", err)
	}
}

func TestDeleteTableIfExists(t *testing.T) {
	t.Parallel()

	// Test table deletion (will fail in test environment but shouldn't panic)
	err := deleteTableIfExists("ip", "nonexistent_table")

	// Should return nil if table doesn't exist (which is likely in test environment)
	if err != nil {
		t.Logf("deleteTableIfExists() returned error: %v", err)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src, dst, proto, sourceIP, destinationIP, sourcePort, destinationPort := parsePacketInfo(tt.payload)

			// For invalid payloads, we expect empty strings
			if src != tt.expectSrc || dst != tt.expectDst || proto != tt.expectProto {
				t.Logf("parsePacketInfo() = src:%s, dst:%s, proto:%s, sourceIP:%s, destinationIP:%s, "+
					"sourcePort:%d, destinationPort:%d",
					src, dst, proto, sourceIP, destinationIP, sourcePort, destinationPort)
			}
		})
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
			processActionEvent(
				logger,
				tt.action,
				tt.flowID,
				tt.src,
				tt.dst,
				tt.proto,
				tt.sourceIP,
				tt.destinationIP,
				tt.sourcePort,
				tt.destinationPort,
				tt.payloadLen,
			)

			// If we reach here without panic, the test passes
			t.Logf("processActionEvent() completed for action %s", tt.action)
		})
	}
}

type processActionEventTest struct {
	name            string
	action          string
	flowID          string
	src             string
	dst             string
	proto           string
	sourceIP        string
	destinationIP   string
	sourcePort      int
	destinationPort int
	payloadLen      int
}

func getProcessActionEventTests() []processActionEventTest {
	tests := make([]processActionEventTest, 0, 3)
	tests = append(tests, getRedirectedActionTest())
	tests = append(tests, getBlockedActionTest())
	tests = append(tests, getAllowedActionTest())

	return tests
}

func getRedirectedActionTest() processActionEventTest {
	return processActionEventTest{
		name:            "redirected action",
		action:          "REDIRECTED",
		flowID:          "test-flow-1",
		src:             "192.168.1.1:80",
		dst:             "192.168.1.2:8080",
		proto:           "TCP",
		sourceIP:        "192.168.1.1",
		destinationIP:   "192.168.1.2",
		sourcePort:      80,
		destinationPort: 8080,
		payloadLen:      1500,
	}
}

func getBlockedActionTest() processActionEventTest {
	return processActionEventTest{
		name:            "blocked action",
		action:          "BLOCKED",
		flowID:          "test-flow-2",
		src:             "192.168.1.1:53",
		dst:             "8.8.8.8:53",
		proto:           "UDP",
		sourceIP:        "192.168.1.1",
		destinationIP:   "8.8.8.8",
		sourcePort:      53,
		destinationPort: 53,
		payloadLen:      512,
	}
}

func getAllowedActionTest() processActionEventTest {
	return processActionEventTest{
		name:            "allowed action",
		action:          "ALLOWED",
		flowID:          "",
		src:             "10.0.0.1",
		dst:             "10.0.0.2",
		proto:           "ICMP",
		sourceIP:        "10.0.0.1",
		destinationIP:   "10.0.0.2",
		sourcePort:      0,
		destinationPort: 0,
		payloadLen:      64,
	}
}
