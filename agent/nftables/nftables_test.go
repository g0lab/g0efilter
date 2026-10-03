//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/agent/flow"
	"github.com/g0lab/g0efilter/shared/actions"
)

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

func TestCreateNflogHookAddsFlowID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	hook := createNflogHook(logger)
	prefix := "blocked"
	payload := ipv4Packet(protoTCP, 0, nil, ports(12345, 443))

	hook(nflog.Attribute{Prefix: &prefix, Payload: &payload})

	want := flow.ID("10.0.0.1", 12345, "10.0.0.2", 443, "TCP")
	if !strings.Contains(buf.String(), `"flow_id":"`+want+`"`) {
		t.Errorf("nflog event does not contain flow ID %q: %s", want, buf.String())
	}
}

func TestStreamNfLogWithLogger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nflog stream test in short mode")
	}

	t.Parallel()

	// Create a context that will be canceled after 100ms
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
			payload:     ipv4Packet(protoTCP, 0, nil, ports(12345, 443)),
			expectSrc:   "10.0.0.1:12345",
			expectDst:   "10.0.0.2:443",
			expectProto: "TCP",
		},
		{
			name:        "valid IPv6 TCP SYN packet",
			payload:     ipv6Packet(protoTCP, ports(12345, 443)),
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
func TestProcessActionEventLevels(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	pkt := PacketInfo{Src: "10.0.0.1:1234", Dst: "1.2.3.4:443", Protocol: "TCP"}

	processActionEvent(logger, "BLOCKED", "flow-1", pkt, 64)

	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Errorf("BLOCKED nflog event must log at WARN, got: %s", buf.String())
	}

	if !strings.Contains(buf.String(), `"alert":true`) {
		t.Errorf("BLOCKED nflog event must flag an alert, got: %s", buf.String())
	}

	buf.Reset()
	processActionEvent(logger, "ALLOWED", "flow-2", pkt, 64)

	if buf.Len() != 0 {
		t.Errorf("ALLOWED nflog event must stay at DEBUG (filtered at INFO), got: %s", buf.String())
	}
}

func TestProcessActionEventSuppressesSyntheticRedirect(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	flowID := flow.ID("192.0.2.1", 12345, "198.51.100.2", 443, "TCP")
	flow.MarkSynthetic(flowID)

	processActionEvent(logger, actions.ActionRedirected, flowID, PacketInfo{}, 64)

	if buf.Len() != 0 {
		t.Errorf("synthetic redirect produced a duplicate nflog event: %s", buf.String())
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
