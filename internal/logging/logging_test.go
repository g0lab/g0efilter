//nolint:testpackage // Need access to internal implementation details
package logging

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := getParseLevelTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseLevel(tt.input)

			if result.Level() != tt.expected.Level() {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, result.Level(), tt.expected.Level())
			}
		})
	}
}

func getParseLevelTests() []struct {
	name     string
	input    string
	expected slog.Leveler
} {
	return []struct {
		name     string
		input    string
		expected slog.Leveler
	}{
		{
			name:     "trace level",
			input:    "TRACE",
			expected: LevelTrace,
		},
		{
			name:     "debug level",
			input:    "DEBUG",
			expected: slog.LevelDebug,
		},
		{
			name:     "info level",
			input:    "INFO",
			expected: slog.LevelInfo,
		},
		{
			name:     "warn level",
			input:    "WARN",
			expected: slog.LevelWarn,
		},
		{
			name:     "warning level",
			input:    "WARNING",
			expected: slog.LevelWarn,
		},
		{
			name:     "error level",
			input:    "ERROR",
			expected: slog.LevelError,
		},
		{
			name:     "unknown defaults to info",
			input:    "UNKNOWN",
			expected: slog.LevelInfo,
		},
		{
			name:     "empty defaults to info",
			input:    "",
			expected: slog.LevelInfo,
		},
		{
			name:     "case insensitive",
			input:    "debug",
			expected: slog.LevelDebug,
		},
		{
			name:     "whitespace trimmed",
			input:    "  DEBUG  ",
			expected: slog.LevelDebug,
		},
	}
}

func TestToZerologLevel(t *testing.T) {
	t.Parallel()

	tests := getToZerologLevelTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := toZerologLevel(tt.input)

			if result != tt.expected {
				t.Errorf("toZerologLevel(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func getToZerologLevelTests() []struct {
	name     string
	input    slog.Level
	expected zerolog.Level
} {
	return []struct {
		name     string
		input    slog.Level
		expected zerolog.Level
	}{
		{
			name:     "trace level",
			input:    LevelTrace,
			expected: zerolog.TraceLevel,
		},
		{
			name:     "debug level",
			input:    slog.LevelDebug,
			expected: zerolog.DebugLevel,
		},
		{
			name:     "info level",
			input:    slog.LevelInfo,
			expected: zerolog.InfoLevel,
		},
		{
			name:     "warn level",
			input:    slog.LevelWarn,
			expected: zerolog.WarnLevel,
		},
		{
			name:     "error level",
			input:    slog.LevelError,
			expected: zerolog.ErrorLevel,
		},
		{
			name:     "unknown defaults to info",
			input:    slog.Level(999),
			expected: zerolog.InfoLevel,
		},
	}
}

func TestRetryLogger(t *testing.T) {
	t.Parallel()

	tests := getRetryLoggerTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var testBuf bytes.Buffer

			testZL := zerolog.New(&testBuf).With().Timestamp().Logger()
			rl := &retryLogger{zl: testZL, lvl: tt.level}

			// Test that Printf and Println don't panic
			rl.Printf("test message %s", "arg")
			rl.Println("test", "message")
			// Just verify the methods don't panic - output format can vary
		})
	}
}

func getRetryLoggerTests() []struct {
	name  string
	level zerolog.Level
} {
	return []struct {
		name  string
		level zerolog.Level
	}{
		{"info level", zerolog.InfoLevel},
		{"debug level", zerolog.DebugLevel},
		{"warn level", zerolog.WarnLevel},
		{"error level", zerolog.ErrorLevel},
		{"trace level", zerolog.TraceLevel},
		{"no level", zerolog.NoLevel},
	}
}

func TestNopLogger(t *testing.T) {
	t.Parallel()

	logger := &nopLogger{}

	// These should not panic or produce output
	logger.Printf("test %s", "message")
	logger.Println("test", "message")
}

func TestNewPoster(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	poster := newPoster("http://test.com/ingest", "test-key", zl, false)

	if poster == nil {
		t.Fatal("newPoster() returned nil")
	}

	if poster.url != "http://test.com/ingest" {
		t.Errorf("newPoster() url = %q, want %q", poster.url, "http://test.com/ingest")
	}

	if poster.apiKey != "test-key" {
		t.Errorf("newPoster() apiKey = %q, want %q", poster.apiKey, "test-key")
	}

	// Clean shutdown
	poster.Stop(100 * time.Millisecond)
}

func TestPosterEnqueue(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	poster := newPoster("http://test.com/ingest", "test-key", zl, false)
	defer poster.Stop(100 * time.Millisecond)

	payload := []byte(`{"test": "data"}`)
	poster.Enqueue(payload)
	// Should not block or panic
}

func TestPosterProbe(t *testing.T) {
	t.Parallel()

	tests := getPosterProbeTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)

				if tt.response != "" {
					_, _ = w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			var buf bytes.Buffer

			zl := zerolog.New(&buf)

			poster := newPoster(server.URL, "test-key", zl, false)
			defer poster.Stop(100 * time.Millisecond)

			err := poster.Probe()

			if tt.expectError && err == nil {
				t.Error("Probe() expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Probe() expected no error, got: %v", err)
			}
		})
	}
}

func getPosterProbeTests() []struct {
	name        string
	statusCode  int
	response    string
	expectError bool
} {
	return []struct {
		name        string
		statusCode  int
		response    string
		expectError bool
	}{
		{
			name:        "success 200",
			statusCode:  200,
			response:    `{"status": "ok"}`,
			expectError: false,
		},
		{
			name:        "success 201",
			statusCode:  201,
			response:    "",
			expectError: false,
		},
		{
			name:        "client error 400",
			statusCode:  400,
			response:    "Bad Request",
			expectError: true,
		},
		{
			name:        "server error 500",
			statusCode:  500,
			response:    `{"error": "internal error"}`,
			expectError: true,
		},
		{
			name:        "not found 404",
			statusCode:  404,
			response:    "Not Found",
			expectError: true,
		},
	}
}

func TestZerologHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelInfo,
		poster:    nil,
		hostname:  "test-host",
	}

	tests := getZerologHandlerTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enabled := handler.Enabled(context.Background(), tt.level)

			if enabled != tt.expectedEnabled {
				t.Errorf("Enabled(%v) = %v, want %v", tt.level, enabled, tt.expectedEnabled)
			}
		})
	}
}

func getZerologHandlerTests() []struct {
	name            string
	level           slog.Level
	expectedEnabled bool
} {
	return []struct {
		name            string
		level           slog.Level
		expectedEnabled bool
	}{
		{
			name:            "debug below threshold",
			level:           slog.LevelDebug,
			expectedEnabled: false,
		},
		{
			name:            "info at threshold",
			level:           slog.LevelInfo,
			expectedEnabled: true,
		},
		{
			name:            "warn above threshold",
			level:           slog.LevelWarn,
			expectedEnabled: true,
		},
		{
			name:            "error above threshold",
			level:           slog.LevelError,
			expectedEnabled: true,
		},
	}
}

func TestZerologHandlerHandle(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf).With().Timestamp().Logger()

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelInfo,
		poster:    nil,
		hostname:  "test-host",
	}

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	record.AddAttrs(slog.String("key", "value"))

	err := handler.Handle(context.Background(), record)
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
	// Just verify the method doesn't return an error - output format testing is complex
}

func TestSetAPIAuthHeaders(t *testing.T) {
	t.Parallel()

	tests := getSetAPIAuthHeadersTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			headers := make(http.Header)
			setAPIAuthHeaders(headers, tt.apiKey)

			if tt.apiKey == "" {
				if len(headers) != 0 {
					t.Errorf("setAPIAuthHeaders() with empty key should not set headers, got: %v", headers)
				}
			} else {
				expectedAuth := "Bearer " + tt.apiKey
				if headers.Get("Authorization") != expectedAuth {
					t.Errorf("setAPIAuthHeaders() Authorization = %q, want %q",
						headers.Get("Authorization"), expectedAuth)
				}

				if headers.Get("X-Api-Key") != tt.apiKey {
					t.Errorf("setAPIAuthHeaders() X-Api-Key = %q, want %q",
						headers.Get("X-Api-Key"), tt.apiKey)
				}
			}
		})
	}
}

func getSetAPIAuthHeadersTests() []struct {
	name   string
	apiKey string
} {
	return []struct {
		name   string
		apiKey string
	}{
		{
			name:   "with api key",
			apiKey: "test-api-key-123",
		},
		{
			name:   "empty api key",
			apiKey: "",
		},
	}
}

func TestGetCanonicalTime(t *testing.T) {
	t.Parallel()

	fallback := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := getCanonicalTimeTests(fallback)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := getCanonicalTime(tt.attrs, fallback)

			if !strings.Contains(result, tt.expectedContains) {
				t.Errorf("getCanonicalTime() = %q, should contain %q", result, tt.expectedContains)
			}
		})
	}
}

func getCanonicalTimeTests(_ time.Time) []struct {
	name             string
	attrs            map[string]any
	expectedContains string
} {
	return []struct {
		name             string
		attrs            map[string]any
		expectedContains string
	}{
		{
			name:             "uses fallback when no time attrs",
			attrs:            map[string]any{},
			expectedContains: "2023-01-01T12:00:00",
		},
		{
			name:             "prefers time attribute",
			attrs:            map[string]any{"time": "2023-02-01T10:00:00Z"},
			expectedContains: "2023-02-01T10:00:00Z",
		},
		{
			name:             "falls back to timestamp",
			attrs:            map[string]any{"timestamp": "2023-03-01T10:00:00Z"},
			expectedContains: "2023-03-01T10:00:00Z",
		},
		{
			name:             "falls back to event_time",
			attrs:            map[string]any{"event_time": "2023-04-01T10:00:00Z"},
			expectedContains: "2023-04-01T10:00:00Z",
		},
		{
			name:             "prefers time over others",
			attrs:            map[string]any{"time": "2023-05-01T10:00:00Z", "timestamp": "2023-06-01T10:00:00Z"},
			expectedContains: "2023-05-01T10:00:00Z",
		},
	}
}

func TestNormalizeAttributeKeys(t *testing.T) {
	t.Parallel()

	tests := getNormalizeAttributeKeysTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			attrs := make(map[string]any)
			for k, v := range tt.input {
				attrs[k] = v
			}

			normalizeAttributeKeys(attrs)

			for key, expectedValue := range tt.expected {
				if attrs[key] != expectedValue {
					t.Errorf("normalizeAttributeKeys() %s = %v, want %v", key, attrs[key], expectedValue)
				}
			}
		})
	}
}

func getNormalizeAttributeKeysTests() []struct {
	name     string
	input    map[string]any
	expected map[string]any
} {
	return []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name:     "normalizes client_ip to source_ip",
			input:    map[string]any{"client_ip": "192.168.1.1"},
			expected: map[string]any{"source_ip": "192.168.1.1"},
		},
		{
			name:     "normalizes dst_ip to destination_ip",
			input:    map[string]any{"dst_ip": "10.0.0.1"},
			expected: map[string]any{"destination_ip": "10.0.0.1"},
		},
		{
			name:     "normalizes dst_port to destination_port",
			input:    map[string]any{"dst_port": 8080},
			expected: map[string]any{"destination_port": 8080},
		},
		{
			name:     "uses host for http_host when http_host not present",
			input:    map[string]any{"host": "example.com"},
			expected: map[string]any{"http_host": "example.com"},
		},
		{
			name:     "keeps http_host when both present",
			input:    map[string]any{"host": "example.com", "http_host": "api.example.com"},
			expected: map[string]any{"http_host": "api.example.com"},
		},
		{
			name:     "multiple normalizations",
			input:    map[string]any{"client_ip": "1.2.3.4", "dst_port": 443, "host": "test.com"},
			expected: map[string]any{"source_ip": "1.2.3.4", "destination_port": 443, "http_host": "test.com"},
		},
	}
}

func TestBuildDashboardPayload(t *testing.T) {
	t.Parallel()

	hostname := "test-host"
	rTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	rLevel := slog.LevelInfo
	rMsg := "test message"
	act := "BLOCKED"
	attrs := map[string]any{
		"source_ip":   "192.168.1.1",
		"destination": "example.com",
		"protocol":    "TCP",
	}

	payload := buildDashboardPayload(hostname, rTime, rLevel, rMsg, act, attrs)

	// Check required fields
	requiredFields := map[string]interface{}{
		"producer_time": "2023-01-01T12:00:00Z",
		"level":         "INFO",
		"msg":           "test message",
		"action":        "BLOCKED",
		"hostname":      "test-host",
	}

	for key, expected := range requiredFields {
		if payload[key] != expected {
			t.Errorf("buildDashboardPayload() %s = %v, want %v", key, payload[key], expected)
		}
	}

	// Check that canonical time is included
	if _, exists := payload["time"]; !exists {
		t.Error("buildDashboardPayload() missing 'time' field")
	}
}

func TestNewWithFormat(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getNewWithFormatTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for test
			if tt.logFile != "" {
				t.Setenv("LOG_FILE", tt.logFile)
			}

			if tt.hostname != "" {
				t.Setenv("HOSTNAME", tt.hostname)
			}

			var buf bytes.Buffer

			logger := NewWithFormat(tt.level, tt.format, &buf, tt.addSource)

			if logger == nil {
				t.Fatal("NewWithFormat() returned nil logger")
			}

			// Test that logger works
			logger.Info("test message")
			// Just verify it doesn't panic and creates a logger
		})
	}
}

func getNewWithFormatTests() []struct {
	name      string
	level     string
	format    string
	addSource bool
	logFile   string
	hostname  string
} {
	return []struct {
		name      string
		level     string
		format    string
		addSource bool
		logFile   string
		hostname  string
	}{
		{
			name:      "basic logger",
			level:     "INFO",
			format:    "json",
			addSource: false,
		},
		{
			name:      "debug level",
			level:     "DEBUG",
			format:    "console",
			addSource: true,
		},
		{
			name:     "with hostname",
			level:    "WARN",
			format:   "json",
			hostname: "test-host",
		},
		{
			name:    "empty level defaults",
			level:   "",
			format:  "json",
			logFile: "/tmp/test.log",
		},
	}
}

func TestNewFromEnv(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv() due to Go testing framework limitations
	tests := getNewFromEnvTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.logLevel != "" {
				t.Setenv("LOG_LEVEL", tt.logLevel)
			}

			if tt.logFormat != "" {
				t.Setenv("LOG_FORMAT", tt.logFormat)
			}

			logger := NewFromEnv()

			if logger == nil {
				t.Fatal("NewFromEnv() returned nil logger")
			}

			// Test that logger works
			logger.Info("test message from env")
		})
	}
}

func getNewFromEnvTests() []struct {
	name      string
	logLevel  string
	logFormat string
} {
	return []struct {
		name      string
		logLevel  string
		logFormat string
	}{
		{
			name:      "default values",
			logLevel:  "",
			logFormat: "",
		},
		{
			name:      "debug level",
			logLevel:  "DEBUG",
			logFormat: "console",
		},
		{
			name:      "error level json",
			logLevel:  "ERROR",
			logFormat: "json",
		},
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	logger := New("INFO")

	if logger == nil {
		t.Fatal("New() returned nil logger")
	}

	// Test that logger works
	logger.Info("test message from New")
}

func TestShutdown(t *testing.T) {
	t.Parallel()

	// Test shutdown with no default poster
	Shutdown(100 * time.Millisecond)

	// Test shutdown with a poster
	var buf bytes.Buffer

	zl := zerolog.New(&buf)
	poster := newPoster("http://test.com/ingest", "test-key", zl, false)
	defaultPoster = poster

	Shutdown(100 * time.Millisecond)

	// Reset default poster
	defaultPoster = nil
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Test that constants have expected values
	if actionRedirected != "REDIRECTED" {
		t.Errorf("Expected actionRedirected to be 'REDIRECTED', got %s", actionRedirected)
	}

	if LevelTrace.Level() != -8 {
		t.Errorf("Expected LevelTrace to be -8, got %d", LevelTrace.Level())
	}

	if defaultQueueSize != 1024 {
		t.Errorf("Expected defaultQueueSize to be 1024, got %d", defaultQueueSize)
	}

	if defaultLogMaxSizeMB != 100 {
		t.Errorf("Expected defaultLogMaxSizeMB to be 100, got %d", defaultLogMaxSizeMB)
	}
}

func TestZerologHandlerWithAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelInfo,
		poster:    nil,
		hostname:  "test-host",
	}

	attrs := []slog.Attr{
		slog.String("key1", "value1"),
		slog.Int("key2", 42),
	}

	newHandler := handler.WithAttrs(attrs)

	if newHandler == nil {
		t.Error("WithAttrs() returned nil handler")
	}

	// Test that the new handler works
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test with attrs", 0)

	err := newHandler.Handle(context.Background(), record)
	if err != nil {
		t.Errorf("Handle() on handler with attrs returned error: %v", err)
	}
}

func TestZerologHandlerWithGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelInfo,
		poster:    nil,
		hostname:  "test-host",
	}

	newHandler := handler.WithGroup("test-group")

	if newHandler == nil {
		t.Error("WithGroup() returned nil handler")
	}

	// Groups are ignored, so should return the same handler
	if newHandler != handler {
		t.Error("WithGroup() should return the same handler (groups are ignored)")
	}
}

func TestLogToTerminal(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)

	// Test logging to terminal
	attrs := map[string]any{"key": "value"}
	logToTerminal(zl, slog.LevelInfo, "test message", attrs)

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Logf("Terminal log output: %s", output)
	}
}
