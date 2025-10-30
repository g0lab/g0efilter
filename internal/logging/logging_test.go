//nolint:testpackage // Need access to internal implementation details
package logging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/rs/zerolog"
)

const actionBlocked = "BLOCKED"

var (
	errTestNetworkError = errors.New("test network error")
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

func TestNopLogger(t *testing.T) {
	t.Parallel()

	logger := &nopLogger{}

	// These should not panic or produce output
	logger.Printf("test %s", "message")
	logger.Println("test", "message")
}

//nolint:paralleltest // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestNewPoster(t *testing.T) {
	// Cannot use t.Parallel() because newPoster modifies global defaultPoster
	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	const (
		testURL   = "http://test.com/ingest"
		testKey   = "test-key"
		testEvent = "test-event"
	)

	poster := newPoster(testURL, testKey, zl, false)

	// Test poster configuration
	expectedConfig := struct {
		url    string
		apiKey string
	}{
		url:    testURL,
		apiKey: testKey,
	}

	if poster.url != expectedConfig.url {
		t.Errorf("poster URL = %q, want %q", poster.url, expectedConfig.url)
	}

	if poster.apiKey != expectedConfig.apiKey {
		t.Errorf("poster API key = %q, want %q", poster.apiKey, expectedConfig.apiKey)
	}

	// Test poster functionality
	payload := []byte(testEvent)
	poster.Enqueue(payload)

	// Clean shutdown and ensure channel is drained
	poster.Stop(100 * time.Millisecond)
}

// t unused but required for test signature.
//
//nolint:paralleltest,revive // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestPosterEnqueue(t *testing.T) {
	// Cannot use t.Parallel() because newPoster modifies global defaultPoster
	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	poster := newPoster("http://test.com/ingest", "test-key", zl, false)
	defer poster.Stop(100 * time.Millisecond)

	payload := []byte(`{"test": "data"}`)
	poster.Enqueue(payload)
	// Should not block or panic
}

//nolint:paralleltest // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestPosterProbe(t *testing.T) {
	// Cannot use t.Parallel() because newPoster modifies global defaultPoster
	tests := getPosterProbeTests()

	for _, tt := range tests { //nolint:paralleltest // Cannot use t.Parallel() because newPoster
		// modifies global defaultPoster
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() because newPoster modifies global defaultPoster
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

			err := poster.Probe(context.Background())

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
	version := "test-version"
	rTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	rMsg := "test message"
	act := actionBlocked
	attrs := map[string]any{
		"source_ip":   "192.168.1.1",
		"destination": "example.com",
		"protocol":    "TCP",
	}

	payload := buildDashboardPayload(hostname, version, rTime, rMsg, act, attrs)

	// Check required fields
	requiredFields := map[string]interface{}{
		"producer_time": "2023-01-01T12:00:00Z",
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

			logger := NewWithFormat(tt.level, tt.format, &buf, tt.addSource, "test-version")

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

// t unused but required for test signature.
//
//nolint:paralleltest,revive // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestShutdown(t *testing.T) {
	// Cannot use t.Parallel() because newPoster modifies global defaultPoster

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
	if filter.ActionRedirected != "REDIRECTED" {
		t.Errorf("Expected ActionRedirected to be 'REDIRECTED', got %s", filter.ActionRedirected)
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

//nolint:paralleltest // Cannot use t.Parallel() due to zerolog global level modification
func TestLogToTerminal(t *testing.T) {
	// Ensure global level allows info logs regardless of other tests
	orig := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(orig) })

	var buf bytes.Buffer

	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)

	// Test logging to terminal
	attrs := map[string]any{"key": "value"}
	logToTerminal(zl, slog.LevelInfo, "test message", attrs)

	output := buf.String()
	if output == "" {
		// Should at least produce some output
		t.Error("expected terminal output, got empty string")
	}
}

// spyRC is a test ReadCloser that records reads and close calls.
type spyRC struct {
	data   []byte
	off    int
	closed bool
}

func (s *spyRC) Read(p []byte) (int, error) {
	if s.off >= len(s.data) {
		return 0, io.EOF
	}

	n := copy(p, s.data[s.off:])
	s.off += n

	return n, nil
}

func (s *spyRC) Close() error {
	s.closed = true

	return nil
}

//nolint:paralleltest // Cannot use t.Parallel() due to zerolog global level modification
func TestLogPosterResponse_NotTrace(t *testing.T) {
	body := &spyRC{data: []byte(strings.Repeat("x", 1024))}
	resp := &http.Response{StatusCode: http.StatusOK, Body: body}
	zl := zerolog.New(io.Discard).Level(zerolog.TraceLevel)

	logPosterResponse(zl, resp, false)

	if !body.closed {
		t.Error("expected body to be closed in non-trace mode")
	}

	if body.off != 1024 {
		t.Errorf("expected body to be fully drained, read=%d", body.off)
	}
}

//nolint:paralleltest // Cannot use t.Parallel() due to zerolog global level modification
func TestLogPosterResponse_TraceJSON(t *testing.T) {
	// Ensure trace logs are enabled regardless of global level set by other tests
	orig := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(orig) })

	var buf bytes.Buffer

	zl := zerolog.New(&buf).Level(zerolog.TraceLevel)

	payload := `{"ok":true}`
	body := &spyRC{data: []byte(payload)}
	resp := &http.Response{StatusCode: http.StatusCreated, Body: body}

	logPosterResponse(zl, resp, true)

	if !body.closed {
		t.Error("expected body to be closed in trace mode")
	}

	if body.off == 0 {
		t.Error("expected body to be read in trace mode")
	}

	out := buf.String()
	if !strings.Contains(out, "dashboard.post resp") {
		t.Errorf("expected trace log to contain marker, got: %s", out)
	}

	if !strings.Contains(out, "resp_body") {
		t.Errorf("expected trace log to contain resp_body, got: %s", out)
	}
}

//nolint:paralleltest // Cannot use t.Parallel() due to zerolog global level modification
func TestLogTraceBody_JSONAndText(t *testing.T) {
	// Ensure trace logs are enabled regardless of global level set by other tests
	orig := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(orig) })

	tests := []struct {
		name       string
		body       []byte
		expectJSON bool
	}{
		{"json body", []byte(`{"a":1}`), true},
		{"text body", []byte("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { //nolint:paralleltest // Due to global level
			var buf bytes.Buffer

			zl := zerolog.New(&buf).Level(zerolog.TraceLevel)

			logTraceBody(zl, "http://example/ingest", tt.body)

			out := buf.String()
			if !strings.Contains(out, "dashboard.post body") {
				t.Errorf("expected log to contain marker, got: %s", out)
			}

			if tt.expectJSON && !strings.Contains(out, "\"body\":{") {
				t.Errorf("expected JSON body field, got: %s", out)
			}

			if !tt.expectJSON && !strings.Contains(out, "\"body\":\"hello\"") {
				t.Errorf("expected string body field, got: %s", out)
			}
		})
	}
}

func TestShipToDashboard_ActionFilter(t *testing.T) {
	t.Parallel()

	mkPoster := func() (*poster, chan []byte) {
		ch := make(chan []byte, 10)
		p := &poster{q: ch, zl: zerolog.New(io.Discard)}

		return p, ch
	}

	allowed := []string{"ALLOWED", "BLOCKED", "REDIRECTED"}
	for _, act := range allowed {
		p, ch := mkPoster()
		attrs := map[string]any{"action": act}
		shipToDashboard(p, "host", "test-version", time.Now(), "msg", attrs)

		select {
		case <-ch:
			// ok
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("expected enqueue for action %s", act)
		}
	}

	// Disallowed action should not enqueue
	p, ch := mkPoster()
	attrs := map[string]any{"action": "OTHER"}
	shipToDashboard(p, "host", "test-version", time.Now(), "msg", attrs)

	select {
	case <-ch:
		t.Fatal("did not expect enqueue for other action")
	case <-time.After(50 * time.Millisecond):
		// ok: nothing enqueued
	}
}

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resp     *http.Response
		err      error
		expected bool
	}{
		{"network error", nil, errTestNetworkError, true},
		{"500 server error", &http.Response{StatusCode: http.StatusInternalServerError}, nil, true},
		{"503 service unavailable", &http.Response{StatusCode: http.StatusServiceUnavailable}, nil, true},
		{"429 rate limited", &http.Response{StatusCode: http.StatusTooManyRequests}, nil, true},
		{"200 success", &http.Response{StatusCode: http.StatusOK}, nil, false},
		{"404 not found", &http.Response{StatusCode: http.StatusNotFound}, nil, false},
		{"nil response", nil, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := shouldRetry(tt.resp, tt.err)
			if result != tt.expected {
				t.Errorf("shouldRetry() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAddJitter(t *testing.T) {
	t.Parallel()

	baseDuration := 1 * time.Second

	// Test multiple times to verify jitter behavior
	for range 100 {
		result := addJitter(baseDuration)

		// Result should be between 0.5x and 1.0x the base duration
		if result < baseDuration/2 || result > baseDuration {
			t.Errorf("addJitter(%v) = %v, want between %v and %v",
				baseDuration, result, baseDuration/2, baseDuration)
		}
	}
}

//nolint:funlen
func TestPosterRetry(t *testing.T) {
	t.Parallel()

	// Create a test server that fails a few times then succeeds
	var (
		failCount = 0
		maxFails  = 3
		received  = make(chan []byte, 1)
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read request body: %v", err)

			return
		}

		defer func() {
			err := r.Body.Close()
			if err != nil {
				t.Errorf("Failed to close request body: %v", err)
			}
		}()

		if failCount < maxFails {
			failCount++

			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		w.WriteHeader(http.StatusOK)

		received <- body
	}))
	defer server.Close()

	zl := zerolog.New(io.Discard)
	p := &poster{
		url:          server.URL,
		q:            make(chan []byte, 1),
		httpC:        &http.Client{Timeout: 100 * time.Millisecond},
		zl:           zl,
		workers:      1,
		retryTimeout: 30 * time.Second,
		retryWaitMin: 10 * time.Millisecond,
		retryWaitMax: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	p.wg.Add(1)

	go p.worker(ctx)

	testMsg := []byte(`{"test":"retry"}`)
	p.Enqueue(testMsg)

	select {
	case <-ctx.Done():
		t.Fatal("Test timed out")
	case msg := <-received:
		if !bytes.Equal(msg, testMsg) {
			t.Errorf("Got unexpected message: %s", msg)
		}
	}
}

func TestPosterQueueOverflow(t *testing.T) {
	t.Parallel()

	// Ensure debug level is enabled for this test
	origLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(origLevel) })

	var buf bytes.Buffer

	// Use ConsoleWriter for more readable output in tests
	zl := zerolog.New(zerolog.ConsoleWriter{Out: &buf, NoColor: true, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger().Level(zerolog.DebugLevel)

	p := &poster{
		url:          "http://localhost:1", // Invalid URL to force queue buildup
		q:            make(chan []byte),    // Unbuffered channel - any enqueue will block/fail
		httpC:        &http.Client{Timeout: 100 * time.Millisecond},
		zl:           zl,
		debug:        true, // Enable debug logging to capture queue full messages
		retryWaitMin: 10 * time.Millisecond,
		retryWaitMax: 50 * time.Millisecond,
	}

	// With unbuffered channel (size 0), all enqueues should fail immediately
	for i := range 5 {
		payload := []byte(fmt.Sprintf(`{"test":"data-%d"}`, i))
		p.Enqueue(payload) // Should all be dropped since channel is unbuffered
	}

	// Give enough time for log writes to complete (race detector slows things down)
	time.Sleep(50 * time.Millisecond)

	// Check that we got queue full/dropping debug messages
	logOutput := buf.String()
	if !strings.Contains(logOutput, "queue full") && !strings.Contains(logOutput, "dropping message") {
		t.Errorf("Expected queue full or dropping message in logs, got: %q", logOutput)
	}

	// Most importantly: verify no "retry attempts exhausted" or similar exit messages
	if strings.Contains(logOutput, "exhausted") || strings.Contains(logOutput, "max_retries") {
		t.Error("Found retry exhaustion message - system should retry infinitely!")
	}
}

func TestPosterResilience(t *testing.T) {
	t.Parallel()

	var processed = make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := r.Body.Close()
			if err != nil {
				t.Errorf("Failed to close request body: %v", err)
			}
		}()

		w.WriteHeader(http.StatusOK)

		processed <- struct{}{}
	}))
	defer server.Close()

	zl := zerolog.New(io.Discard)
	p := &poster{
		url:          server.URL,
		q:            make(chan []byte, 1),
		httpC:        &http.Client{Timeout: 100 * time.Millisecond},
		zl:           zl,
		workers:      1,
		retryTimeout: 30 * time.Second,
		retryWaitMin: 10 * time.Millisecond,
		retryWaitMax: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	p.wg.Add(1)

	go p.worker(ctx)

	// Send initial message
	p.Enqueue([]byte(`{"test":"first"}`))

	// Wait for first message
	select {
	case <-ctx.Done():
		t.Fatal("First message timeout")
	case <-processed:
	}

	// Verify system still accepts new messages
	p.Enqueue([]byte(`{"test":"second"}`))

	select {
	case <-ctx.Done():
		t.Fatal("System should still be processing")
	case <-processed:
		// System still operational
	}
}

//nolint:paralleltest // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestPosterStop_Timeout(_ *testing.T) {
	var buf bytes.Buffer

	zl := zerolog.New(&buf)
	poster := newPoster("http://test.com/ingest", "test-key", zl, false)

	// Stop with short timeout to test timeout path
	poster.Stop(1 * time.Millisecond)
}

//nolint:paralleltest // Cannot use t.Parallel() because newPoster modifies global defaultPoster
func TestPosterStop_ZeroTimeout(_ *testing.T) {
	var buf bytes.Buffer

	zl := zerolog.New(&buf)
	poster := newPoster("http://test.com/ingest", "test-key", zl, false)

	// Stop with zero timeout should wait indefinitely
	poster.Stop(0)
}

func TestZerologHandlerWithPoster(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	// Mock poster
	ch := make(chan []byte, 10)
	mockPoster := &poster{q: ch, zl: zl}

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelWarn, // Higher threshold
		poster:    mockPoster,
		hostname:  "test-host",
	}

	// Test that debug level is enabled due to poster (even if below term threshold)
	enabled := handler.Enabled(context.Background(), slog.LevelDebug)
	if !enabled {
		t.Error("Expected debug to be enabled due to poster presence")
	}
}

func TestNewWithContext_DashboardIntegration(t *testing.T) {
	t.Setenv("DASHBOARD_HOST", "http://localhost:8080")
	t.Setenv("DASHBOARD_API_KEY", "test-key")

	var buf bytes.Buffer

	logger := NewWithContext(context.Background(), "DEBUG", "json", &buf, false, "test-version")

	if logger == nil {
		t.Fatal("NewWithContext() returned nil logger")
	}

	// Test that logger works
	logger.Info("test dashboard integration")
}

func TestNewWithContext_LogFile(t *testing.T) {
	t.Setenv("LOG_FILE", "/tmp/test.log")

	var buf bytes.Buffer

	logger := NewWithContext(context.Background(), "INFO", "json", &buf, false, "test-version")

	if logger == nil {
		t.Fatal("NewWithContext() returned nil logger with LOG_FILE")
	}
}

func TestZerologHandlerEnabled_WithPoster(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zl := zerolog.New(&buf)

	// Create handler with poster
	ch := make(chan []byte, 1)
	mockPoster := &poster{q: ch, zl: zl}

	handler := &zerologHandler{
		zl:        zl,
		termLevel: slog.LevelError, // Very high threshold
		poster:    mockPoster,      // But poster present
		hostname:  "test-host",
	}

	// Should be enabled even for debug due to poster
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Expected debug to be enabled due to poster")
	}

	// Should be enabled for error due to term level
	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Error("Expected error to be enabled due to term level")
	}
}

func TestBuildDashboardPayload_HostnameHandling(t *testing.T) {
	t.Parallel()

	rTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("empty hostname", func(t *testing.T) {
		t.Parallel()

		payload := buildDashboardPayload("", "", rTime, "msg", "BLOCKED", map[string]any{})
		if _, exists := payload["hostname"]; exists {
			t.Error("Expected no hostname field for empty hostname")
		}
	})

	t.Run("hostname from attrs takes precedence", func(t *testing.T) {
		t.Parallel()

		attrs := map[string]any{"hostname": "attr-host"}

		payload := buildDashboardPayload("param-host", "test-version", rTime, "msg", "BLOCKED", attrs)
		if payload["hostname"] != "attr-host" {
			t.Errorf("Expected hostname from attrs, got %v", payload["hostname"])
		}
	})

	t.Run("uses param hostname when attr empty", func(t *testing.T) {
		t.Parallel()

		attrs := map[string]any{"hostname": ""}

		payload := buildDashboardPayload("param-host", "test-version", rTime, "msg", "BLOCKED", attrs)
		if payload["hostname"] != "param-host" {
			t.Errorf("Expected param hostname, got %v", payload["hostname"])
		}
	})
}
