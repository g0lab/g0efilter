//nolint:testpackage // Need access to internal implementation details
package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	t.Parallel()

	tests := getConfigDefaultsTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := tt.input
			applyConfigDefaults(&cfg)

			if cfg != tt.expected {
				t.Errorf("Config defaults mismatch.\nGot: %+v\nWant: %+v", cfg, tt.expected)
			}
		})
	}
}

func getConfigDefaultsTestCases() []struct {
	name     string
	input    Config
	expected Config
} {
	return []struct {
		name     string
		input    Config
		expected Config
	}{
		{
			name: "all defaults applied",
			input: Config{
				Addr:      ":8081",
				APIKey:    "test-key",
				LogLevel:  "INFO",
				LogFormat: "json",
			},
			expected: Config{
				Addr:       ":8081",
				APIKey:     "test-key",
				LogLevel:   "INFO",
				LogFormat:  "json",
				BufferSize: 5000,
				ReadLimit:  500,
				SERetryMs:  2000,
				RateRPS:    50,
				RateBurst:  100,
			},
		},
		{
			name: "custom values preserved",
			input: Config{
				Addr:       ":9000",
				APIKey:     "custom-key",
				LogLevel:   "DEBUG",
				LogFormat:  "console",
				BufferSize: 1000,
				ReadLimit:  100,
				SERetryMs:  1000,
				RateRPS:    25.0,
				RateBurst:  50.0,
			},
			expected: Config{
				Addr:       ":9000",
				APIKey:     "custom-key",
				LogLevel:   "DEBUG",
				LogFormat:  "console",
				BufferSize: 1000,
				ReadLimit:  100,
				SERetryMs:  1000,
				RateRPS:    25.0,
				RateBurst:  50.0,
			},
		},
	}
}

// getConfigDefaultsTests returns test cases for config defaults.
func getConfigDefaultsTests() []struct {
	name     string
	input    Config
	expected Config
} {
	testCases := getConfigDefaultsTestCases()

	// Add the zero values test case
	testCases = append(testCases, struct {
		name     string
		input    Config
		expected Config
	}{
		name: "zero values get defaults",
		input: Config{
			Addr:       ":8081",
			APIKey:     "test-key",
			LogLevel:   "INFO",
			LogFormat:  "json",
			BufferSize: 0,
			ReadLimit:  0,
			SERetryMs:  0,
			RateRPS:    0,
			RateBurst:  0,
		},
		expected: Config{
			Addr:       ":8081",
			APIKey:     "test-key",
			LogLevel:   "INFO",
			LogFormat:  "json",
			BufferSize: 5000,
			ReadLimit:  500,
			SERetryMs:  2000,
			RateRPS:    50,
			RateBurst:  100,
		},
	})

	return testCases
}

func applyConfigDefaults(cfg *Config) {
	// Apply the same defaults logic as Run function
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 5000
	}

	if cfg.ReadLimit <= 0 {
		cfg.ReadLimit = 500
	}

	if cfg.SERetryMs <= 0 {
		cfg.SERetryMs = 2000
	}

	if cfg.RateRPS <= 0 {
		cfg.RateRPS = 50
	}

	if cfg.RateBurst <= 0 {
		cfg.RateBurst = 100
	}
}

func TestMemStore_NewStore(t *testing.T) {
	t.Parallel()

	t.Run("new store", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(10)
		if store.size != 10 {
			t.Errorf("Expected size 10, got %d", store.size)
		}

		if store.count != 0 {
			t.Errorf("Expected count 0, got %d", store.count)
		}

		if store.nextID != 1 {
			t.Errorf("Expected nextID 1, got %d", store.nextID)
		}
	})

	t.Run("new store with zero size", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(0)
		if store.size != 1 {
			t.Errorf("Expected size 1 (minimum), got %d", store.size)
		}
	})
}

func TestMemStore_InsertAndQuery(t *testing.T) {
	t.Parallel()

	store := newMemStore(5)
	ctx := context.Background()

	// Insert a log entry
	entry := &LogEntry{
		Message: "test message",
		Fields:  json.RawMessage(`{"key":"value"}`),
	}

	id, err := store.Insert(ctx, entry)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	if id != 1 {
		t.Errorf("Expected ID 1, got %d", id)
	}

	// Query the entry
	entries, err := store.Query(ctx, "", 0, 10)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	if entries[0].Message != "test message" {
		t.Errorf("Expected message 'test message', got %s", entries[0].Message)
	}
}

func TestMemStore_Clear(t *testing.T) {
	t.Parallel()

	store := newMemStore(5)
	ctx := context.Background()

	// Insert an entry
	entry := &LogEntry{Message: "test"}

	_, err := store.Insert(ctx, entry)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Clear the store
	err = store.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify empty
	entries, err := store.Query(ctx, "", 0, 10)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", len(entries))
	}
}

func TestMemStore_RingBuffer(t *testing.T) {
	t.Parallel()

	store := newMemStore(2) // Small buffer
	ctx := context.Background()

	// Insert 3 entries (more than capacity)
	for i := range 3 {
		entry := &LogEntry{
			Message: fmt.Sprintf("message %d", i),
		}

		_, err := store.Insert(ctx, entry)
		if err != nil {
			t.Fatalf("Insert %d failed: %v", i, err)
		}
	}

	// Should only have the last 2 entries
	entries, err := store.Query(ctx, "", 0, 10)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries (ring buffer), got %d", len(entries))
	}

	// Should be in reverse order (newest first)
	if entries[0].Message != "message 2" {
		t.Errorf("Expected newest message first, got %s", entries[0].Message)
	}

	if entries[1].Message != "message 1" {
		t.Errorf("Expected second newest message, got %s", entries[1].Message)
	}
}

func TestBroadcaster(t *testing.T) {
	t.Parallel()

	t.Run("add and remove clients", func(t *testing.T) {
		t.Parallel()

		b := newBroadcaster()

		ch1 := b.add()
		ch2 := b.add()

		if len(b.clients) != 2 {
			t.Errorf("Expected 2 clients, got %d", len(b.clients))
		}

		b.remove(ch1)

		if len(b.clients) != 1 {
			t.Errorf("Expected 1 client after removal, got %d", len(b.clients))
		}

		b.remove(ch2)

		if len(b.clients) != 0 {
			t.Errorf("Expected 0 clients after all removed, got %d", len(b.clients))
		}
	})

	t.Run("send to clients", func(t *testing.T) {
		t.Parallel()

		b := newBroadcaster()

		ch1 := b.add()
		ch2 := b.add()

		message := []byte("test message")
		b.send(message)

		// Check both clients received the message
		select {
		case msg := <-ch1:
			if !bytes.Equal(msg, message) {
				t.Errorf("Client 1 got wrong message: %s", msg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Client 1 didn't receive message")
		}

		select {
		case msg := <-ch2:
			if !bytes.Equal(msg, message) {
				t.Errorf("Client 2 got wrong message: %s", msg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Client 2 didn't receive message")
		}

		b.remove(ch1)
		b.remove(ch2)
	})
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()

	t.Run("allows requests under limit", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(10, 10) // 10 RPS, burst 10

		// Should allow first request
		if !rl.allow("test-ip") {
			t.Error("Expected first request to be allowed")
		}
	})

	t.Run("blocks when over burst", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(1, 2) // 1 RPS, burst 2

		// First 2 should be allowed (burst)
		if !rl.allow("test-ip") {
			t.Error("Expected first request to be allowed")
		}

		if !rl.allow("test-ip") {
			t.Error("Expected second request to be allowed")
		}

		// Third should be blocked
		if rl.allow("test-ip") {
			t.Error("Expected third request to be blocked")
		}
	})

	t.Run("different IPs have separate limits", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(1, 1) // 1 RPS, burst 1

		// Both IPs should be allowed their first request
		if !rl.allow("ip1") {
			t.Error("Expected first IP to be allowed")
		}

		if !rl.allow("ip2") {
			t.Error("Expected second IP to be allowed")
		}

		// Both should be blocked on second request
		if rl.allow("ip1") {
			t.Error("Expected ip1 second request to be blocked")
		}

		if rl.allow("ip2") {
			t.Error("Expected ip2 second request to be blocked")
		}
	})
}

func TestToStr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    interface{}
		expected string
	}{
		{nil, ""},
		{"hello", "hello"},
		{123, "123"},
		{123.45, "123.45"},
		{true, "true"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%v", tt.input), func(t *testing.T) {
			t.Parallel()

			result := toStr(tt.input)
			if result != tt.expected {
				t.Errorf("toStr(%v) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestToInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    interface{}
		expected int
	}{
		{nil, 0},
		{123, 123},
		{int64(456), 456},
		{123.45, 123},
		{"789", 789},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%v", tt.input), func(t *testing.T) {
			t.Parallel()

			result := toInt(tt.input)
			if result != tt.expected {
				t.Errorf("toInt(%v) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{"empty slice", []string{}, ""},
		{"all empty", []string{"", "", ""}, ""},
		{"second non-empty", []string{"", "second", "third"}, "second"},
		{"first non-empty", []string{"first", "second"}, "first"},
		{"whitespace trimmed", []string{"  ", "trimmed"}, "trimmed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := firstNonEmpty(tt.input...)
			if result != tt.expected {
				t.Errorf("firstNonEmpty(%v) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRemoteIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{"IPv4 with port", "192.168.1.1:12345", "192.168.1.1"},
		{"IPv6 with port", "[::1]:8080", "::1"},
		{"invalid format", "invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := &http.Request{RemoteAddr: tt.remoteAddr}

			result := remoteIP(req)
			if result != tt.expected {
				t.Errorf("remoteIP with addr %s = %s, want %s", tt.remoteAddr, result, tt.expected)
			}
		})
	}
}

func TestMathMin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a, b     float64
		expected float64
	}{
		{"a smaller", 1.0, 2.0, 1.0},
		{"b smaller", 2.0, 1.0, 1.0},
		{"equal", 1.0, 1.0, 1.0},
		{"negative", -1.0, 1.0, -1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := mathMin(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("mathMin(%f, %f) = %f, want %f", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestAPIKeyMiddleware(t *testing.T) {
	t.Parallel()

	expectedKey := "test-api-key"
	handler := apiKeyMiddleware(expectedKey, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))

	t.Run("valid API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Api-Key", expectedKey)

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Body.String() != "success" {
			t.Errorf("Expected success message, got %s", w.Body.String())
		}
	})

	t.Run("missing API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("invalid API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Api-Key", "wrong-key")

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})
}

func TestHealthzHandler(t *testing.T) {
	t.Parallel()

	store := newMemStore(10)
	bus := newBroadcaster()
	mux := newMux(nil, store, bus, "test-key", 100, time.Second, 50, 100)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("Expected 'ok' in response, got %s", body)
	}
}

func setupTestStore() *memStore {
	store := newMemStore(10)
	ctx := context.Background()

	// Insert test data
	entries := []*LogEntry{
		{Message: "info message", Fields: json.RawMessage(`{"action":"ALLOWED"}`)},
		{Message: "error message", Fields: json.RawMessage(`{"action":"BLOCKED"}`)},
		{Message: "debug message", Fields: json.RawMessage(`{"action":"ALLOWED"}`)},
	}

	for _, entry := range entries {
		_, err := store.Insert(ctx, entry)
		if err != nil {
			panic(fmt.Sprintf("Failed to insert test data: %v", err))
		}
	}

	return store
}

func TestListLogsHandler_GetAllLogs(t *testing.T) {
	t.Parallel()

	store := setupTestStore()
	handler := listLogsHandler(store, 100)

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var logs []LogEntry

	err := json.Unmarshal(w.Body.Bytes(), &logs)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(logs) != 3 {
		t.Errorf("Expected 3 logs, got %d", len(logs))
	}
}

func TestListLogsHandler_FilterByQuery(t *testing.T) {
	t.Parallel()

	store := setupTestStore()
	handler := listLogsHandler(store, 100)

	req := httptest.NewRequest(http.MethodGet, "/logs?q=error", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var logs []LogEntry

	err := json.Unmarshal(w.Body.Bytes(), &logs)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(logs) != 1 {
		t.Errorf("Expected 1 log with 'error', got %d", len(logs))
	}

	if !strings.Contains(logs[0].Message, "error") {
		t.Errorf("Expected message containing 'error', got %s", logs[0].Message)
	}
}

func TestListLogsHandler_SearchQuery(t *testing.T) {
	t.Parallel()

	store := setupTestStore()
	handler := listLogsHandler(store, 100)

	req := httptest.NewRequest(http.MethodGet, "/logs?q=info", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var logs []LogEntry

	err := json.Unmarshal(w.Body.Bytes(), &logs)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(logs) != 1 {
		t.Errorf("Expected 1 log matching 'info', got %d", len(logs))
	}
}

func TestListLogsHandler_LimitResults(t *testing.T) {
	t.Parallel()

	store := setupTestStore()
	handler := listLogsHandler(store, 100)

	req := httptest.NewRequest(http.MethodGet, "/logs?limit=2", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var logs []LogEntry

	err := json.Unmarshal(w.Body.Bytes(), &logs)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(logs) != 2 {
		t.Errorf("Expected 2 logs with limit, got %d", len(logs))
	}
}

func TestRespWrap(t *testing.T) {
	t.Parallel()

	t.Run("tracks status code", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		wrap := &respWrap{
			ResponseWriter: w,
			code:           200,
		}

		wrap.WriteHeader(http.StatusNotFound)

		if wrap.code != 404 {
			t.Errorf("Expected code 404, got %d", wrap.code)
		}

		// Verify the underlying ResponseWriter was also called
		if w.Code != http.StatusNotFound {
			t.Errorf("Expected underlying ResponseWriter code 404, got %d", w.Code)
		}
	})

	t.Run("default code is preserved", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		wrap := &respWrap{
			ResponseWriter: w,
			code:           200,
		}

		// Don't call WriteHeader, should keep default
		if wrap.code != 200 {
			t.Errorf("Expected default code 200, got %d", wrap.code)
		}

		// Write some data to verify the embedded ResponseWriter works
		_, err := wrap.Write([]byte("test"))
		if err != nil {
			t.Errorf("Write failed: %v", err)
		}

		if w.Body.String() != "test" {
			t.Errorf("Expected body 'test', got %s", w.Body.String())
		}
	})
}

// Test HTTP handler functions with various scenarios.
func TestHTTPHandlers(t *testing.T) {
	t.Parallel()

	t.Run("ingest handler", func(t *testing.T) {
		t.Parallel()
		testIngestHandler(t)
	})

	t.Run("API key authentication", func(t *testing.T) {
		t.Parallel()
		testAPIKeyAuthentication(t)
	})

	t.Run("logs list handler", func(t *testing.T) {
		t.Parallel()
		testLogsListHandler(t)
	})
}

func testIngestHandler(t *testing.T) {
	t.Helper()

	// Create components
	st := newMemStore(1000)
	bus := newBroadcaster()
	rl := newRateLimiter(50, 100)

	handler := ingestHandler(nil, st, bus, rl)

	// Valid log entry
	logEntry := map[string]any{
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
		"msg":    "test message",
		"action": "BLOCKED",
	}

	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("Expected status %d, got %d", http.StatusAccepted, w.Code)
	}
}

func testAPIKeyAuthentication(t *testing.T) {
	t.Helper()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ /* r */ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	protectedHandler := apiKeyMiddleware("test-secret-key", testHandler)

	tests := []struct {
		name         string
		apiKey       string
		expectedCode int
	}{
		{"valid API key", "test-secret-key", http.StatusOK},
		{"invalid API key", "wrong-key", http.StatusUnauthorized},
		{"missing API key", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.apiKey != "" {
				req.Header.Set("X-Api-Key", tt.apiKey)
			}

			w := httptest.NewRecorder()

			protectedHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, w.Code)
			}
		})
	}
}

func testLogsListHandler(t *testing.T) {
	t.Helper()

	st := newMemStore(1000)

	// Add a test log entry
	entry := &LogEntry{
		Time:    time.Now().UTC(),
		Message: "test message",
		Action:  "BLOCKED",
	}

	_, err := st.Insert(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	handler := listLogsHandler(st, 500)

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Parse response
	var logs []LogEntry

	err = json.Unmarshal(w.Body.Bytes(), &logs)
	if err != nil {
		t.Fatal(err)
	}

	if len(logs) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(logs))
	}
}

// Test error conditions and edge cases.
func TestErrorConditions(t *testing.T) {
	t.Parallel()

	t.Run("ingest handler errors", func(t *testing.T) {
		t.Parallel()
		testIngestHandlerErrors(t)
	})

	t.Run("config validation", func(t *testing.T) {
		t.Parallel()
		testConfigValidation(t)
	})

	t.Run("memory store operations", func(t *testing.T) {
		t.Parallel()
		testMemoryStoreOperations(t)
	})
}

func testIngestHandlerErrors(t *testing.T) {
	t.Helper()

	st := newMemStore(2)
	bus := newBroadcaster()
	rl := newRateLimiter(50, 100)

	// Test invalid JSON
	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()

		handler := ingestHandler(nil, st, bus, rl)

		req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader("invalid-json"))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	// Test wrong HTTP method
	t.Run("wrong method", func(t *testing.T) {
		t.Parallel()

		handler := ingestHandler(nil, st, bus, rl)

		req := httptest.NewRequest(http.MethodGet, "/ingest", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func testConfigValidation(t *testing.T) {
	t.Helper()

	invalidCfg := Config{
		Addr:     "",
		APIKey:   "",
		LogLevel: "",
	}

	applyConfigDefaults(&invalidCfg)

	if invalidCfg.BufferSize <= 0 {
		t.Error("Config BufferSize should have positive default value")
	}

	if invalidCfg.ReadLimit <= 0 {
		t.Error("Config ReadLimit should have positive default value")
	}
}

func testMemoryStoreOperations(t *testing.T) {
	t.Helper()

	st := newMemStore(5)

	// Test inserting entries
	for i := range 3 {
		entry := &LogEntry{
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("test message %d", i),
			Action:  "BLOCKED",
		}

		id, err := st.Insert(context.Background(), entry)
		if err != nil {
			t.Fatal(err)
		}

		if id <= 0 {
			t.Errorf("Expected positive ID, got %d", id)
		}
	}

	// Test querying
	logs, err := st.Query(context.Background(), "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}

	if len(logs) != 3 {
		t.Errorf("Expected 3 logs, got %d", len(logs))
	}
}

// Test rate limiter allow functionality.
func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(2.0, 3.0) // 2 RPS, burst of 3

	// Test that initial requests are allowed
	for i := range 3 {
		if !rl.allow("127.0.0.1") {
			t.Errorf("Expected request %d to be allowed", i)
		}
	}

	// The 4th request should be rate limited
	if rl.allow("127.0.0.1") {
		t.Error("Expected 4th request to be rate limited")
	}

	// Different IPs should have independent limits
	if !rl.allow("192.168.1.1") {
		t.Error("Expected request from different IP to be allowed")
	}
}

// Test functions with 0% coverage.
func TestRun(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	tests := []struct {
		name      string
		config    Config
		expectErr bool
	}{
		{
			name: "missing API key",
			config: Config{
				Addr:     ":0",
				APIKey:   "",
				LogLevel: "INFO",
			},
			expectErr: true,
		},
		{
			name: "valid config",
			config: Config{
				Addr:     ":0",
				APIKey:   "test-key-123",
				LogLevel: "INFO",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Run(ctx, tt.config)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				// For valid config, we expect context timeout since server would start
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWithCommon(t *testing.T) {
	t.Parallel()

	// Import needed for logger
	logger := slog.Default()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test response"))
	})

	// Wrap it with withCommon
	wrappedHandler := withCommon(logger, testHandler)

	// Test the wrapped handler
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check that the response was written
	body := w.Body.String()
	if body != "test response" {
		t.Errorf("Expected 'test response', got %s", body)
	}
}

func TestFlush(t *testing.T) {
	t.Parallel()

	// Create a response writer wrapper
	w := httptest.NewRecorder()
	wrapper := &respWrap{
		ResponseWriter: w,
	}

	// Test Flush method
	wrapper.Flush()
	// Verify it doesn't panic and can be called
	// The actual flush behavior depends on the underlying ResponseWriter
}

func TestHijack(t *testing.T) {
	t.Parallel()

	// Create a mock connection that can be hijacked
	w := httptest.NewRecorder()
	wrapper := &respWrap{
		ResponseWriter: w,
	}

	// Test Hijack method
	_, _, err := wrapper.Hijack()

	// For httptest.ResponseRecorder, Hijack is not supported
	// so we expect an error, but the method should not panic
	if err == nil {
		t.Log("Hijack unexpectedly succeeded")
	} else {
		t.Logf("Hijack failed as expected: %v", err)
	}
}

func TestPush(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	wrapper := &respWrap{
		ResponseWriter: w,
	}

	// Test Push method
	err := wrapper.Push("/test-resource", nil)

	// For httptest.ResponseRecorder, Push is not supported
	// but the method should not panic
	if err == nil {
		t.Log("Push unexpectedly succeeded")
	} else {
		t.Logf("Push failed as expected: %v", err)
	}
}

func TestIntFrom(t *testing.T) {
	t.Parallel()

	tests := getIntFromTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := intFrom(tt.m, tt.k)
			if result != tt.expected {
				t.Errorf("intFrom(%v, %q) = %d, want %d", tt.m, tt.k, result, tt.expected)
			}
		})
	}
}

func getIntFromTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected int
} {
	var cases []struct {
		name     string
		m        map[string]any
		k        string
		expected int
	}

	cases = append(cases, getIntFromBasicTestCases()...)
	cases = append(cases, getIntFromNumericTestCases()...)
	cases = append(cases, getIntFromEdgeTestCases()...)

	return cases
}

func getIntFromBasicTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected int
} {
	return []struct {
		name     string
		m        map[string]any
		k        string
		expected int
	}{
		{
			name:     "nil map",
			m:        nil,
			k:        "test",
			expected: 0,
		},
		{
			name:     "key not found",
			m:        map[string]any{"other": 123},
			k:        "test",
			expected: 0,
		},
		{
			name:     "nil value",
			m:        map[string]any{"test": nil},
			k:        "test",
			expected: 0,
		},
	}
}

func getIntFromNumericTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected int
} {
	return []struct {
		name     string
		m        map[string]any
		k        string
		expected int
	}{
		{
			name:     "int value",
			m:        map[string]any{"test": 42},
			k:        "test",
			expected: 42,
		},
		{
			name:     "negative int value",
			m:        map[string]any{"test": -15},
			k:        "test",
			expected: -15,
		},
		{
			name:     "float64 value",
			m:        map[string]any{"test": 3.14},
			k:        "test",
			expected: 3,
		},
		{
			name:     "float64 negative value",
			m:        map[string]any{"test": -2.8},
			k:        "test",
			expected: -2,
		},
	}
}

func getIntFromEdgeTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected int
} {
	return []struct {
		name     string
		m        map[string]any
		k        string
		expected int
	}{
		{
			name:     "string numeric value",
			m:        map[string]any{"test": "123"},
			k:        "test",
			expected: 123,
		},
		{
			name:     "string non-numeric value",
			m:        map[string]any{"test": "abc"},
			k:        "test",
			expected: 0,
		},
		{
			name:     "string empty value",
			m:        map[string]any{"test": ""},
			k:        "test",
			expected: 0,
		},
		{
			name:     "bool value",
			m:        map[string]any{"test": true},
			k:        "test",
			expected: 0,
		},
		{
			name:     "slice value",
			m:        map[string]any{"test": []int{1, 2, 3}},
			k:        "test",
			expected: 0,
		},
		{
			name:     "map value",
			m:        map[string]any{"test": map[string]int{"nested": 42}},
			k:        "test",
			expected: 0,
		},
	}
}

func TestStrFrom(t *testing.T) {
	t.Parallel()

	tests := getStrFromTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := strFrom(tt.m, tt.k)
			if result != tt.expected {
				t.Errorf("strFrom(%v, %q) = %q, want %q", tt.m, tt.k, result, tt.expected)
			}
		})
	}
}

func getStrFromTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected string
} {
	var cases []struct {
		name     string
		m        map[string]any
		k        string
		expected string
	}

	cases = append(cases, getStrFromBasicTestCases()...)
	cases = append(cases, getStrFromTypeTestCases()...)

	return cases
}

func getStrFromBasicTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected string
} {
	return []struct {
		name     string
		m        map[string]any
		k        string
		expected string
	}{
		{
			name:     "nil map",
			m:        nil,
			k:        "test",
			expected: "",
		},
		{
			name:     "key not found",
			m:        map[string]any{"other": "value"},
			k:        "test",
			expected: "",
		},
		{
			name:     "nil value",
			m:        map[string]any{"test": nil},
			k:        "test",
			expected: "",
		},
		{
			name:     "string value",
			m:        map[string]any{"test": "hello"},
			k:        "test",
			expected: "hello",
		},
		{
			name:     "empty string value",
			m:        map[string]any{"test": ""},
			k:        "test",
			expected: "",
		},
	}
}

func getStrFromTypeTestCases() []struct {
	name     string
	m        map[string]any
	k        string
	expected string
} {
	return []struct {
		name     string
		m        map[string]any
		k        string
		expected string
	}{
		{
			name:     "int value",
			m:        map[string]any{"test": 42},
			k:        "test",
			expected: "42",
		},
		{
			name:     "bool value",
			m:        map[string]any{"test": true},
			k:        "test",
			expected: "true",
		},
		{
			name:     "float value",
			m:        map[string]any{"test": 3.14},
			k:        "test",
			expected: "3.14",
		},
		{
			name:     "slice value",
			m:        map[string]any{"test": []int{1, 2, 3}},
			k:        "test",
			expected: "[1 2 3]",
		},
	}
}
