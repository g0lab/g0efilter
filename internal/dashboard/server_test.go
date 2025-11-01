//nolint:testpackage // Testing internal functions
package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testActionBlocked = "BLOCKED"
	testActionAllowed = "ALLOWED"
)

// TestMemStore tests the in-memory store operations.
//
//nolint:cyclop,funlen
func TestMemStore(t *testing.T) {
	t.Parallel()

	t.Run("Insert and Query", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(10)
		ctx := context.Background()

		entry := &LogEntry{
			Time:      time.Now(),
			Message:   "test message",
			Action:    testActionBlocked,
			SourceIP:  "192.168.1.1",
			Protocol:  "TCP",
			RemoteIP:  "10.0.0.1",
			PolicyHit: "test-policy",
		}

		id, err := store.Insert(ctx, entry)
		if err != nil {
			t.Fatalf("Insert failed: %v", err)
		}

		if id != 1 {
			t.Errorf("First insert ID = %d, want 1", id)
		}

		results, err := store.Query(ctx, "", 0, 10)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Query returned %d results, want 1", len(results))
		}

		if results[0].Message != "test message" {
			t.Errorf("Message = %s, want 'test message'", results[0].Message)
		}

		if results[0].Action != testActionBlocked {
			t.Errorf("Action = %s, want %s", results[0].Action, testActionBlocked)
		}
	})

	t.Run("Clear", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(10)
		ctx := context.Background()

		// Insert some entries
		for range 5 {
			_, _ = store.Insert(ctx, &LogEntry{
				Time:    time.Now(),
				Message: "test",
				Action:  "ALLOWED",
			})
		}

		results, _ := store.Query(ctx, "", 0, 10)
		if len(results) != 5 {
			t.Fatalf("Before clear: got %d entries, want 5", len(results))
		}

		err := store.Clear(ctx)
		if err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		results, _ = store.Query(ctx, "", 0, 10)
		if len(results) != 0 {
			t.Errorf("After clear: got %d entries, want 0", len(results))
		}
	})

	t.Run("Circular buffer wrap", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(3)
		ctx := context.Background()

		// Insert 5 entries into a buffer of size 3
		for i := 1; i <= 5; i++ {
			_, _ = store.Insert(ctx, &LogEntry{
				Time:    time.Now(),
				Message: "msg" + string(rune('0'+i)),
				Action:  "ALLOWED",
			})
		}

		results, _ := store.Query(ctx, "", 0, 10)
		if len(results) != 3 {
			t.Errorf("Circular buffer: got %d entries, want 3", len(results))
		}
	})

	t.Run("Query with filter", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(10)
		ctx := context.Background()

		_, _ = store.Insert(ctx, &LogEntry{
			Time:     time.Now(),
			Message:  "blocked connection",
			Action:   testActionBlocked,
			SourceIP: "192.168.1.1",
		})

		_, _ = store.Insert(ctx, &LogEntry{
			Time:     time.Now(),
			Message:  "allowed connection",
			Action:   testActionAllowed,
			SourceIP: "192.168.1.2",
		})

		results, _ := store.Query(ctx, "blocked", 0, 10)
		if len(results) != 1 {
			t.Errorf("Filtered query: got %d results, want 1", len(results))
		}

		if results[0].Action != testActionBlocked {
			t.Errorf("Filtered result action = %s, want %s", results[0].Action, testActionBlocked)
		}
	})

	t.Run("Query with sinceID", func(t *testing.T) {
		t.Parallel()

		store := newMemStore(10)
		ctx := context.Background()

		id1, _ := store.Insert(ctx, &LogEntry{Time: time.Now(), Message: "first", Action: "ALLOWED"})
		_, _ = store.Insert(ctx, &LogEntry{Time: time.Now(), Message: "second", Action: "ALLOWED"})
		_, _ = store.Insert(ctx, &LogEntry{Time: time.Now(), Message: "third", Action: "ALLOWED"})

		results, _ := store.Query(ctx, "", id1, 10)
		if len(results) != 2 {
			t.Errorf("Query with sinceID: got %d results, want 2", len(results))
		}
	})
}

// TestExtractFieldsMap tests the field extraction helper.
func TestExtractFieldsMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "nested fields merged with top-level",
			input: map[string]any{
				"fields": map[string]any{
					"custom_field": "value1",
				},
				"action":    "BLOCKED",
				"source_ip": "192.168.1.1",
				"version":   "1.0.0",
			},
			expected: map[string]any{
				"custom_field": "value1",
				"action":       "BLOCKED",
				"source_ip":    "192.168.1.1",
				"version":      "1.0.0",
			},
		},
		{
			name: "no nested fields",
			input: map[string]any{
				"action":    "ALLOWED",
				"source_ip": "10.0.0.1",
			},
			expected: map[string]any{
				"action":    "ALLOWED",
				"source_ip": "10.0.0.1",
			},
		},
		{
			name: "nil values excluded",
			input: map[string]any{
				"action":    "BLOCKED",
				"source_ip": nil,
			},
			expected: map[string]any{
				"action": "BLOCKED",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := extractFieldsMap(tt.input)

			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("Field %s = %v, want %v", k, result[k], v)
				}
			}
		})
	}
}

// TestDeriveProtocol tests protocol derivation logic.
func TestDeriveProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{
			name:     "explicit protocol",
			input:    map[string]any{"protocol": "TCP"},
			expected: "TCP",
		},
		{
			name:     "derived from http component",
			input:    map[string]any{"component": "http"},
			expected: "TCP",
		},
		{
			name:     "derived from https component",
			input:    map[string]any{"component": "https"},
			expected: "TCP",
		},
		{
			name:     "derived from dns component",
			input:    map[string]any{"component": "dns"},
			expected: "UDP",
		},
		{
			name:     "no protocol info",
			input:    map[string]any{},
			expected: "",
		},
		{
			name:     "unknown component",
			input:    map[string]any{"component": "unknown"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := deriveProtocol(tt.input)
			if result != tt.expected {
				t.Errorf("deriveProtocol() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGetStringFromPayload tests string extraction from payload.
func TestGetStringFromPayload(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"field1": "value1",
		"field2": "",
		"field3": "value3",
	}

	tests := []struct {
		name     string
		keys     []string
		expected string
	}{
		{
			name:     "first key exists",
			keys:     []string{"field1"},
			expected: "value1",
		},
		{
			name:     "fallback to second key",
			keys:     []string{"field2", "field3"},
			expected: "value3",
		},
		{
			name:     "no match",
			keys:     []string{"nonexistent"},
			expected: "",
		},
		{
			name:     "empty string skipped",
			keys:     []string{"field2", "field1"},
			expected: "value1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := getStringFromPayload(payload, tt.keys...)
			if result != tt.expected {
				t.Errorf("getStringFromPayload() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGetIntFromPayload tests integer extraction from payload.
func TestGetIntFromPayload(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"port":    float64(8080),
		"missing": "not a number",
	}

	if result := getIntFromPayload(payload, "port"); result != 8080 {
		t.Errorf("getIntFromPayload(port) = %d, want 8080", result)
	}

	if result := getIntFromPayload(payload, "missing"); result != 0 {
		t.Errorf("getIntFromPayload(missing) = %d, want 0", result)
	}

	if result := getIntFromPayload(payload, "nonexistent"); result != 0 {
		t.Errorf("getIntFromPayload(nonexistent) = %d, want 0", result)
	}
}

// TestProcessPayload tests the main payload processing logic.
//
//nolint:gocognit,cyclop,funlen
func TestProcessPayload(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	srv := &Server{logger: logger}

	t.Run("valid BLOCKED payload", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":         "connection blocked",
			"action":      "blocked",
			"source_ip":   "192.168.1.1",
			"source_port": float64(12345),
			"protocol":    "TCP",
			"version":     "1.0.0",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry == nil {
			t.Fatal("processPayload returned nil for valid payload")
		}

		if entry.Message != "connection blocked" {
			t.Errorf("Message = %s, want 'connection blocked'", entry.Message)
		}

		if entry.Action != testActionBlocked {
			t.Errorf("Action = %s, want %s", entry.Action, testActionBlocked)
		}

		if entry.SourceIP != "192.168.1.1" {
			t.Errorf("SourceIP = %s, want 192.168.1.1", entry.SourceIP)
		}

		if entry.SourcePort != 12345 {
			t.Errorf("SourcePort = %d, want 12345", entry.SourcePort)
		}

		if entry.Protocol != "TCP" {
			t.Errorf("Protocol = %s, want TCP", entry.Protocol)
		}

		if entry.RemoteIP != "10.0.0.1" {
			t.Errorf("RemoteIP = %s, want 10.0.0.1", entry.RemoteIP)
		}

		if entry.Version != "1.0.0" {
			t.Errorf("Version = %s, want 1.0.0", entry.Version)
		}
	})

	t.Run("empty message returns nil", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":    "",
			"action": "BLOCKED",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry != nil {
			t.Error("processPayload should return nil for empty message")
		}
	})

	t.Run("invalid action returns nil", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":    "test",
			"action": "INVALID",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry != nil {
			t.Error("processPayload should return nil for invalid action")
		}
	})

	t.Run("allowed action", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":    "connection allowed",
			"action": "allowed",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry == nil {
			t.Fatal("processPayload returned nil for ALLOWED action")
		}

		if entry.Action != testActionAllowed {
			t.Errorf("Action = %s, want %s", entry.Action, testActionAllowed)
		}
	})

	t.Run("redirected action filtered out", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":    "connection redirected",
			"action": "REDIRECTED",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry != nil {
			t.Fatal("processPayload should return nil for REDIRECTED action (not shipped to dashboard)")
		}
	})

	t.Run("HTTPS extraction priority", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":       "test",
			"action":    "BLOCKED",
			"http_host": "example.com",
			"host":      "fallback.com",
			"https":     "last.com",
			"qname":     "dns.com",
		}

		entry := srv.processPayload(context.Background(), payload, "10.0.0.1")
		if entry == nil {
			t.Fatal("processPayload returned nil")
		}

		// http_host should be first priority
		if entry.HTTPS != "example.com" {
			t.Errorf("HTTPS = %s, want example.com (http_host priority)", entry.HTTPS)
		}

		if entry.HTTPHost != "example.com" {
			t.Errorf("HTTPHost = %s, want example.com", entry.HTTPHost)
		}
	})
}

// Helper function to create a test server.
func newTestServer() *Server {
	logger := slog.New(slog.DiscardHandler)
	cfg := Config{
		APIKey:     "test-api-key",
		BufferSize: 100,
		ReadLimit:  50,
		RateRPS:    100,
		RateBurst:  200,
	}

	return newServer(logger, cfg)
}

// TestHealthHandler tests the health check endpoint.
func TestHealthHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	var response map[string]string

	err := json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("status = %s, want ok", response["status"])
	}

	if response["service"] != "g0efilter-dashboard" {
		t.Errorf("service = %s, want g0efilter-dashboard", response["service"])
	}
}

// TestIngestHandler tests the log ingestion endpoint.
//
//nolint:funlen
func TestIngestHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	t.Run("single valid log", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg":       "test message",
			"action":    "BLOCKED",
			"source_ip": "192.168.1.1",
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		srv.ingestHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}

		var response map[string]any

		err := json.NewDecoder(w.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		created, ok := response["created"].(float64)
		if !ok || created != 1 {
			t.Errorf("created = %v, want 1", response["created"])
		}
	})

	t.Run("array of logs", func(t *testing.T) {
		t.Parallel()

		payload := []map[string]any{
			{"msg": "test1", "action": "BLOCKED"},
			{"msg": "test2", "action": "ALLOWED"},
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		srv.ingestHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		srv.ingestHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", strings.NewReader("[]"))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		srv.ingestHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

// TestListLogsHandler tests the log listing endpoint.
//
//nolint:cyclop,funlen
func TestListLogsHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	ctx := context.Background()

	// Insert test data
	_, _ = srv.store.Insert(ctx, &LogEntry{
		Time:     time.Now(),
		Message:  "blocked connection",
		Action:   "BLOCKED",
		SourceIP: "192.168.1.1",
	})

	_, _ = srv.store.Insert(ctx, &LogEntry{
		Time:     time.Now(),
		Message:  "allowed connection",
		Action:   "ALLOWED",
		SourceIP: "192.168.1.2",
	})

	t.Run("list all logs", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil)
		w := httptest.NewRecorder()

		srv.listLogsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var logs []LogEntry

		err := json.NewDecoder(w.Body).Decode(&logs)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(logs) != 2 {
			t.Errorf("Got %d logs, want 2", len(logs))
		}
	})

	t.Run("filter by query", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?q=blocked", nil)
		w := httptest.NewRecorder()

		srv.listLogsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var logs []LogEntry

		err := json.NewDecoder(w.Body).Decode(&logs)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(logs) != 1 {
			t.Errorf("Filtered query: got %d logs, want 1", len(logs))
		}

		if logs[0].Action != "BLOCKED" {
			t.Errorf("Action = %s, want BLOCKED", logs[0].Action)
		}
	})

	t.Run("limit results", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=1", nil)
		w := httptest.NewRecorder()

		srv.listLogsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var logs []LogEntry

		err := json.NewDecoder(w.Body).Decode(&logs)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(logs) != 1 {
			t.Errorf("Limited query: got %d logs, want 1", len(logs))
		}
	})
}

// TestClearLogsHandler tests the clear logs endpoint.
func TestClearLogsHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	ctx := context.Background()

	// Insert test data
	_, _ = srv.store.Insert(ctx, &LogEntry{
		Time:    time.Now(),
		Message: "test",
		Action:  "BLOCKED",
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	srv.clearLogsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	var response map[string]string

	err := json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("status = %s, want ok", response["status"])
	}

	// Verify logs are cleared
	logs, _ := srv.store.Query(ctx, "", 0, 10)
	if len(logs) != 0 {
		t.Errorf("After clear: got %d logs, want 0", len(logs))
	}
}

// TestRequireAPIKey tests the API key middleware.
func TestRequireAPIKey(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	handler := srv.requireAPIKey()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("valid API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", nil)
		req.Header.Set("X-Api-Key", "test-api-key")

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("missing API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid API key", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", nil)
		req.Header.Set("X-Api-Key", "wrong-key")

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

// TestRateLimiter tests the rate limiting logic.
func TestRateLimiter(t *testing.T) {
	t.Parallel()

	t.Run("allows requests within limit", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(10, 10) // 10 RPS, burst 10

		for i := range 10 {
			if !rl.Allow("test-client") {
				t.Errorf("Request %d was blocked but should be allowed", i+1)
			}
		}
	})

	t.Run("blocks requests exceeding burst", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(1, 5) // 1 RPS, burst 5

		// First 5 should succeed
		for i := range 5 {
			if !rl.Allow("test-client") {
				t.Errorf("Request %d was blocked but should be allowed", i+1)
			}
		}

		// Next should be blocked
		if rl.Allow("test-client") {
			t.Error("Request should be blocked after exceeding burst")
		}
	})

	t.Run("different keys have separate limits", func(t *testing.T) {
		t.Parallel()

		rl := newRateLimiter(1, 2) // 1 RPS, burst 2

		// Client 1 uses its burst
		if !rl.Allow("client1") {
			t.Error("Client1 first request should be allowed")
		}

		if !rl.Allow("client1") {
			t.Error("Client1 second request should be allowed")
		}

		// Client 2 should still have its full burst available
		if !rl.Allow("client2") {
			t.Error("Client2 first request should be allowed")
		}

		if !rl.Allow("client2") {
			t.Error("Client2 second request should be allowed")
		}
	})
}

// TestRoutes tests that all routes are properly registered.
func TestRoutes(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	router := srv.routes()

	tests := []struct {
		method     string
		path       string
		wantStatus int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/", http.StatusOK}, // UI handler

		// Public endpoints (protected by Traefik in production)
		{http.MethodGet, "/api/v1/logs", http.StatusOK},
		{http.MethodDelete, "/api/v1/logs", http.StatusOK},
		// Note: /api/v1/events is SSE and runs indefinitely, tested separately
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tt.wantStatus > 0 && w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.wantStatus)
			} else if tt.wantStatus == 0 && w.Code == http.StatusNotFound {
				t.Errorf("Route %s %s returned 404", tt.method, tt.path)
			}
		})
	}
}

// TestRunValidation tests the Run function's validation.
func TestRunValidation(t *testing.T) {
	t.Parallel()

	t.Run("missing API key", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			APIKey: "",
		}

		err := Run(context.Background(), cfg)
		if !errors.Is(err, errAPIKeyRequired) {
			t.Errorf("Expected errAPIKeyRequired, got %v", err)
		}
	})

	t.Run("whitespace-only API key", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			APIKey: "   ",
		}

		err := Run(context.Background(), cfg)
		if !errors.Is(err, errAPIKeyRequired) {
			t.Errorf("Expected errAPIKeyRequired for whitespace key, got %v", err)
		}
	})
}

// BenchmarkProcessPayload benchmarks the payload processing.
func BenchmarkProcessPayload(b *testing.B) {
	logger := slog.New(slog.DiscardHandler)
	srv := &Server{logger: logger}

	payload := map[string]any{
		"msg":              "test message",
		"action":           "BLOCKED",
		"source_ip":        "192.168.1.1",
		"source_port":      float64(12345),
		"destination_ip":   "10.0.0.1",
		"destination_port": float64(80),
		"protocol":         "TCP",
		"version":          "1.0.0",
	}

	for b.Loop() {
		_ = srv.processPayload(context.Background(), payload, "10.0.0.1")
	}
}

// BenchmarkMemStoreInsert benchmarks store insertions.
func BenchmarkMemStoreInsert(b *testing.B) {
	store := newMemStore(10000)
	ctx := context.Background()

	entry := &LogEntry{
		Time:     time.Now(),
		Message:  "test message",
		Action:   "BLOCKED",
		SourceIP: "192.168.1.1",
	}

	for b.Loop() {
		_, _ = store.Insert(ctx, entry)
	}
}

// BenchmarkMemStoreQuery benchmarks store queries.
func BenchmarkMemStoreQuery(b *testing.B) {
	store := newMemStore(1000)
	ctx := context.Background()

	// Populate store
	for range 1000 {
		_, _ = store.Insert(ctx, &LogEntry{
			Time:     time.Now(),
			Message:  "test message",
			Action:   "BLOCKED",
			SourceIP: "192.168.1.1",
		})
	}

	for b.Loop() {
		_, _ = store.Query(ctx, "", 0, 100)
	}
}

// TestBroadcaster tests the SSE broadcaster.
func TestBroadcaster(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()

	// Create a subscriber
	ch := bc.Add()

	// Send a message
	testMsg := []byte("test message")
	bc.Send(testMsg)

	// Verify we receive it
	select {
	case msg := <-ch:
		if string(msg) != string(testMsg) {
			t.Errorf("Received %s, want %s", msg, testMsg)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for broadcast message")
	}

	// Remove subscriber
	bc.Remove(ch)

	// Verify channel is closed after removal
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Channel should be closed after removal")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Channel should be closed immediately after removal")
	}
}

// TestBroadcasterMultipleClients tests broadcasting to multiple clients.
func TestBroadcasterMultipleClients(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()

	// Create multiple subscribers
	ch1 := bc.Add()
	ch2 := bc.Add()
	ch3 := bc.Add()

	// Send a message
	testMsg := []byte("broadcast to all")
	bc.Send(testMsg)

	// Verify all receive it
	for i, ch := range []chan []byte{ch1, ch2, ch3} {
		select {
		case msg := <-ch:
			if string(msg) != string(testMsg) {
				t.Errorf("Client %d received %s, want %s", i+1, msg, testMsg)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("Client %d timeout waiting for message", i+1)
		}
	}

	// Cleanup
	bc.Remove(ch1)
	bc.Remove(ch2)
	bc.Remove(ch3)
}

// TestMain can be used for setup/teardown if needed.
func TestMain(m *testing.M) {
	// Suppress logger output during tests
	slog.SetDefault(slog.New(slog.DiscardHandler))

	os.Exit(m.Run())
}
