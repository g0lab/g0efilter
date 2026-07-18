//nolint:testpackage // Testing internal functions
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestUnblockStore_Add(t *testing.T) {
	t.Parallel()

	t.Run("adds new request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		if id == "" {
			t.Error("Add returned empty ID")
		}

		pending := store.GetPending()
		if len(pending) != 1 {
			t.Fatalf("GetPending returned %d items, want 1", len(pending))
		}

		if pending[0].Type != "domain" {
			t.Errorf("Type = %s, want domain", pending[0].Type)
		}

		if pending[0].Value != "example.com" {
			t.Errorf("Value = %s, want example.com", pending[0].Value)
		}
	})

	t.Run("deduplicates same request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id1 := store.Add("domain", "example.com", "host1")
		id2 := store.Add("domain", "example.com", "host1")

		if id1 != id2 {
			t.Errorf("Duplicate request got different IDs: %s vs %s", id1, id2)
		}

		pending := store.GetPending()
		if len(pending) != 1 {
			t.Errorf("GetPending returned %d items, want 1 (deduped)", len(pending))
		}
	})

	t.Run("different targets are not duplicates", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		store.Add("domain", "example.com", "host1")
		store.Add("domain", "example.com", "host2")
		store.Add("domain", "example.com", "") // all hosts

		pending := store.GetPending()
		if len(pending) != 3 {
			t.Errorf("GetPending returned %d items, want 3", len(pending))
		}
	})
}

func TestUnblockStore_GetPendingForHost(t *testing.T) {
	t.Parallel()

	store := newUnblockStore()
	store.Add("domain", "all-hosts.com", "")       // targets all
	store.Add("domain", "host1-only.com", "host1") // targets host1
	store.Add("domain", "host2-only.com", "host2") // targets host2
	store.Add("ip", "192.168.1.1", "host1")        // targets host1

	t.Run("host1 gets targeted and global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host1")
		if len(pending) != 3 {
			t.Errorf("host1 got %d requests, want 3", len(pending))
		}

		values := make(map[string]bool)
		for _, req := range pending {
			values[req.Value] = true
		}

		if !values["all-hosts.com"] {
			t.Error("host1 should get all-hosts.com")
		}

		if !values["host1-only.com"] {
			t.Error("host1 should get host1-only.com")
		}

		if !values["192.168.1.1"] {
			t.Error("host1 should get 192.168.1.1")
		}
	})

	t.Run("host2 gets targeted and global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host2")
		if len(pending) != 2 {
			t.Errorf("host2 got %d requests, want 2", len(pending))
		}
	})

	t.Run("host3 gets only global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host3")
		if len(pending) != 1 {
			t.Errorf("host3 got %d requests, want 1", len(pending))
		}

		if pending[0].Value != "all-hosts.com" {
			t.Errorf("host3 should only get all-hosts.com, got %s", pending[0].Value)
		}
	})
}

func TestUnblockStore_Acknowledge(t *testing.T) {
	t.Parallel()

	t.Run("acknowledges existing request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		ok := store.Acknowledge(id)
		if !ok {
			t.Error("Acknowledge returned false for existing ID")
		}

		pending := store.GetPending()
		if len(pending) != 0 {
			t.Errorf("After ack, GetPending returned %d items, want 0", len(pending))
		}
	})

	t.Run("returns false for non-existent ID", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		ok := store.Acknowledge("nonexistent")

		if ok {
			t.Error("Acknowledge returned true for non-existent ID")
		}
	})

	t.Run("double acknowledge returns false", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		ok1 := store.Acknowledge(id)
		ok2 := store.Acknowledge(id)

		if !ok1 {
			t.Error("First Acknowledge should return true")
		}

		if ok2 {
			t.Error("Second Acknowledge should return false")
		}
	})
}

//nolint:gocognit,cyclop,funlen // Test function with multiple subtests
func TestUnblockHandlers(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	newTestServer := func() *Server {
		return &Server{
			logger:       lg,
			store:        newMemStore(100),
			broadcaster:  newBroadcaster(),
			unblockStore: newUnblockStore(),
			apiKeys:      newMemAPIKeyStore("test-key"),
			readLimit:    100,
			rateLimiter:  newRateLimiter(50, 100),
		}
	}

	t.Run("POST /api/v1/unblocks creates request", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"domain","value":"example.com","target_hostname":"host1"}`
		bodyReader := strings.NewReader(body)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bodyReader)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusCreated)
		}

		var resp map[string]string

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if resp["id"] == "" {
			t.Error("Response missing id")
		}

		if resp["status"] != "pending" {
			t.Errorf("Status = %s, want pending", resp["status"])
		}

		// Verify it's in the store
		pending := srv.unblockStore.GetPending()
		if len(pending) != 1 {
			t.Fatalf("Store has %d items, want 1", len(pending))
		}
	})

	t.Run("POST /api/v1/unblocks rejects invalid type", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"invalid","value":"example.com"}`
		bodyReader := strings.NewReader(body)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bodyReader)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("POST /api/v1/unblocks rejects empty value", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"domain","value":""}`
		bodyReader := strings.NewReader(body)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bodyReader)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("GET /api/v1/unblocks returns all pending", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		srv.unblockStore.Add("domain", "example1.com", "")
		srv.unblockStore.Add("ip", "192.168.1.1", "host1")

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks", nil)
		rec := httptest.NewRecorder()

		srv.listUnblocksHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		var resp struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(resp.Pending) != 2 {
			t.Errorf("Got %d pending, want 2", len(resp.Pending))
		}
	})

	t.Run("GET /api/v1/unblocks?hostname= filters by host", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		srv.unblockStore.Add("domain", "all-hosts.com", "")       // all
		srv.unblockStore.Add("domain", "host1-only.com", "host1") // host1 only

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks?hostname=host1", nil)
		rec := httptest.NewRecorder()

		srv.listUnblocksHandler(rec, req)

		var resp struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(resp.Pending) != 2 {
			t.Errorf("host1 got %d pending, want 2", len(resp.Pending))
		}

		// Request for host2 should only get the global one
		req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks?hostname=host2", nil)
		rec2 := httptest.NewRecorder()

		srv.listUnblocksHandler(rec2, req2)

		var resp2 struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err2 := json.NewDecoder(rec2.Body).Decode(&resp2)
		if err2 != nil {
			t.Fatalf("Failed to decode response: %v", err2)
		}

		if len(resp2.Pending) != 1 {
			t.Errorf("host2 got %d pending, want 1", len(resp2.Pending))
		}
	})

	t.Run("POST /api/v1/unblocks/ack removes request", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		id := srv.unblockStore.Add("domain", "example.com", "")

		body := `{"id":"` + id + `"}`
		bodyReader := strings.NewReader(body)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks/ack", bodyReader)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.ackUnblockHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		pending := srv.unblockStore.GetPending()
		if len(pending) != 0 {
			t.Errorf("After ack, got %d pending, want 0", len(pending))
		}
	})

	t.Run("POST /api/v1/unblocks/ack returns 404 for unknown ID", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"id":"nonexistent"}`
		bodyReader := strings.NewReader(body)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks/ack", bodyReader)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.ackUnblockHandler(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestGenerateID(t *testing.T) {
	t.Parallel()

	t.Run("generates unique IDs", func(t *testing.T) {
		t.Parallel()

		ids := make(map[string]bool)

		for range 100 {
			id := generateID()
			if ids[id] {
				t.Errorf("Duplicate ID generated: %s", id)
			}

			ids[id] = true
		}
	})

	t.Run("generates 16-character IDs", func(t *testing.T) {
		t.Parallel()

		id := generateID()
		if len(id) != 16 {
			t.Errorf("ID length = %d, want 16", len(id))
		}
	})

	t.Run("generates hex-only characters", func(t *testing.T) {
		t.Parallel()

		id := generateID()
		for _, c := range id {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Errorf("ID %q contains non-hex character %q", id, c)
			}
		}
	})
}

func TestUnblockStore_MaxPending(t *testing.T) {
	t.Parallel()

	store := newUnblockStore()
	store.maxPending = 3 // small cap for testing

	id1 := store.Add("domain", "a.com", "")
	id2 := store.Add("domain", "b.com", "")
	id3 := store.Add("domain", "c.com", "")

	if id1 == "" || id2 == "" || id3 == "" {
		t.Fatal("first 3 adds should succeed")
	}

	// Fourth should be rejected
	id4 := store.Add("domain", "d.com", "")
	if id4 != "" {
		t.Errorf("4th add should return empty string, got %s", id4)
	}

	// Duplicates still work (don't count against cap)
	idDup := store.Add("domain", "a.com", "")
	if idDup != id1 {
		t.Errorf("duplicate should return existing ID %s, got %s", id1, idDup)
	}

	// Acknowledging one frees a slot
	store.Acknowledge(id1)

	id5 := store.Add("domain", "e.com", "")
	if id5 == "" {
		t.Error("add after ack should succeed")
	}
}

func TestUnblockStore_MaxCompleted(t *testing.T) {
	t.Parallel()

	store := newUnblockStore()

	// Add and acknowledge 110 requests to overflow the maxCompleted=100 bound
	for i := range 110 {
		id := store.Add("domain", fmt.Sprintf("d%d.com", i), "")
		if id == "" {
			t.Fatalf("Add %d failed", i)
		}

		if !store.Acknowledge(id) {
			t.Fatalf("Acknowledge %d failed", i)
		}
	}

	completed := store.GetCompleted()
	if len(completed) != 100 {
		t.Errorf("completed length = %d, want 100 (bounded)", len(completed))
	}

	// Oldest entries should have been trimmed - last entry should be d109.com
	last := completed[len(completed)-1]
	if last.Value != "d109.com" {
		t.Errorf("last completed = %s, want d109.com", last.Value)
	}
}

func TestValidateUnblockValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reqType string
		value   string
		wantVal string
		wantErr string
	}{
		{"valid domain", "domain", "example.com", "example.com", ""},
		{"valid subdomain", "domain", "api.example.com", "api.example.com", ""},
		{"valid IPv4", "ip", "192.168.1.1", "192.168.1.1", ""},
		{"valid IPv6", "ip", "::1", "::1", ""},
		{"empty value", "domain", "", "", "value cannot be empty"},
		{"whitespace only", "domain", "   ", "", "value cannot be empty"},
		{"invalid domain with injection", "domain", "evil.com\r\nX-Inject: header", "", "invalid domain"},
		{"invalid domain with script", "domain", "<script>alert(1)</script>", "", "invalid domain"},
		{"invalid IP", "ip", "not-an-ip", "", "invalid ip address"},
		{"domain as IP type", "ip", "example.com", "", "invalid ip address"},
		{"trimmed domain", "domain", "  example.com  ", "example.com", ""},
		{"trimmed IP", "ip", "  10.0.0.1  ", "10.0.0.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			val, errMsg := validateUnblockValue(tt.reqType, tt.value)
			if val != tt.wantVal {
				t.Errorf("value = %q, want %q", val, tt.wantVal)
			}

			if errMsg != tt.wantErr {
				t.Errorf("errMsg = %q, want %q", errMsg, tt.wantErr)
			}
		})
	}
}

func TestCreateUnblockHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &Server{
		logger:       lg,
		store:        newMemStore(100),
		broadcaster:  newBroadcaster(),
		unblockStore: newUnblockStore(),
		apiKeys:      newMemAPIKeyStore("test-key"),
		readLimit:    100,
		rateLimiter:  newRateLimiter(50, 100),
	}

	// Send a body larger than the 4 KiB limit
	bigBody := strings.Repeat("x", 8192)
	bigBodyReader := strings.NewReader(bigBody)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bigBodyReader)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	srv.createUnblockHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d for oversized body", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateUnblockHandler_StoreFull(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	us := newUnblockStore()
	us.maxPending = 1 // allow only 1 pending

	srv := &Server{
		logger:       lg,
		store:        newMemStore(100),
		broadcaster:  newBroadcaster(),
		unblockStore: us,
		apiKeys:      newMemAPIKeyStore("test-key"),
		readLimit:    100,
		rateLimiter:  newRateLimiter(50, 100),
	}

	// First request succeeds
	body1 := `{"type":"domain","value":"example.com"}`
	body1Reader := strings.NewReader(body1)
	req1 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", body1Reader)
	req1.Header.Set("Content-Type", "application/json")

	rec1 := httptest.NewRecorder()
	srv.createUnblockHandler(rec1, req1)

	if rec1.Code != http.StatusCreated {
		t.Fatalf("First request: status = %d, want %d", rec1.Code, http.StatusCreated)
	}

	// Second request hits capacity
	body2 := `{"type":"domain","value":"other.com"}`
	body2Reader := strings.NewReader(body2)
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", body2Reader)
	req2.Header.Set("Content-Type", "application/json")

	rec2 := httptest.NewRecorder()
	srv.createUnblockHandler(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request: status = %d, want %d", rec2.Code, http.StatusTooManyRequests)
	}

	var errResp map[string]string

	err := json.NewDecoder(rec2.Body).Decode(&errResp)
	if err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp["error"] != "too many pending requests" {
		t.Errorf("error = %q, want 'too many pending requests'", errResp["error"])
	}
}

func TestAckUnblockHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &Server{
		logger:       lg,
		store:        newMemStore(100),
		broadcaster:  newBroadcaster(),
		unblockStore: newUnblockStore(),
		apiKeys:      newMemAPIKeyStore("test-key"),
		readLimit:    100,
		rateLimiter:  newRateLimiter(50, 100),
	}

	bigBody := strings.Repeat("x", 8192)
	bigBodyReader := strings.NewReader(bigBody)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks/ack", bigBodyReader)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	srv.ackUnblockHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d for oversized body", rec.Code, http.StatusBadRequest)
	}
}

func TestAckUnblockHandler_EmptyID(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &Server{
		logger:       lg,
		store:        newMemStore(100),
		broadcaster:  newBroadcaster(),
		unblockStore: newUnblockStore(),
		apiKeys:      newMemAPIKeyStore("test-key"),
		readLimit:    100,
		rateLimiter:  newRateLimiter(50, 100),
	}

	tests := []struct {
		name string
		body string
	}{
		{"empty string", `{"id":""}`},
		{"whitespace only", `{"id":"   "}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyReader := strings.NewReader(tt.body)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks/ack", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			srv.ackUnblockHandler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: Status = %d, want %d", tt.name, rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestCreateUnblockHandler_InvalidIP(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &Server{
		logger:       lg,
		store:        newMemStore(100),
		broadcaster:  newBroadcaster(),
		unblockStore: newUnblockStore(),
		apiKeys:      newMemAPIKeyStore("test-key"),
		readLimit:    100,
		rateLimiter:  newRateLimiter(50, 100),
	}

	tests := []struct {
		name  string
		body  string
		want  int
		errIs string
	}{
		{"not an IP", `{"type":"ip","value":"not-an-ip"}`, http.StatusBadRequest, "invalid ip address"},
		{"domain as IP", `{"type":"ip","value":"example.com"}`, http.StatusBadRequest, "invalid ip address"},
		{"invalid type", `{"type":"foo","value":"1.2.3.4"}`, http.StatusBadRequest, "type must be"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyReader := strings.NewReader(tt.body)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			srv.createUnblockHandler(rec, req)

			if rec.Code != tt.want {
				t.Errorf("%s: Status = %d, want %d", tt.name, rec.Code, tt.want)
			}

			if !strings.Contains(rec.Body.String(), tt.errIs) {
				t.Errorf("%s: body = %q, want to contain %q", tt.name, rec.Body.String(), tt.errIs)
			}
		})
	}
}
