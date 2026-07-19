//nolint:testpackage // Need access to internal implementation details
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
)

var errStoreFailure = errors.New("store failure")

// failingStore implements LogStore and fails every operation.
type failingStore struct{}

func (failingStore) Insert(_ context.Context, _ *LogEntry) (int64, error) {
	return 0, errStoreFailure
}

func (failingStore) Query(_ context.Context, _ string, _ int64, _ int) ([]LogEntry, error) {
	return nil, errStoreFailure
}

func (failingStore) Aggregate(
	_ context.Context, _, _ time.Time, _ string, _ int,
) (model.AggregateResult, error) {
	return model.AggregateResult{}, errStoreFailure
}

func (failingStore) Clear(_ context.Context) error {
	return errStoreFailure
}

func TestConfigHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer() // BufferSize 100, ReadLimit 50

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()

	srv.configHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	//nolint:tagliatelle // snake_case JSON API
	var resp struct {
		BufferSize   float64 `json:"buffer_size"`
		ReadLimit    float64 `json:"read_limit"`
		AuthMode     string  `json:"auth_mode"`
		FleetEnabled bool    `json:"fleet_enabled"`
	}

	err := json.NewDecoder(w.Body).Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.BufferSize != 100 {
		t.Errorf("buffer_size = %v, want 100", resp.BufferSize)
	}

	if resp.ReadLimit != 50 {
		t.Errorf("read_limit = %v, want 50", resp.ReadLimit)
	}
}

func TestUnblockStatusHandler(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	srv.unblockStore.Add("domain", testExampleDomain, "")

	ackID := srv.unblockStore.Add("ip", "10.0.0.1", "")
	if !srv.unblockStore.Acknowledge(ackID) {
		t.Fatal("failed to acknowledge seeded request")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks/status", nil)
	w := httptest.NewRecorder()

	srv.unblockStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp struct {
		Pending   []UnblockRequest   `json:"pending"`
		Completed []CompletedUnblock `json:"completed"`
	}

	err := json.NewDecoder(w.Body).Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Pending) != 1 {
		t.Errorf("pending = %d items, want 1", len(resp.Pending))
	}

	if len(resp.Completed) != 1 {
		t.Errorf("completed = %d items, want 1", len(resp.Completed))
	}
}

func TestIngestHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	// One byte over the handler's 1 MiB limit
	body := strings.NewReader(strings.Repeat("a", 1<<20+1))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/logs", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	srv.ingestHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	if !strings.Contains(w.Body.String(), "failed to read body") {
		t.Errorf("body = %q, want read failure error", w.Body.String())
	}
}

func TestIngestHandler_MalformedJSON(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	tests := []struct {
		name string
		body string
	}{
		{"garbage", "not json at all"},
		{"bare number", "42"},
		{"bare string", `"hello"`},
		{"bare bool", "true"},
		{"json null", "null"}, // decodes to a nil slice, rejected as empty payload
		{"array of scalars", "[42]"},
		{"truncated object", `{"msg":`},
		{"empty body", ""},
		{"empty array", "[]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := strings.NewReader(tt.body)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/logs", body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			srv.ingestHandler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// ingestAndCount posts the body to ingestHandler and returns the "created" count.
func ingestAndCount(t *testing.T, srv *Server, body string) int {
	t.Helper()

	bodyReader := strings.NewReader(body)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/logs", bodyReader)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	srv.ingestHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Status = %d, want %d (body %q)", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
	}

	err := json.NewDecoder(w.Body).Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return resp.Created
}

// Wrong field types must not create entries or crash; the batch is accepted
// with the bad records filtered out.
func TestIngestHandler_WrongFieldTypes(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	tests := []struct {
		name        string
		body        string
		wantCreated int
	}{
		{"msg is number", `[{"msg":123,"action":"BLOCKED"}]`, 0},
		{"msg is object", `[{"msg":{"a":1},"action":"BLOCKED"}]`, 0},
		{"action is number", `[{"msg":"m","action":42}]`, 0},
		{"action is bool", `[{"msg":"m","action":true}]`, 0},
		{"action missing", `[{"msg":"m"}]`, 0},
		{"unknown action", `[{"msg":"m","action":"REDIRECTED"}]`, 0},
		{"empty object", `{}`, 0},
		{"port is string ignored", `[{"msg":"m","action":"BLOCKED","source_port":"999"}]`, 1},
		{"time is number ignored", `[{"msg":"m","action":"ALLOWED","time":12345}]`, 1},
		{"mixed valid and invalid", `[{"msg":"ok","action":"BLOCKED"},{"msg":456,"action":"ALLOWED"}]`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			created := ingestAndCount(t, srv, tt.body)
			if created != tt.wantCreated {
				t.Errorf("created = %d, want %d", created, tt.wantCreated)
			}
		})
	}
}

func TestIngestHandler_Auth(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	router := srv.routes()

	tests := []struct {
		name        string
		apiKey      string
		contentType string
		want        int
	}{
		{"missing api key", "", "application/json", http.StatusUnauthorized},
		{"wrong api key", "wrong-key", "application/json", http.StatusUnauthorized},
		{"empty api key header", "", "application/json", http.StatusUnauthorized},
		{"valid key wrong content type", "test-api-key", "text/plain", http.StatusUnsupportedMediaType},
		{"valid key and content type", "test-api-key", "application/json", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := strings.NewReader(`[{"msg":"m","action":"BLOCKED"}]`)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/logs", body)
			req.Header.Set("Content-Type", tt.contentType)

			if tt.apiKey != "" {
				req.Header.Set("X-Api-Key", tt.apiKey)
			}

			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.want {
				t.Errorf("Status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// The dashboard store is a substring-matched in-memory buffer, not SQL, so
// SQLi-style text is legitimate search input and must pass through unchanged.
func TestSanitizeSearchQuery_Boundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"sqli quote passes through", "' OR 1=1 --", "' OR 1=1 --"},
		{"sqli union passes through", "UNION SELECT * FROM logs", "UNION SELECT * FROM logs"},
		{"sqli stacked passes through", "'; DROP TABLE logs;--", "'; DROP TABLE logs;--"},
		{"exactly 200 chars allowed", strings.Repeat("a", 200), strings.Repeat("a", 200)},
		{"201 chars rejected", strings.Repeat("a", 201), ""},
		{"DEL char rejected", "abc\x7fdef", ""},
		{"escape char rejected", "abc\x1b[31m", ""},
		{"script tag rejected", "<script>alert(1)</script>", ""},
		{"embedded script rejected", "foo <script src=x>", ""},
		{"javascript scheme rejected", "javascript:void(0)", ""},
		{"unicode allowed", "münchen", "münchen"},
		{"url-ish query allowed", "example.com:443/path?x=1", "example.com:443/path?x=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := SanitizeSearchQuery(tt.in)
			if got != tt.want {
				t.Errorf("SanitizeSearchQuery(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsValidSearchChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain text", "blocked example.com", true},
		{"punctuation", "a-b_c.d:e/f?g=h&i", true},
		{"unicode above ascii", "münchen", true},
		{"empty", "", true},
		{"tab", "a\tb", false},
		{"newline", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"null byte", "a\x00b", false},
		{"bell", "a\x07b", false},
		{"DEL", "a\x7fb", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isValidSearchChars(tt.in)
			if got != tt.want {
				t.Errorf("isValidSearchChars(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasInjectionPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"script tag", "<script>alert(1)", true},
		{"script tag embedded", "x<script src=y>", true},
		{"script tag uppercase", "<SCRIPT>alert(1)", true},
		{"script tag mixed case", "<ScRiPt>", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"javascript scheme embedded", "href=javascript:x", true},
		{"javascript scheme uppercase", "JAVASCRIPT:alert(1)", true},
		{"benign", "blocked example.com", false},
		{"word javascript alone", "javascript is a language", false},
		{"angle bracket alone", "a < b > c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := hasInjectionPatterns(tt.in)
			if got != tt.want {
				t.Errorf("hasInjectionPatterns(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// queryLogs runs listLogsHandler with the given query string and returns the rows.
func queryLogs(t *testing.T, srv *Server, rawQuery string) []LogEntry {
	t.Helper()

	target := "/api/v1/logs" + rawQuery
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	srv.listLogsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	var logs []LogEntry

	err := json.NewDecoder(w.Body).Decode(&logs)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return logs
}

func TestListLogsHandler_ParamValidation(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	ctx := context.Background()

	for range 3 {
		_, _ = srv.store.Insert(ctx, &LogEntry{
			Time:    time.Now(),
			Message: "entry",
			Action:  testActionBlocked,
		})
	}

	tests := []struct {
		name      string
		rawQuery  string
		wantCount int
	}{
		{"non-numeric since_id ignored", "?since_id=abc", 3},
		{"negative since_id ignored", "?since_id=-5", 3},
		{"valid since_id filters", "?since_id=1", 2},
		{"non-numeric limit ignored", "?limit=abc", 3},
		{"negative limit ignored", "?limit=-1", 3},
		{"zero limit ignored", "?limit=0", 3},
		{"oversized limit ignored", "?limit=99999", 3},
		{"valid limit applied", "?limit=2", 2},
		{"injection query sanitized to empty", "?q=%3Cscript%3Ealert(1)%3C/script%3E", 3},
		{"control-char query sanitized to empty", "?q=a%00b", 3},
		{"no-match query", "?q=nomatch", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logs := queryLogs(t, srv, tt.rawQuery)
			if len(logs) != tt.wantCount {
				t.Errorf("got %d logs, want %d", len(logs), tt.wantCount)
			}
		})
	}
}

//nolint:cyclop,wsl_v5 // sequential handler contract scenario
func TestAggregateLogsHandler_DefaultRangeAndFilter(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	now := time.Now().UTC()
	entries := []LogEntry{
		{Time: now.Add(-31 * 24 * time.Hour), Action: testActionBlocked, HTTPHost: "old.example"},
		{Time: now.Add(-25 * time.Hour), Action: testActionBlocked, HTTPHost: "outside-default.example"},
		{Time: now.Add(-time.Hour), Action: "ALLOWED", HTTPHost: testExampleDomain},
		{Time: now.Add(-30 * time.Minute), Action: testActionBlocked, HTTPHost: testExampleDomain},
		{Time: now.Add(-time.Minute), Action: "AUDIT", HTTPHost: "audit.example"},
	}
	for i := range entries {
		_, _ = srv.store.Insert(context.Background(), &entries[i])
	}

	request := func(target string) (int, model.AggregateResult) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		srv.aggregateLogsHandler(w, req)

		var result model.AggregateResult
		if w.Code == http.StatusOK {
			err := json.NewDecoder(w.Body).Decode(&result)
			if err != nil {
				t.Fatalf("decode aggregate: %v", err)
			}
		}

		return w.Code, result
	}

	code, result := request("/api/v1/aggregates")
	if code != http.StatusOK || result.Events != 3 || len(result.Buckets) != aggregateBuckets {
		t.Fatalf("default aggregate: status=%d result=%+v", code, result)
	}

	code, result = request("/api/v1/aggregates?range=30d")
	if code != http.StatusOK || result.Events != 4 {
		t.Fatalf("30-day aggregate: status=%d result=%+v", code, result)
	}

	code, result = request("/api/v1/aggregates?range=all&q=example.com")
	if code != http.StatusOK || result.Events != 2 || len(result.Rows) != 1 {
		t.Fatalf("filtered aggregate: status=%d result=%+v", code, result)
	}

	code, _ = request("/api/v1/aggregates?range=forever")
	if code != http.StatusBadRequest {
		t.Fatalf("invalid range status = %d, want 400", code)
	}
}

func TestAggregateLogsHandler_StoreError(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	srv.store = failingStore{}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/aggregates", nil)
	w := httptest.NewRecorder()
	srv.aggregateLogsHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Status = %d, want 500", w.Code)
	}
}

func TestParseAggregateRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		duration time.Duration
		all      bool
		wantErr  bool
	}{
		{name: "default", duration: 24 * time.Hour},
		{name: "day", raw: "24h", duration: 24 * time.Hour},
		{name: "day alias", raw: " 1D ", duration: 24 * time.Hour},
		{name: "15 minutes", raw: "15m", duration: 15 * time.Minute},
		{name: "hour", raw: "1h", duration: time.Hour},
		{name: "6 hours", raw: "6h", duration: 6 * time.Hour},
		{name: "7 days", raw: "7d", duration: 7 * 24 * time.Hour},
		{name: "30 days", raw: "30d", duration: 30 * 24 * time.Hour},
		{name: "90 days", raw: "90d", duration: 90 * 24 * time.Hour},
		{name: "all", raw: "all", all: true},
		{name: "invalid", raw: "forever", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			duration, all, err := parseAggregateRange(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAggregateRange(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}

			if duration != tt.duration || all != tt.all {
				t.Fatalf("parseAggregateRange(%q) = %s/%v, want %s/%v",
					tt.raw, duration, all, tt.duration, tt.all)
			}
		})
	}
}

func TestListLogsHandler_StoreError(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	srv.store = failingStore{}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	srv.listLogsHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestClearLogsHandler_StoreError(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	srv.store = failingStore{}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	srv.clearLogsHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestClearLogsHandler_BroadcastsCleared(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	ch := srv.broadcaster.Add()

	defer srv.broadcaster.Remove(ch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	srv.clearLogsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	select {
	case msg := <-ch:
		if string(msg) != `{"type":"cleared"}` {
			t.Errorf("broadcast = %s, want cleared event", msg)
		}
	case <-time.After(time.Second):
		t.Error("no cleared event broadcast")
	}
}

func TestUnblockHandlers_BroadcastStatusInvalidation(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	ch := srv.broadcaster.Add()
	defer srv.broadcaster.Remove(ch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks",
		strings.NewReader(`{"type":"domain","value":"example.com"}`))
	w := httptest.NewRecorder()
	srv.createUnblockHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create unblock = %d, want 201", w.Code)
	}

	select {
	case msg := <-ch:
		if string(msg) != `{"type":"unblock_status"}` {
			t.Errorf("broadcast = %s, want unblock status invalidation", msg)
		}
	case <-time.After(time.Second):
		t.Error("no unblock status invalidation broadcast")
	}

	var created map[string]string

	err := json.Unmarshal(w.Body.Bytes(), &created)
	if err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	ack := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks/ack",
		strings.NewReader(`{"id":"`+created["id"]+`"}`))
	ackRecorder := httptest.NewRecorder()
	srv.ackUnblockHandler(ackRecorder, ack)

	if ackRecorder.Code != http.StatusOK {
		t.Fatalf("ack unblock = %d, want 200", ackRecorder.Code)
	}

	select {
	case msg := <-ch:
		if string(msg) != `{"type":"unblock_status"}` {
			t.Errorf("ack broadcast = %s, want unblock status invalidation", msg)
		}
	case <-time.After(time.Second):
		t.Error("no unblock status invalidation broadcast after ack")
	}
}

func TestCreateUnblockHandler_MissingFields(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"empty object", `{}`, "type must be"},
		{"missing value", `{"type":"domain"}`, "value cannot be empty"},
		{"missing type", `{"value":"example.com"}`, "type must be"},
		{"value wrong type", `{"type":"domain","value":123}`, "invalid json"},
		{"type wrong type", `{"type":42,"value":"example.com"}`, "invalid json"},
		{"uppercase type rejected", `{"type":"DOMAIN","value":"example.com"}`, "type must be"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyReader := strings.NewReader(tt.body)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/unblocks", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			srv.createUnblockHandler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
			}

			if !strings.Contains(w.Body.String(), tt.wantErr) {
				t.Errorf("body = %q, want to contain %q", w.Body.String(), tt.wantErr)
			}
		})
	}
}

func TestAckUnblockHandler_BadRequests(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	tests := []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"id wrong type", `{"id":123}`},
		{"malformed json", `{"id":`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyReader := strings.NewReader(tt.body)
			target := "/api/v1/unblocks/ack"
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, bodyReader)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			srv.ackUnblockHandler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// Verifies which unblock endpoints sit behind the API key via the real router.
func TestUnblockRoutes_Auth(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	router := srv.routes()

	tests := []struct {
		name   string
		method string
		path   string
		apiKey string
		body   string
		want   int
	}{
		{"list without key", http.MethodGet, "/api/v1/unblocks", "", "", http.StatusUnauthorized},
		{"list with wrong key", http.MethodGet, "/api/v1/unblocks", "nope", "", http.StatusUnauthorized},
		{"list with key", http.MethodGet, "/api/v1/unblocks", "test-api-key", "", http.StatusOK},
		{"ack without key", http.MethodPost, "/api/v1/unblocks/ack", "", `{"id":"x"}`, http.StatusUnauthorized},
		{"ack with key unknown id", http.MethodPost, "/api/v1/unblocks/ack", "test-api-key",
			`{"id":"x"}`, http.StatusNotFound},
		{"create is public", http.MethodPost, "/api/v1/unblocks", "",
			`{"type":"ip","value":"10.0.0.1"}`, http.StatusCreated},
		{"status is public", http.MethodGet, "/api/v1/unblocks/status", "", "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyReader := strings.NewReader(tt.body)
			req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, bodyReader)
			req.Header.Set("Content-Type", "application/json")

			if tt.apiKey != "" {
				req.Header.Set("X-Api-Key", tt.apiKey)
			}

			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.want {
				t.Errorf("Status = %d, want %d (body %q)", w.Code, tt.want, w.Body.String())
			}
		})
	}
}

// sseRecorder is a goroutine-safe ResponseWriter with Flush support for SSE tests.
type sseRecorder struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	header http.Header
	code   int
}

func newSSERecorder() *sseRecorder {
	return &sseRecorder{header: make(http.Header)} //nolint:exhaustruct // zero values are fine
}

func (r *sseRecorder) Header() http.Header { return r.header }

func (r *sseRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, _ := r.buf.Write(p) // bytes.Buffer.Write never returns an error

	return n, nil
}

func (r *sseRecorder) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.code = code
}

func (r *sseRecorder) Flush() {}

func (r *sseRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.buf.String()
}

// waitForSSE polls the recorder until substr appears or the deadline passes.
func waitForSSE(t *testing.T, rec *sseRecorder, substr string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), substr) {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %q in SSE output %q", substr, rec.String())
}

func TestSSEHandler_StreamsEvents(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/events", nil)
	rec := newSSERecorder()
	done := make(chan struct{})

	go func() {
		srv.sseHandler(rec, req)
		close(done)
	}()

	// The ": connected" comment is written after the client is subscribed.
	waitForSSE(t, rec, ": connected\n\n")

	srv.broadcaster.Send([]byte("line1\nline2"))
	waitForSSE(t, rec, "data: line1\ndata: line2\n\n")

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sseHandler did not exit after context cancel")
	}

	if !strings.HasPrefix(rec.String(), "retry: ") {
		t.Errorf("output should start with a retry hint, got %q", rec.String())
	}

	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
}

// noFlushWriter deliberately does not implement http.Flusher.
type noFlushWriter struct {
	rec *httptest.ResponseRecorder
}

func (w noFlushWriter) Header() http.Header { return w.rec.Header() }

func (w noFlushWriter) Write(p []byte) (int, error) {
	n, err := w.rec.Write(p)
	if err != nil {
		return n, err //nolint:wrapcheck // passthrough test double
	}

	return n, nil
}

func (w noFlushWriter) WriteHeader(code int) { w.rec.WriteHeader(code) }

func TestSSEHandler_FlusherUnsupported(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	srv.sseHandler(noFlushWriter{rec: rec}, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
