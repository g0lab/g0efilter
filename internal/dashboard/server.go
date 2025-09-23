// Package dashboard provides the embedded web UI and HTTP API server for ingesting and
// viewing log events from g0efilter.
//
//nolint:tagliatelle,funlen,lll,noinlineerr
package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

const actionRedirected = "REDIRECTED"

var (
	errAPIKeyRequired       = errors.New("API_KEY is required")
	errHijackerNotSupported = errors.New("hijacker not supported")
)

// Config holds the dashboard server configuration.
type Config struct {
	Addr       string  // ":8081"
	APIKey     string  // required for /ingest and /logs/clear
	LogLevel   string  // "INFO"
	LogFormat  string  // "json"
	BufferSize int     // optional (default 5000)
	ReadLimit  int     // optional (default 500)
	SERetryMs  int     // optional (default 2000) - SSE client retry hint
	RateRPS    float64 // optional (default 50)
	RateBurst  float64 // optional (default 100)
}

// Run starts the dashboard HTTP server and stops when ctx is done.
//
//nolint:cyclop,funlen
func Run(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return errAPIKeyRequired
	}

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

	// Logger
	lg := logging.NewWithContext(ctx, cfg.LogLevel, cfg.LogFormat, os.Stdout, false)
	slog.SetDefault(lg)

	// In-memory store + SSE bus
	st := newMemStore(cfg.BufferSize)
	bus := newBroadcaster()

	// Router / server
	mux := newMux(
		lg, st, bus,
		cfg.APIKey,
		cfg.ReadLimit,
		time.Duration(cfg.SERetryMs)*time.Millisecond,
		cfg.RateRPS, cfg.RateBurst,
	)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withCommon(lg, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      0, // 15 * time.Second,
		IdleTimeout:       600 * time.Second,
	}

	lg.Info("dashboard.running", "addr", cfg.Addr)

	lc := &net.ListenConfig{} //nolint:exhaustruct

	listener, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}

	errCh := make(chan error, 1)

	go func() {
		e := srv.Serve(listener)
		if !errors.Is(e, http.ErrServerClosed) {
			errCh <- e
		}
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(shCtx)

		lg.Info("dashboard.shutdown")

		return nil
	case e := <-errCh:
		lg.Error("dashboard.failed", "err", e.Error())

		return e
	}
}

/* =========================
   Types (log event)
   ========================= */

// LogEntry represents a single ingested or synthetic log event.
type LogEntry struct {
	ID       int64           `json:"id,omitempty"`
	Time     time.Time       `json:"time"`
	Level    string          `json:"level"`
	Message  string          `json:"msg"`
	Fields   json.RawMessage `json:"fields,omitempty"`
	RemoteIP string          `json:"remote_ip,omitempty"`

	// Flattened (derived from Fields for API / SSE convenience)
	Action          string `json:"action,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	PolicyHit       string `json:"policy_hit,omitempty"`
	PayloadLen      int    `json:"payload_len,omitempty"`
	SNI             string `json:"sni,omitempty"`
	HTTPHost        string `json:"http_host,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Src             string `json:"src,omitempty"`
	Dst             string `json:"dst,omitempty"`
}

/* =========================
   In-memory queue store
   ========================= */

type memStore struct {
	mu     sync.RWMutex
	buf    []LogEntry
	head   int // next write position
	size   int // capacity
	count  int // number of valid records currently in buffer
	nextID int64
}

func newMemStore(n int) *memStore {
	if n < 1 {
		n = 1
	}

	return &memStore{
		buf:    make([]LogEntry, n),
		size:   n,
		nextID: 1,
	}
}

func (s *memStore) Insert(_ context.Context, e *LogEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	if e.Level == "" {
		e.Level = "INFO"
	}

	if e.Message == "" {
		e.Message = "log"
	}

	if e.Fields == nil {
		e.Fields = json.RawMessage("null")
	}

	e.ID = s.nextID
	s.nextID++

	// Write into ring
	s.buf[s.head] = *e

	s.head = (s.head + 1) % s.size
	if s.count < s.size {
		s.count++
	}

	return e.ID, nil
}

func (s *memStore) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.head = 0
	s.count = 0
	s.nextID = 1

	return nil
}

// Query returns latest items (DESC by ID).
func (s *memStore) Query(_ context.Context, level, q string, sinceID int64, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	level = strings.ToUpper(strings.TrimSpace(level))
	q = strings.TrimSpace(q)

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]LogEntry, 0, limit)
	if s.count == 0 {
		return out, nil
	}

	idx := (s.head - 1 + s.size) % s.size
	seen := 0

	for seen < s.count && len(out) < limit {
		it := s.buf[idx]

		if s.shouldSkipEntry(it, level, q, sinceID) {
			seen++
			idx = s.prevIndex(idx)

			continue
		}

		// Enrich the entry with convenience fields
		s.enrichLogEntry(&it)
		out = append(out, it)

		seen++
		idx = s.prevIndex(idx)
	}

	return out, nil
}

func (s *memStore) shouldSkipEntry(entry LogEntry, level, q string, sinceID int64) bool {
	// ID filter
	if sinceID > 0 && entry.ID <= sinceID {
		return true
	}

	// Level filter
	if level != "" && strings.ToUpper(entry.Level) != level {
		return true
	}

	// Query filter
	if q != "" {
		hay := strings.ToLower(strings.Join([]string{
			entry.Message,
			string(entry.Fields),
		}, " "))
		if !strings.Contains(hay, strings.ToLower(q)) {
			return true
		}
	}

	return false
}

func (s *memStore) prevIndex(idx int) int {
	if idx == 0 {
		return s.size - 1
	}

	return idx - 1
}

func (s *memStore) enrichLogEntry(it *LogEntry) {
	var m map[string]any

	_ = json.Unmarshal(it.Fields, &m)

	it.Action = strFrom(m, "action")
	it.Protocol = strFrom(m, "protocol")
	it.PolicyHit = strFrom(m, "policy_hit")
	it.PayloadLen = intFrom(m, "payload_len")
	it.TenantID = strFrom(m, "tenant_id")
	it.SourceIP = strFrom(m, "source_ip")
	it.SourcePort = intFrom(m, "source_port")
	it.DestinationIP = strFrom(m, "destination_ip")
	it.DestinationPort = intFrom(m, "destination_port")
	it.SNI = firstNonEmpty(strFrom(m, "http_host"), strFrom(m, "host"), strFrom(m, "sni"), strFrom(m, "qname"))
	it.HTTPHost = firstNonEmpty(strFrom(m, "http_host"), strFrom(m, "host"))
	it.FlowID = strFrom(m, "flow_id")
	it.Hostname = strFrom(m, "hostname")
	it.Src = strFrom(m, "src")
	it.Dst = strFrom(m, "dst")

	if it.Protocol == "" {
		comp := strings.ToLower(strFrom(m, "component"))
		switch comp {
		case "http", "sni":
			it.Protocol = "TCP"
		case "dns":
			it.Protocol = "UDP"
		}
	}
}

/* =========================
   Router
   ========================= */

func newMux(lg *slog.Logger, st *memStore, bus *broadcaster, apiKey string, defaultReadLimit int, sseRetry time.Duration, rateRPS, rateBurst float64) *http.ServeMux {
	mux := http.NewServeMux()

	// per-IP rate limiter for /ingest
	rl := newRateLimiter(rateRPS, rateBurst)

	// UI + health
	mux.Handle("/", IndexHandler(sseRetry))
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))

	// Public reads
	mux.Handle("/logs", listLogsHandler(st, defaultReadLimit))
	mux.Handle("/events", sseHandler(bus, sseRetry))

	// Protected writes
	mux.Handle("/ingest", apiKeyMiddleware(apiKey, ingestHandler(lg, st, bus, rl)))
	mux.Handle("/logs/clear", apiKeyMiddleware(apiKey, clearLogsHandler(lg, st, bus)))

	return mux
}

/* =========================
   Handlers
   ========================= */

func ingestHandler(lg *slog.Logger, st *memStore, bus *broadcaster, rl *rateLimiter) http.Handler {
	const maxBody = 1 << 20 // 1 MiB

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateIngestRequest(w, r, rl) {
			return
		}

		payloads, ok := parseRequestBody(w, r, maxBody)
		if !ok {
			return
		}

		results := processPayloads(r.Context(), lg, st, bus, payloads, remoteIP(r))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(results)
	})
}

func validateIngestRequest(w http.ResponseWriter, r *http.Request, rl *rateLimiter) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return false
	}

	ip := remoteIP(r)
	if !rl.allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)

		return false
	}

	return true
}

func parseRequestBody(w http.ResponseWriter, r *http.Request, maxBody int64) ([]map[string]any, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r.Body)

	raw := buf.Bytes()
	if len(raw) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)

		return nil, false
	}

	payloads := make([]map[string]any, 0)
	if b := bytes.TrimSpace(raw); len(b) > 0 && b[0] == '[' {
		err := json.Unmarshal(b, &payloads)
		if err != nil {
			http.Error(w, "bad json array", http.StatusBadRequest)

			return nil, false
		}
	} else {
		var obj map[string]any

		err := json.Unmarshal(raw, &obj)
		if err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)

			return nil, false
		}

		payloads = append(payloads, obj)
	}

	if len(payloads) == 0 {
		http.Error(w, "no payload", http.StatusBadRequest)

		return nil, false
	}

	return payloads, true
}

func processPayloads(ctx context.Context, lg *slog.Logger, st *memStore, bus *broadcaster, payloads []map[string]any, remoteIP string) []map[string]any {
	results := make([]map[string]any, 0, len(payloads))

	for _, in := range payloads {
		if entry := processPayload(in, remoteIP); entry != nil {
			if id, err := st.Insert(ctx, entry); err != nil {
				lg.Error("insert.failed", "err", err.Error())
			} else {
				entry.ID = id
				results = append(results, map[string]any{"id": id, "status": "ok"})

				if out, err := json.Marshal(entry); err == nil && out != nil {
					// Sanitize JSON to prevent XSS attacks while preserving JSON structure
					sanitized := sanitizeJSONForSSE(out)
					bus.send(sanitized)
				}
			}
		}
	}

	return results
}

// sanitizeJSONForSSE HTML-escapes JSON content to prevent XSS attacks
// while preserving JSON structure for client-side parsing.
func sanitizeJSONForSSE(jsonData []byte) []byte {
	var buf bytes.Buffer
	json.HTMLEscape(&buf, jsonData)
	return buf.Bytes()
}

func processPayload(in map[string]any, remoteIP string) *LogEntry {
	level := toStr(in["level"])
	msg := toStr(in["msg"])

	// Action filter: only keep ALLOWED/BLOCKED/REDIRECTED
	act := strings.ToUpper(strings.TrimSpace(toStr(in["action"])))
	if act != "ALLOWED" && act != "BLOCKED" && act != actionRedirected {
		return nil // Skip quietly
	}

	if msg == "" || level == "" {
		return nil
	}

	ts := parseTimestamp(in)
	fieldsMap := buildFieldsMap(in)
	fieldsRaw := marshalFields(fieldsMap)

	entry := &LogEntry{
		Time:     ts,
		Level:    level,
		Message:  msg,
		Fields:   fieldsRaw,
		RemoteIP: remoteIP,

		// Enriched top-level copies:
		Action:          act,
		Protocol:        determineProtocol(in),
		PolicyHit:       toStr(in["policy_hit"]),
		PayloadLen:      toInt(in["payload_len"]),
		TenantID:        toStr(in["tenant_id"]),
		SourceIP:        toStr(in["source_ip"]),
		SourcePort:      toInt(in["source_port"]),
		DestinationIP:   toStr(in["destination_ip"]),
		DestinationPort: toInt(in["destination_port"]),
		SNI:             firstNonEmpty(toStr(in["http_host"]), toStr(in["host"]), toStr(in["sni"]), toStr(in["qname"])),
		HTTPHost:        firstNonEmpty(toStr(in["http_host"]), toStr(in["host"])),
	}

	return entry
}

func parseTimestamp(in map[string]any) time.Time {
	ts := time.Now().UTC()

	if tval, ok := in["time"]; ok && tval != nil {
		if tsStr, ok := tval.(string); ok && tsStr != "" {
			if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
				ts = t.UTC()
			}
		}
	}

	return ts
}

func buildFieldsMap(in map[string]any) map[string]any {
	fieldsMap := map[string]any{}

	// Start with nested "fields" if provided
	if f, ok := in["fields"]; ok && f != nil {
		if fm, ok := f.(map[string]any); ok {
			for k, v := range fm {
				fieldsMap[k] = v
			}
		}
	}

	// Copy normalized keys
	normKeys := []string{
		"action", "component", "protocol", "policy_hit", "payload_len",
		"reason", "tenant_id", "flow_id", "hostname",
		"source_ip", "source_port", "destination_ip", "destination_port",
		"src", "dst",
		"http_host", "host", "sni", "qname", "qtype",
	}

	for _, k := range normKeys {
		if v, ok := in[k]; ok && v != nil {
			fieldsMap[k] = v
		}
	}

	return fieldsMap
}

func marshalFields(fieldsMap map[string]any) json.RawMessage {
	fieldsRaw := json.RawMessage("null")

	if len(fieldsMap) > 0 {
		if b, err := json.Marshal(fieldsMap); err == nil {
			fieldsRaw = json.RawMessage(b)
		}
	}

	return fieldsRaw
}

func determineProtocol(in map[string]any) string {
	if protocol := toStr(in["protocol"]); protocol != "" {
		return protocol
	}

	comp := strings.ToLower(toStr(in["component"]))
	switch comp {
	case "http", "sni":
		return "TCP"
	case "dns":
		return "UDP"
	default:
		return ""
	}
}

func listLogsHandler(st *memStore, defaultLimit int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		// Parse & sanitize query params
		level := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
		q := strings.TrimSpace(r.URL.Query().Get("q"))

		var sinceID int64

		if v := strings.TrimSpace(r.URL.Query().Get("since_id")); v != "" {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
				sinceID = id
			}
		}

		limit := defaultLimit

		if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}

		rows, err := st.Query(r.Context(), level, q, sinceID, limit)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)

			return
		}

		// JSON response
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(true)
		_ = enc.Encode(rows)
	})
}

func sseHandler(bus *broadcaster, retry time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		if bus == nil {
			http.Error(w, "broadcaster not initialized", http.StatusInternalServerError)

			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)

			return
		}

		ch := bus.add()
		defer bus.remove(ch)

		// priming write + client retry hint
		_, _ = fmt.Fprintf(w, "retry: %d\n\n", int(retry.Milliseconds()))
		_, _ = w.Write([]byte(": connected\n\n"))

		flusher.Flush()

		ctx := r.Context()

		hb := time.NewTicker(15 * time.Second)
		defer hb.Stop()

		writeEvent := func(b []byte) {
			// Split on newlines per SSE framing and prefix "data: "
			for len(b) > 0 {
				i := bytes.IndexByte(b, '\n')
				if i == -1 {
					_, _ = w.Write([]byte("data: "))
					_, _ = w.Write(b)
					_, _ = w.Write([]byte("\n"))

					break
				}

				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(b[:i])
				_, _ = w.Write([]byte("\n"))
				b = b[i+1:]
			}

			_, _ = w.Write([]byte("\n"))

			flusher.Flush()
		}

		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-ch:
				writeEvent(msg)
			case <-hb.C:
				_, _ = w.Write([]byte(": ping\n\n"))

				flusher.Flush()
			}
		}
	})
}

func clearLogsHandler(lg *slog.Logger, st *memStore, bus *broadcaster) http.Handler {
	type resp struct {
		Status string `json:"status"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		err := st.Clear(r.Context())
		if err != nil {
			lg.Error("logs.clear_failed", "err", err.Error())
			http.Error(w, "store error", http.StatusInternalServerError)

			return
		}

		bus.send([]byte(`{"type":"cleared"}`))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp{Status: "ok"})
	})
}

func withCommon(lg *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &respWrap{ResponseWriter: w, code: 200}
		next.ServeHTTP(ww, r)
		lg.Debug("http.req",
			"method", r.Method,
			"path", r.URL.Path,
			"code", ww.code,
			"t", time.Since(start).String(),
		)
	})
}

type respWrap struct {
	http.ResponseWriter

	code int
}

func (w *respWrap) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *respWrap) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *respWrap) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err != nil {
			return nil, nil, fmt.Errorf("hijack: %w", err)
		}

		return conn, rw, nil
	}

	return nil, nil, errHijackerNotSupported
}

// Push provides passthrough HTTP/2 server push (no-op if not supported).
func (w *respWrap) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		err := p.Push(target, opts)
		if err != nil {
			return fmt.Errorf("push: %w", err)
		}

		return nil
	}

	return http.ErrNotSupported
}

func apiKeyMiddleware(expected string, next http.Handler) http.Handler {
	keyBytes := []byte(expected)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Api-Key")
		if expected == "" || len(got) != len(expected) ||
			subtle.ConstantTimeCompare([]byte(got), keyBytes) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func toStr(v any) string {
	if v == nil {
		return ""
	}

	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func toInt(v any) int {
	if v == nil {
		return 0
	}

	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}

	return 0
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}

	return ""
}

// helpers (query-time).
func strFrom(m map[string]any, k string) string {
	if m == nil {
		return ""
	}

	if v, ok := m[k]; ok && v != nil {
		switch t := v.(type) {
		case string:
			return t
		case json.Number:
			return t.String()
		default:
			return fmt.Sprint(t)
		}
	}

	return ""
}

func intFrom(m map[string]any, k string) int {
	if m == nil {
		return 0
	}

	v, ok := m[k]
	if !ok || v == nil {
		return 0
	}

	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)

		return i
	default:
		_ = t

		return 0
	}
}

type broadcaster struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

func newBroadcaster() *broadcaster {
	return &broadcaster{clients: make(map[chan []byte]struct{})}
}

func (b *broadcaster) add() chan []byte {
	ch := make(chan []byte, 64)

	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	return ch
}

func (b *broadcaster) remove(ch chan []byte) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *broadcaster) send(p []byte) {
	b.mu.RLock()

	for ch := range b.clients {
		select {
		case ch <- p:
		default:
			// drop if slow consumer
		}
	}

	b.mu.RUnlock()
}

type rateLimiter struct {
	mu     sync.Mutex
	tokens map[string]float64
	last   map[string]time.Time
	rps    float64
	burst  float64
}

func newRateLimiter(rps, burst float64) *rateLimiter {
	if rps <= 0 {
		rps = 50
	}

	if burst <= 0 {
		burst = 100
	}

	return &rateLimiter{
		tokens: map[string]float64{},
		last:   map[string]time.Time{},
		rps:    rps,
		burst:  burst,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	t := rl.tokens[key]
	last := rl.last[key]
	dt := now.Sub(last).Seconds()
	// replenish
	t = mathMin(rl.burst, t+dt*rl.rps)
	if t < 1.0 {
		rl.tokens[key] = t
		rl.last[key] = now

		return false
	}

	rl.tokens[key] = t - 1.0
	rl.last[key] = now

	return true
}

func mathMin(a, b float64) float64 {
	if a < b {
		return a
	}

	return b
}
