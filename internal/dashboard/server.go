// Package dashboard provides the web UI and HTTP API server.
//
//nolint:tagliatelle,noinlineerr
package dashboard

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	errAPIKeyRequired = errors.New("API_KEY is required")
)

// Config holds the dashboard server configuration.
type Config struct {
	Addr         string  // ":8081"
	APIKey       string  // required for POST /api/v1/logs
	LogLevel     string  // "INFO"
	BufferSize   int     // optional (default 5000)
	ReadLimit    int     // optional (default 500)
	SERetryMs    int     // optional (default 2000) - SSE client retry hint
	RateRPS      float64 // optional (default 50)
	RateBurst    float64 // optional (default 100)
	WriteTimeout int     // optional (default 0 = no timeout) - HTTP write timeout in seconds
	Version      string  // optional - dashboard version for logging
}

// Server holds all dependencies for HTTP handlers.
type Server struct {
	logger       *slog.Logger
	store        LogStore         // Interface instead of concrete *memStore
	broadcaster  EventBroadcaster // Interface instead of concrete *broadcaster
	apiKey       string
	readLimit    int
	sseRetry     time.Duration
	rateLimiter  RateLimiter // Interface instead of concrete *rateLimiter
	adminLimiter RateLimiter
}

// normalizeConfig applies defaults to unset config fields.
func normalizeConfig(cfg *Config) {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
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
	// WriteTimeout defaults to 0 for SSE
	if cfg.WriteTimeout < 0 {
		cfg.WriteTimeout = 0
	}
}

// Run starts the dashboard HTTP server with the provided configuration.
// It validates the API key, normalizes config, and starts the HTTP listener.
func Run(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return errAPIKeyRequired
	}

	normalizeConfig(&cfg)

	// Logger
	lg := logging.NewWithContext(ctx, cfg.LogLevel, os.Stdout, cfg.Version)
	slog.SetDefault(lg)

	// Create server with all dependencies
	srv := newServer(lg, cfg)

	// HTTP server
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      time.Duration(cfg.WriteTimeout) * time.Second,
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
		e := httpSrv.Serve(listener)
		if !errors.Is(e, http.ErrServerClosed) {
			errCh <- e
		}
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		_ = httpSrv.Shutdown(shCtx)

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
	Version         string `json:"version,omitempty"`
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

// newMemStore creates a new in-memory circular buffer log store with the specified capacity.
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

// Insert adds a log entry to the store and returns its assigned ID.
func (s *memStore) Insert(_ context.Context, e *LogEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
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

// Clear removes all log entries from the store.
func (s *memStore) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.head = 0
	s.count = 0
	s.nextID = 1

	return nil
}

// Query returns log entries matching the query string and ID filter, sorted by ID descending.
func (s *memStore) Query(_ context.Context, q string, sinceID int64, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

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

		if s.shouldSkipEntry(it, q, sinceID) {
			seen++
			idx = s.prevIndex(idx)

			continue
		}

		out = append(out, it)
		seen++
		idx = s.prevIndex(idx)
	}

	return out, nil
}

// shouldSkipEntry returns true if the entry should be filtered out based on ID or query string.
func (s *memStore) shouldSkipEntry(entry LogEntry, q string, sinceID int64) bool {
	// ID filter
	if sinceID > 0 && entry.ID <= sinceID {
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

// prevIndex returns the previous index in the circular buffer, wrapping around if necessary.
func (s *memStore) prevIndex(idx int) int {
	if idx == 0 {
		return s.size - 1
	}

	return idx - 1
}

/* =========================
   Router
   ========================= */

// newServer creates a new Server with all dependencies initialized.
func newServer(lg *slog.Logger, cfg Config) *Server {
	return &Server{
		logger:       lg,
		store:        newMemStore(cfg.BufferSize),
		broadcaster:  newBroadcaster(),
		apiKey:       cfg.APIKey,
		readLimit:    cfg.ReadLimit,
		sseRetry:     time.Duration(cfg.SERetryMs) * time.Millisecond,
		rateLimiter:  newRateLimiter(cfg.RateRPS, cfg.RateBurst),
		adminLimiter: newRateLimiter(1.0, 5.0),
	}
}

// routes configures all HTTP routes and middleware.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.loggerMiddleware())
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Public routes
	r.Get("/health", s.healthHandler)

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoints
		r.Get("/logs", s.listLogsHandler)
		r.Get("/events", s.sseHandler)
		r.Delete("/logs", s.clearLogsHandler)

		// Protected endpoints (require API key + rate limiting for remote log ingestion)
		r.Group(func(r chi.Router) {
			r.Use(s.requireAPIKey())
			r.Use(s.rateLimitMiddleware(s.rateLimiter))
			r.Use(middleware.AllowContentType("application/json"))
			r.Post("/logs", s.ingestHandler)
		})
	})

	// Serve static UI files
	r.Mount("/", IndexHandler(s.sseRetry))

	return r
}

// loggerMiddleware logs HTTP requests with structured logging.
func (s *Server) loggerMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				if s.logger != nil {
					s.logger.Debug("http.req",
						"method", r.Method,
						"path", r.URL.Path,
						"remote", r.RemoteAddr,
						"code", ww.Status(),
						"bytes", ww.BytesWritten(),
						"duration", time.Since(start).String(),
					)
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

// requireAPIKey validates the X-Api-Key header (Chi middleware).
func (s *Server) requireAPIKey() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-Api-Key")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.apiKey)) != 1 {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitMiddleware applies per-IP rate limiting (Chi middleware).
func (s *Server) rateLimitMiddleware(rl RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow(r.RemoteAddr) {
				http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

/* =========================
   Handlers
   ========================= */

// healthHandler handles health check requests.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "g0efilter-dashboard",
	}); err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// ingestHandler processes incoming log events and stores them in the buffer.
func (s *Server) ingestHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 1 << 20 // 1 MiB

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	// Read body once into memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)

		return
	}

	var payloads []map[string]any

	// Try array first
	if err := json.Unmarshal(body, &payloads); err != nil {
		// Try single object
		var obj map[string]any
		if err2 := json.Unmarshal(body, &obj); err2 != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

			return
		}

		payloads = []map[string]any{obj}
	}

	if len(payloads) == 0 {
		http.Error(w, `{"error":"empty payload"}`, http.StatusBadRequest)

		return
	}

	results := s.processPayloads(r.Context(), payloads, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(map[string]any{
		"created": len(results),
		"results": results,
	}); err != nil {
		s.logger.Error("failed to encode ingest response", "error", err)
	}
}

// processPayloads converts raw payloads to LogEntry structs, inserts them, and broadcasts to SSE clients.
func (s *Server) processPayloads(ctx context.Context, payloads []map[string]any, remoteIP string) []map[string]any {
	results := make([]map[string]any, 0, len(payloads))

	for _, in := range payloads {
		if entry := s.processPayload(in, remoteIP); entry != nil {
			if id, err := s.store.Insert(ctx, entry); err != nil {
				s.logger.Error("insert.failed", "err", err.Error())
			} else {
				entry.ID = id
				results = append(results, map[string]any{"id": id, "status": "ok"})

				if out, err := json.Marshal(entry); err == nil && out != nil {
					s.broadcaster.Send(out)
				}
			}
		}
	}

	return results
}

// extractFieldsMap builds a map of all fields from the payload.
func extractFieldsMap(in map[string]any) map[string]any {
	fieldsMap := make(map[string]any)

	if f, ok := in["fields"].(map[string]any); ok {
		maps.Copy(fieldsMap, f)
	}

	// Merge top-level fields
	for _, k := range []string{"action", "component", "protocol", "policy_hit", "payload_len",
		"reason", "tenant_id", "flow_id", "hostname", "source_ip", "source_port",
		"destination_ip", "destination_port", "src", "dst", "http_host", "host", "sni", "qname", "qtype", "version"} {
		if v, ok := in[k]; ok && v != nil {
			fieldsMap[k] = v
		}
	}

	return fieldsMap
}

// deriveProtocol determines the protocol from the payload.
func deriveProtocol(in map[string]any) string {
	protocol, _ := in["protocol"].(string)
	if protocol != "" {
		return protocol
	}

	if comp, ok := in["component"].(string); ok {
		switch strings.ToLower(comp) {
		case "http", "sni":
			return "TCP"
		case "dns":
			return "UDP"
		}
	}

	return ""
}

// getStringFromPayload gets the first non-empty string from multiple keys.
func getStringFromPayload(in map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := in[k].(string); ok && v != "" {
			return v
		}
	}

	return ""
}

// getIntFromPayload gets float64 as int from payload.
func getIntFromPayload(in map[string]any, key string) int {
	if v, ok := in[key].(float64); ok {
		return int(v)
	}

	return 0
}

// processPayload converts a raw log payload map into a LogEntry struct with enriched fields.
//

func (s *Server) processPayload(in map[string]any, remoteIP string) *LogEntry {
	msg, _ := in["msg"].(string)
	if msg == "" {
		return nil
	}

	// Action filter: only keep ALLOWED/BLOCKED
	action, _ := in["action"].(string)

	act := strings.ToUpper(strings.TrimSpace(action))
	if act != "ALLOWED" && act != "BLOCKED" {
		return nil
	}

	// Parse timestamp
	ts := time.Now().UTC()

	if tval, ok := in["time"].(string); ok && tval != "" {
		if t, err := time.Parse(time.RFC3339Nano, tval); err == nil {
			ts = t.UTC()
		}
	}

	// Build fields JSON
	fieldsMap := extractFieldsMap(in)

	fieldsRaw, err := json.Marshal(fieldsMap)
	if err != nil {
		s.logger.Error("failed to marshal fields", "error", err)

		return nil
	}

	if fieldsRaw == nil {
		fieldsRaw = json.RawMessage("null")
	}

	return &LogEntry{
		Time:            ts,
		Message:         msg,
		Fields:          fieldsRaw,
		RemoteIP:        remoteIP,
		Action:          act,
		Protocol:        deriveProtocol(in),
		PolicyHit:       getStringFromPayload(in, "policy_hit"),
		TenantID:        getStringFromPayload(in, "tenant_id"),
		SourceIP:        getStringFromPayload(in, "source_ip"),
		DestinationIP:   getStringFromPayload(in, "destination_ip"),
		SNI:             getStringFromPayload(in, "http_host", "host", "sni", "qname"),
		HTTPHost:        getStringFromPayload(in, "http_host", "host"),
		PayloadLen:      getIntFromPayload(in, "payload_len"),
		SourcePort:      getIntFromPayload(in, "source_port"),
		DestinationPort: getIntFromPayload(in, "destination_port"),
		Version:         getStringFromPayload(in, "version"),
	}
}

// listLogsHandler handles GET /logs requests and returns filtered log entries as JSON.
func (s *Server) listLogsHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	var sinceID int64

	if v := strings.TrimSpace(r.URL.Query().Get("since_id")); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
			sinceID = id
		}
	}

	limit := s.readLimit

	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	rows, err := s.store.Query(r.Context(), q, sinceID, limit)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(rows); err != nil {
		s.logger.Error("failed to encode query response", "error", err)
	}
}

// sseHandler handles Server-Sent Events streaming of log entries to connected clients.
func (s *Server) sseHandler(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)

		return
	}

	ch := s.broadcaster.Add()
	defer s.broadcaster.Remove(ch)

	// Client retry hint
	_, _ = fmt.Fprintf(w, "retry: %d\n\n", int(s.sseRetry.Milliseconds()))
	_, _ = w.Write([]byte(": connected\n\n"))

	flusher.Flush()

	ctx := r.Context()

	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			// Split on newlines per SSE framing
			for len(msg) > 0 {
				i := bytes.IndexByte(msg, '\n')
				if i == -1 {
					_, _ = w.Write([]byte("data: "))
					_, _ = w.Write(msg)
					_, _ = w.Write([]byte("\n\n"))

					break
				}

				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(msg[:i])
				_, _ = w.Write([]byte("\n"))
				msg = msg[i+1:]
			}

			if len(msg) == 0 {
				_, _ = w.Write([]byte("\n"))
			}

			flusher.Flush()
		case <-hb.C:
			_, _ = w.Write([]byte(": ping\n\n"))

			flusher.Flush()
		}
	}
}

// clearLogsHandler handles DELETE /api/v1/logs requests to empty the log buffer.
func (s *Server) clearLogsHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Clear(r.Context()); err != nil {
		s.logger.Error("logs.clear_failed", "err", err.Error())
		http.Error(w, `{"error":"failed to clear logs"}`, http.StatusInternalServerError)

		return
	}

	s.broadcaster.Send([]byte(`{"type":"cleared"}`))
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.logger.Error("failed to encode clear response", "error", err)
	}
}

type broadcaster struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

// newBroadcaster creates a new SSE broadcaster for distributing log events to connected clients.
func newBroadcaster() *broadcaster {
	return &broadcaster{clients: make(map[chan []byte]struct{})}
}

// Add registers a new SSE client and returns its message channel.
func (b *broadcaster) Add() chan []byte {
	ch := make(chan []byte, 64)

	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	return ch
}

// Remove unregisters an SSE client and closes its channel.
func (b *broadcaster) Remove(ch chan []byte) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

// Send broadcasts a message to all connected SSE clients, dropping messages for slow consumers.
func (b *broadcaster) Send(p []byte) {
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
	mu          sync.Mutex
	tokens      map[string]float64
	last        map[string]time.Time
	rps         float64
	burst       float64
	maxEntries  int
	lastCleanup time.Time
}

// newRateLimiter creates a token bucket rate limiter with the specified requests per second and burst size.
func newRateLimiter(rps, burst float64) *rateLimiter {
	if rps <= 0 {
		rps = 50
	}

	if burst <= 0 {
		burst = 100
	}

	return &rateLimiter{
		tokens:      map[string]float64{},
		last:        map[string]time.Time{},
		rps:         rps,
		burst:       burst,
		maxEntries:  10000, // Prevent unlimited memory growth
		lastCleanup: time.Now(),
	}
}

// Allow checks if a request from the given key (IP) is permitted under the rate limit.
func (rl *rateLimiter) Allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup to prevent memory leaks
	if len(rl.tokens) > rl.maxEntries || now.Sub(rl.lastCleanup) > 10*time.Minute {
		rl.cleanup(now)
		rl.lastCleanup = now
	}

	t := rl.tokens[key]
	last := rl.last[key]
	dt := now.Sub(last).Seconds()

	// Replenish tokens (cap at burst limit)
	t += dt * rl.rps
	if t > rl.burst {
		t = rl.burst
	}

	if t < 1.0 {
		rl.tokens[key] = t
		rl.last[key] = now

		return false
	}

	rl.tokens[key] = t - 1.0
	rl.last[key] = now

	return true
}

// cleanup removes entries older than 1 hour to prevent memory leaks.
func (rl *rateLimiter) cleanup(now time.Time) {
	cutoff := now.Add(-time.Hour)
	for key, lastSeen := range rl.last {
		if lastSeen.Before(cutoff) {
			delete(rl.tokens, key)
			delete(rl.last, key)
		}
	}
}
