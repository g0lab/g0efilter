package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

const (
	unblockTypeDomain = "domain"
	unblockTypeIP     = "ip"

	keyStatus   = "status"
	keyPending  = "pending"
	keyHTTPS    = "https"
	keyAuthMode = "auth_mode"
)

// configHandler returns buffer/read-limit config plus feature flags the UI
// uses to gate navigation (fleet page, logout button).
func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(map[string]any{
		"buffer_size":   s.bufferSize,
		"read_limit":    s.readLimit,
		keyAuthMode:     s.authMode,
		"fleet_enabled": s.fleetEnabled,
	})
	if err != nil {
		s.logger.Error("failed to encode config response", "error", err)
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(map[string]string{
		keyStatus: "ok",
		"service": "g0efilter-dashboard",
	})
	if err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// ingestHandler processes incoming log events and stores them in the buffer.
//
//nolint:funlen // Function handles complete request processing flow
func (s *Server) ingestHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 1 << 20 // 1 MiB

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Debug("ingest.read_failed",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)

		return
	}

	s.logger.Log(r.Context(), logging.LevelTrace, "ingest.body_read",
		"remote", r.RemoteAddr,
		"bytes", len(body),
	)

	var payloads []map[string]any

	err = json.Unmarshal(body, &payloads)
	if err != nil {
		var obj map[string]any

		err2 := json.Unmarshal(body, &obj)
		if err2 != nil {
			s.logger.Warn("ingest.invalid_json",
				"remote", r.RemoteAddr,
				"error", err2.Error(),
				"body_preview", string(body[:min(len(body), 100)]),
			)
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

			return
		}

		payloads = []map[string]any{obj}
	}

	if len(payloads) == 0 {
		s.logger.Warn("ingest.empty_payload",
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"empty payload"}`, http.StatusBadRequest)

		return
	}

	s.logger.Debug("ingest.processing",
		"remote", r.RemoteAddr,
		"count", len(payloads),
	)

	results := s.processPayloads(r.Context(), payloads, r.RemoteAddr)

	s.logger.Debug("ingest.completed",
		"remote", r.RemoteAddr,
		"created", len(results),
		"total", len(payloads),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]any{
		"created": len(results),
		"results": results,
	})
	if err != nil {
		s.logger.Error("failed to encode ingest response", "error", err)
	}
}

// listLogsHandler handles GET /logs requests and returns filtered log entries as JSON.
func (s *Server) listLogsHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	// Sanitize search query to prevent injection
	q = SanitizeSearchQuery(q)

	var sinceID int64

	raw := strings.TrimSpace(r.URL.Query().Get("since_id"))
	if raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err == nil && id > 0 {
			sinceID = id
		}
	}

	limit := s.readLimit

	raw = strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw != "" {
		n, err := strconv.Atoi(raw)
		if err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}

	s.logger.Debug("logs.query",
		"remote", r.RemoteAddr,
		"query", q,
		"since_id", sinceID,
		"limit", limit,
	)

	rows, err := s.store.Query(r.Context(), q, sinceID, limit)
	if err != nil {
		s.logger.Error("logs.query_failed",
			"error", err.Error(),
			"query", q,
			"since_id", sinceID,
		)
		http.Error(w, "store error", http.StatusInternalServerError)

		return
	}

	s.logger.Debug("logs.query_result",
		"count", len(rows),
	)

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(rows)
	if err != nil {
		s.logger.Error("failed to encode query response", "error", err)
	}
}

// sseHandler handles Server-Sent Events streaming of log entries to connected clients.
//
//nolint:funlen // SSE handler requires complete event loop implementation
func (s *Server) sseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.logger.Error("sse.flusher_unsupported",
			"remote", r.RemoteAddr,
			"warning", "http.ResponseWriter does not support flushing",
		)
		http.Error(w, "stream unsupported", http.StatusInternalServerError)

		return
	}

	ch := s.broadcaster.Add()
	defer s.broadcaster.Remove(ch)

	s.logger.Debug("sse.client_connected",
		"remote", r.RemoteAddr,
	)

	_, _ = fmt.Fprintf(w, "retry: %d\n\n", int(s.sseRetry.Milliseconds()))
	_, _ = w.Write([]byte(": connected\n\n"))

	flusher.Flush()

	ctx := r.Context()

	hb := time.NewTicker(10 * time.Second)
	defer hb.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Debug("sse.client_disconnected",
				"remote", r.RemoteAddr,
			)

			return
		case msg := <-ch:
			s.logger.Log(ctx, logging.LevelTrace, "sse.send",
				"remote", r.RemoteAddr,
				"bytes", len(msg),
			)
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
			s.logger.Log(ctx, logging.LevelTrace, "sse.heartbeat",
				"remote", r.RemoteAddr,
			)

			_, _ = w.Write([]byte(": ping\n\n"))

			flusher.Flush()
		}
	}
}

func (s *Server) clearLogsHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("logs.clearing",
		"remote", r.RemoteAddr,
	)

	err := s.store.Clear(r.Context())
	if err != nil {
		s.logger.Error("logs.clear_failed",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"failed to clear logs"}`, http.StatusInternalServerError)

		return
	}

	s.logger.Debug("logs.cleared",
		"remote", r.RemoteAddr,
	)

	s.broadcaster.Send([]byte(`{"type":"cleared"}`))
	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{keyStatus: "ok"})
	if err != nil {
		s.logger.Error("failed to encode clear response", "error", err)
	}
}

// unblockStatusHandler handles GET /api/v1/unblocks/status requests.
// Returns a snapshot used for initial load and SSE reconnection recovery.
func (s *Server) unblockStatusHandler(w http.ResponseWriter, _ *http.Request) {
	pending := s.unblockStore.GetPending()
	completed := s.unblockStore.GetCompleted()

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(map[string]any{
		keyPending:  pending,
		"completed": completed,
	})
	if err != nil {
		s.logger.Error("failed to encode unblock status response", "error", err)
	}
}

// listUnblocksHandler handles GET /api/v1/unblocks requests.
// Supports ?hostname= query parameter to filter for a specific host.
func (s *Server) listUnblocksHandler(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))

	s.logger.Debug("unblocks.list",
		"remote", r.RemoteAddr,
		"hostname", hostname,
	)

	var pending []UnblockRequest
	if hostname != "" {
		pending = s.unblockStore.GetPendingForHost(hostname)
	} else {
		pending = s.unblockStore.GetPending()
	}

	completed := s.unblockStore.GetCompleted()

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(map[string]any{
		keyPending:  pending,
		"completed": completed,
	})
	if err != nil {
		s.logger.Error("failed to encode unblocks response", "error", err)
	}
}

// createUnblockHandler handles POST /api/v1/unblocks requests.
//
//nolint:funlen,tagliatelle // JSON uses snake_case for API compatibility
func (s *Server) createUnblockHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 4096 // 4 KiB - small JSON payload

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	var req struct {
		Type           string `json:"type"`            // "domain" or "ip"
		Value          string `json:"value"`           // the domain or IP to unblock
		TargetHostname string `json:"target_hostname"` // optional: specific host, empty = all
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.logger.Debug("unblocks.create.invalid_json", "remote", r.RemoteAddr, "error", err.Error())
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	if req.Type != unblockTypeDomain && req.Type != unblockTypeIP {
		s.logger.Debug("unblocks.create.invalid_type", "remote", r.RemoteAddr, "type", req.Type)
		http.Error(w, `{"error":"type must be 'domain' or 'ip'"}`, http.StatusBadRequest)

		return
	}

	value, errMsg := validateUnblockValue(req.Type, req.Value)
	if errMsg != "" {
		s.logger.Debug("unblocks.create.invalid_value",
			"remote", r.RemoteAddr, "type", req.Type, "value", req.Value, "reason", errMsg,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		err := json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
		if err != nil {
			s.logger.Error("failed to encode unblock error response", "error", err)
		}

		return
	}

	targetHost := strings.TrimSpace(req.TargetHostname)
	id := s.unblockStore.Add(req.Type, value, targetHost)

	if id == "" {
		s.logger.Warn("unblocks.create.store_full", "remote", r.RemoteAddr)
		http.Error(w, `{"error":"too many pending requests"}`, http.StatusTooManyRequests)

		return
	}

	s.logger.Info("unblocks.created",
		"remote", r.RemoteAddr, "type", req.Type,
		"value", value, "target_hostname", targetHost, "id", id,
	)
	s.broadcaster.Send([]byte(`{"type":"unblock_status"}`))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]string{"id": id, keyStatus: keyPending})
	if err != nil {
		s.logger.Error("failed to encode unblock response", "error", err)
	}
}

// ackUnblockHandler handles POST /api/v1/unblocks/ack requests.
func (s *Server) ackUnblockHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 4096 // 4 KiB - small JSON payload

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	var req struct {
		ID string `json:"id"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.logger.Debug("unblocks.ack.invalid_json",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	if strings.TrimSpace(req.ID) == "" {
		s.logger.Debug("unblocks.ack.empty_id",
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"id cannot be empty"}`, http.StatusBadRequest)

		return
	}

	ok := s.unblockStore.Acknowledge(strings.TrimSpace(req.ID))
	if !ok {
		s.logger.Debug("unblocks.ack.not_found",
			"remote", r.RemoteAddr,
			"id", req.ID,
		)
		http.Error(w, `{"error":"unblock request not found"}`, http.StatusNotFound)

		return
	}

	s.logger.Info("unblocks.acknowledged",
		"remote", r.RemoteAddr,
		"id", req.ID,
	)
	s.broadcaster.Send([]byte(`{"type":"unblock_status"}`))

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{keyStatus: "ok"})
	if err != nil {
		s.logger.Error("failed to encode ack response", "error", err)
	}
}

// SanitizeSearchQuery returns the sanitized query, or empty string if validation fails.
func SanitizeSearchQuery(q string) string {
	if q == "" {
		return q
	}

	const maxQueryLength = 200

	if len(q) > maxQueryLength {
		return ""
	}

	if !isValidSearchChars(q) {
		return ""
	}

	if hasInjectionPatterns(q) {
		return ""
	}

	return q
}

func isValidSearchChars(q string) bool {
	for _, r := range q {
		// reject control characters (< 0x20) and DEL (0x7f)
		if r < 32 || r == 127 {
			return false
		}
	}

	return true
}

func hasInjectionPatterns(q string) bool {
	// Case-insensitive: <SCRIPT> and JAVASCRIPT: must not slip through.
	lower := strings.ToLower(q)

	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "javascript:")
}

// validateUnblockValue validates and sanitizes the value for an unblock request.
// Returns the cleaned value and an error message (empty if valid).
func validateUnblockValue(reqType, rawValue string) (string, string) {
	value := strings.TrimSpace(rawValue)
	if value == "" {
		return "", "value cannot be empty"
	}

	if reqType == unblockTypeDomain {
		value = SanitizeDomainField(value)
		if value == "" || value == "[invalid]" {
			return "", "invalid domain"
		}

		return value, ""
	}

	if net.ParseIP(value) == nil {
		return "", "invalid ip address"
	}

	return value, ""
}
