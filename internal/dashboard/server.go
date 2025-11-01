// Package dashboard provides the web UI and HTTP API server.
//
//nolint:tagliatelle
package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
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
	HTTPS           string `json:"https,omitempty"`
	HTTPHost        string `json:"http_host,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Src             string `json:"src,omitempty"`
	Dst             string `json:"dst,omitempty"`
	Version         string `json:"version,omitempty"`
}

// Run starts the dashboard HTTP server with the provided configuration.
// It validates the API key and starts the HTTP listener.
//
//nolint:funlen // Function is clear and well-structured despite length
func Run(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.APIKey) == "" {
		// Log to stderr before logger is initialized
		fmt.Fprintln(os.Stderr, "ERROR: API_KEY environment variable is required but not set")
		fmt.Fprintln(os.Stderr, "The dashboard requires an API key for secure log ingestion")
		fmt.Fprintln(os.Stderr, "Please set API_KEY to a secure random string")

		return errAPIKeyRequired
	}

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
		ReadTimeout:       0, // No timeout for SSE long-lived connections
		WriteTimeout:      time.Duration(cfg.WriteTimeout) * time.Second,
		IdleTimeout:       600 * time.Second,
	}

	lg.Info("dashboard.running", "addr", cfg.Addr)

	lc := &net.ListenConfig{
		KeepAlive: 30 * time.Second, // TCP keepalive to prevent connection tracking timeouts
	}

	listener, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		lg.Error("dashboard.listen_failed",
			"addr", cfg.Addr,
			"error", err.Error(),
		)

		return fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}

	errCh := make(chan error, 1)

	go func() {
		e := httpSrv.Serve(listener)
		if !errors.Is(e, http.ErrServerClosed) {
			lg.Error("dashboard.serve_failed",
				"addr", cfg.Addr,
				"error", e.Error(),
			)

			errCh <- e
		}
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lg.Debug("dashboard.shutting_down", "reason", "context_cancelled")

		//nolint:contextcheck // Intentionally using fresh context for graceful shutdown after parent ctx cancelled.
		err := httpSrv.Shutdown(shCtx)
		if err != nil {
			lg.Error("dashboard.shutdown_failed",
				"error", err.Error(),
			)
		}

		lg.Info("dashboard.shutdown")

		return nil
	case e := <-errCh:
		lg.Error("dashboard.failed", "err", e.Error())

		return e
	}
}

/* =========================
   Router & Middleware
   ========================= */

// newServer creates a new Server with all dependencies initialized.
func newServer(lg *slog.Logger, cfg Config) *Server {
	slog.Debug("dashboard.server_init",
		"buffer_size", cfg.BufferSize,
		"read_limit", cfg.ReadLimit,
		"sse_retry_ms", cfg.SERetryMs,
		"write_timeout", cfg.WriteTimeout,
		"rate_rps", cfg.RateRPS,
		"rate_burst", cfg.RateBurst,
	)

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
				s.logger.Debug("auth.failed",
					"remote", r.RemoteAddr,
					"path", r.URL.Path,
					"reason", "invalid_api_key",
				)
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)

				return
			}

			s.logger.Log(r.Context(), logging.LevelTrace, "auth.success",
				"remote", r.RemoteAddr,
				"path", r.URL.Path,
			)

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitMiddleware applies per-IP rate limiting (Chi middleware).
func (s *Server) rateLimitMiddleware(rl RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow(r.RemoteAddr) {
				s.logger.Debug("rate_limit.denied",
					"remote", r.RemoteAddr,
					"path", r.URL.Path,
				)
				http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
