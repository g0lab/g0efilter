// Package server provides the web UI and HTTP API server.
package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/shared/logging"
	"github.com/gin-gonic/gin"
)

const (
	// Login brute-force limiter: per-IP token bucket.
	loginRateRPS   = 0.5
	loginRateBurst = 5

	sessionGCInterval = 15 * time.Minute
)

// Config holds the dashboard server configuration.
type Config struct {
	Addr         string // ":8081"
	APIKey       string
	LogLevel     string  // "INFO"
	BufferSize   int     // optional (default 5000)
	ReadLimit    int     // optional (default 5000)
	SERetryMs    int     // optional (default 2000) - SSE client retry hint
	RateRPS      float64 // optional (default 50)
	RateBurst    float64 // optional (default 100)
	WriteTimeout int     // optional (default 0 = no timeout) - HTTP write timeout in seconds
	Version      string  // optional - dashboard version for logging

	AuthMode          string        // "session" (default), "none", "forward", or "jwt"
	DBPath            string        // SQLite file; empty = in-memory stores (no persistence)
	CookieSecure      bool          // set Secure on the session cookie (default true)
	SessionTTL        time.Duration // session lifetime (default 24h)
	ForwardAuthHeader string        // trusted identity header in forward mode
	AdminUsername     string        // session-mode admin user (default "admin")
	AdminPasswordHash string        // bcrypt hash for the admin user

	// jwt mode (OIDC/SSO): validate a bearer token. Exactly one key source.
	JWTSecret        string // HS256 shared secret
	JWTPublicKeyPEM  string // RS256/ES256 PEM (inline or @/path/to/file)
	JWKSURL          string // OIDC JWKS endpoint (RS256/ES256, keys fetched + cached)
	JWTUsernameClaim string // claim used as the principal (default "sub")
	JWTIssuer        string // optional "iss" to require
	JWTAudience      string // optional "aud" to require

	// CORS: allowed browser origins for the API. Empty = no CORS headers
	// (same-origin only), which is the right default behind a reverse proxy.
	CORSAllowedOrigins []string

	// TrustedProxyCIDRs are the reverse-proxy networks whose X-Forwarded-For
	// header is honored for the client IP (used by rate limiting / logs). Empty
	// = do not trust XFF; use the socket peer, so a directly-exposed dashboard
	// cannot be spoofed to bypass per-IP throttling.
	TrustedProxyCIDRs []string

	// LogRetention caps rows kept when logs are persisted (DBPath set); oldest
	// are pruned beyond it (default 100000).
	LogRetention int

	// Fleet management (Phase 7): opt-in instance/group/policy control plane.
	FleetEnabled bool
}

// Server holds all dependencies for HTTP handlers.
type Server struct {
	logger       *slog.Logger
	store        LogStore
	broadcaster  EventBroadcaster
	unblockStore UnblockStore // Pending unblock requests
	apiKeys      APIKeyStore
	sessions     SessionStore
	users        UserStore
	fleet        FleetStore
	fleetChanges *changeNotifier
	readLimit    int
	bufferSize   int
	sseRetry     time.Duration
	rateLimiter  RateLimiter
	loginLimiter RateLimiter
	bootstrapOut io.Writer

	authMode          string
	cookieSecure      bool
	sessionTTL        time.Duration
	forwardAuthHeader string

	// jwtVerify resolves a request to a principal in jwt mode; built at
	// startup by setupJWT so key/JWKS errors fail closed before serving.
	jwtVerify func(r *http.Request) (principal string, ok bool)

	corsOrigins       []string
	trustedProxyCIDRs []string
	fleetEnabled      bool
}

// LogEntry represents a single ingested or synthetic log event.
type LogEntry = model.LogEntry

// Run starts the dashboard HTTP server with the provided configuration.
//
//nolint:funlen,cyclop // linear startup sequence of guarded init steps
func Run(ctx context.Context, cfg Config) error {
	if _, configured := os.LookupEnv(gin.EnvGinMode); !configured {
		gin.SetMode(gin.ReleaseMode)
	}

	lg := logging.New(cfg.LogLevel, os.Stdout)
	slog.SetDefault(lg)

	err := validateAuthConfig(cfg)
	if err != nil {
		lg.Error("config.invalid_auth_mode", "auth_mode", cfg.AuthMode)

		return err
	}

	err = validateCORSOrigins(cfg.CORSAllowedOrigins)
	if err != nil {
		lg.Error("config.invalid_cors", "error", err.Error())

		return err
	}

	srv := newServer(lg, cfg)

	// Persistence + auth stores must be ready (and migrations applied)
	// before the server accepts a single request.
	closeStores, err := srv.wireStores(ctx, cfg)
	if err != nil {
		lg.Error("dashboard.store_init_failed", "error", err.Error())

		return err
	}
	defer closeStores()

	err = ensureAdminUser(ctx, cfg, srv.users, lg, srv.bootstrapOut)
	if err != nil {
		lg.Error("config.admin_seed_failed", "error", err.Error())

		return err
	}

	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		lg.Error("dashboard.api_key_init_failed", "error", err.Error())

		return err
	}

	err = srv.setupJWT(ctx, cfg)
	if err != nil {
		lg.Error("config.jwt_setup_failed", "error", err.Error())

		return err
	}

	go srv.sessionGCLoop(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.routes(), //nolint:contextcheck // request deadlines derive from each HTTP request, not startup
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
		unblockStore: newUnblockStore(),
		apiKeys:      newMemAPIKeyStore(cfg.APIKey),
		sessions:     newMemSessionStore(),
		users:        newMemUserStore(),
		fleetChanges: newChangeNotifier(),
		readLimit:    cfg.ReadLimit,
		bufferSize:   cfg.BufferSize,
		sseRetry:     time.Duration(cfg.SERetryMs) * time.Millisecond,
		rateLimiter:  newRateLimiter(cfg.RateRPS, cfg.RateBurst),
		loginLimiter: newRateLimiter(loginRateRPS, loginRateBurst),
		bootstrapOut: os.Stderr,

		authMode:          cfg.AuthMode,
		cookieSecure:      cfg.CookieSecure,
		sessionTTL:        cfg.SessionTTL,
		forwardAuthHeader: cfg.ForwardAuthHeader,

		corsOrigins:       cfg.CORSAllowedOrigins,
		trustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		fleetEnabled:      cfg.FleetEnabled,
	}
}

// loginPublicFiles are static paths reachable without a session so the login
// page can render. /assets/* (hashed JS/CSS bundles - public code, no data)
// is added separately; index.html and the API stay behind auth.
//
//nolint:gochecknoglobals // fixed allowlist
var loginPublicFiles = []string{"/login.html", "/favicon.ico"}

// routes configures all HTTP routes and middleware.
//
//nolint:funlen // route table + middleware wiring reads best in one place
func (s *Server) routes() http.Handler {
	r := gin.New()
	r.RedirectTrailingSlash = false

	// Gin trusts all proxies by default. Always replace that default: an empty
	// list means trust no forwarded headers, while configured CIDRs are checked
	// against the network peer before X-Forwarded-For is accepted.
	err := r.SetTrustedProxies(s.trustedProxyCIDRs)
	if err != nil {
		s.logger.Error("dashboard.invalid_trusted_proxy", "error", err.Error())

		_ = r.SetTrustedProxies(nil)
	}

	r.Use(requestIDMiddleware())
	r.Use(s.clientIPMiddleware())
	r.Use(s.securityHeadersMiddleware())

	// CORS before auth so preflight (which carries no credentials) is answered.
	if corsHandler := s.corsMiddleware(); corsHandler != nil {
		r.Use(corsHandler)
	}

	r.Use(s.loggerMiddleware())
	r.Use(s.recoveryMiddleware())
	r.Use(requestTimeoutMiddleware(60 * time.Second))

	// Public routes
	r.GET("/health", httpHandler(s.healthHandler))

	// Auth endpoints. Login is rate-limited against brute force and
	// CSRF-checked (login CSRF); logout/me operate on the presented cookie.
	login := r.Group("/api/v1/auth")
	login.Use(s.rateLimitMiddleware(s.loginLimiter), s.csrfMiddleware())
	login.POST("/login", httpHandler(s.loginHandler))
	r.POST("/api/v1/auth/logout", s.csrfMiddleware(), httpHandler(s.logoutHandler))
	r.GET("/api/v1/auth/me", httpHandler(s.meHandler))

	// API v1 routes
	api := r.Group("/api/v1")

	// Machine realm (X-Api-Key; used by g0efilter instances).
	unblocks := api.Group("/unblocks", s.requireAPIKey())
	unblocks.GET("", httpHandler(s.listUnblocksHandler))    // g0efilter polls for pending
	unblocks.POST("/ack", httpHandler(s.ackUnblockHandler)) // g0efilter acknowledges processed

	// Log ingestion (API key + rate limiting).
	ingest := api.Group("", s.requireAPIKey(), s.rateLimitMiddleware(s.rateLimiter), requireJSONMiddleware())
	ingest.POST("/logs", httpHandler(s.ingestHandler))

	// Fleet reconcile (API key; instances long-poll for desired config).
	if s.fleetEnabled {
		fleetSync := api.Group("", s.requireAPIKey(), s.rateLimitMiddleware(s.rateLimiter), requireJSONMiddleware())
		fleetSync.POST("/sync", httpHandler(s.syncHandler))
	}

	// Human realm (AUTH_MODE session/none/forward + CSRF).
	admin := api.Group("", s.uiAuthMiddleware(), s.csrfMiddleware())
	admin.GET("/config", httpHandler(s.configHandler))
	admin.GET("/logs", httpHandler(s.listLogsHandler))            // sensitive: exposes traffic logs
	admin.GET("/aggregates", httpHandler(s.aggregateLogsHandler)) // sensitive: summarizes traffic logs
	admin.GET("/events", httpHandler(s.sseHandler))               // sensitive: streams live traffic data
	admin.DELETE("/logs", httpHandler(s.clearLogsHandler))        // sensitive: destructive - clears all logs
	admin.POST("/unblocks", httpHandler(s.createUnblockHandler))  // sensitive: queues firewall policy changes
	admin.GET("/unblocks/status", httpHandler(s.unblockStatusHandler))

	// API key management.
	admin.GET("/apikeys", httpHandler(s.listAPIKeysHandler))
	admin.POST("/apikeys", httpHandler(s.createAPIKeyHandler))
	admin.DELETE("/apikeys/:id", httpHandler(s.revokeAPIKeyHandler))

	// Fleet management (admin).
	if s.fleetEnabled {
		admin.GET("/fleet/instances", httpHandler(s.listInstancesHandler))
		admin.DELETE("/fleet/instances/:id", httpHandler(s.deleteInstanceHandler))
		admin.PUT("/fleet/instances/:id/group", httpHandler(s.setInstanceGroupHandler))
		admin.PUT("/fleet/instances/:id/policy", httpHandler(s.setInstancePolicyHandler))
		admin.GET("/fleet/groups", httpHandler(s.listGroupsHandler))
		admin.POST("/fleet/groups", httpHandler(s.createGroupHandler))
		admin.DELETE("/fleet/groups/:id", httpHandler(s.deleteGroupHandler))
		admin.PUT("/fleet/groups/:id/policy", httpHandler(s.setGroupPolicyHandler))
	}

	// Static UI: login page + hashed asset bundles are public, the rest
	// (index.html and any future pages) requires auth.
	ui := IndexHandler()
	for _, p := range loginPublicFiles {
		r.GET(p, gin.WrapH(ui))
		r.HEAD(p, gin.WrapH(ui))
	}

	r.GET("/assets/*filepath", gin.WrapH(ui))
	r.HEAD("/assets/*filepath", gin.WrapH(ui))

	// A root catch-all conflicts with Gin's registered API routes. NoRoute is
	// the authenticated static-file fallback for / and future UI paths.
	r.NoRoute(s.uiAuthMiddleware(), gin.WrapH(ui))

	return r
}

// httpHandler adapts the existing net/http transport handlers to Gin. Route
// parameters are copied into Request.PathValue so handlers stay independent
// of the router implementation.
func httpHandler(handler http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, param := range c.Params {
			c.Request.SetPathValue(param.Key, param.Value)
		}

		handler(c.Writer, c.Request)
	}
}

const requestIDHeader = "X-Request-ID"

// requestIDMiddleware preserves an incoming request ID or generates a
// cryptographically random one, then exposes it on both request and response.
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(requestIDHeader)
		if requestID == "" {
			requestID = rand.Text()
			c.Request.Header.Set(requestIDHeader, requestID)
		}

		c.Header(requestIDHeader, requestID)
		c.Next()
	}
}

// requestTimeoutMiddleware leaves SSE open until the client disconnects. All
// ordinary requests, including the capped 30-second fleet long-poll, retain a
// defensive server-side deadline.
func requestTimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/api/v1/events" {
			c.Next()

			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

type clientIPContextKey struct{}

// clientIPMiddleware records Gin's proxy-validated client IP on the request so
// the router-independent handlers and auth code can use it.
func (s *Server) clientIPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), clientIPContextKey{}, c.ClientIP())
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// clientIP returns the proxy-validated client IP recorded by Gin. Direct
// handler calls (primarily unit tests) fall back to the socket peer.
func clientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPContextKey{}).(string); ok && ip != "" {
		return ip
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}

// securityHeadersMiddleware sets standard HTTP security headers on every response.
// The Svelte build emits external hashed script bundles. Svelte style directives
// and transitions update element style attributes at runtime, so style-src must
// permit inline styles; script-src remains restricted to same-origin files.
// In production these headers may be overridden or supplemented by the reverse proxy (e.g. Traefik).
func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	const csp = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"

	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", csp)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// loggerMiddleware logs HTTP requests with structured logging.
func (s *Server) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		if s.logger != nil {
			s.logger.Debug("http.req",
				"request_id", c.GetHeader(requestIDHeader),
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"remote", clientIP(c.Request),
				"code", c.Writer.Status(),
				"bytes", c.Writer.Size(),
				"duration", time.Since(start).String(),
			)
		}
	}
}

// recoveryMiddleware keeps panic output in structured logs instead of Gin's
// default stderr logger.
func (s *Server) recoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		s.logger.Error("http.panic", "path", c.Request.URL.Path, "panic", recovered)
		http.Error(c.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		c.Abort()
	})
}

// requireAPIKey validates the X-Api-Key header against the key store
// (Gin middleware). Comparison is constant-time over hashed keys.
func (s *Server) requireAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request

		keyID, ok := s.apiKeys.Validate(r.Context(), r.Header.Get("X-Api-Key"))
		if !ok {
			s.logger.Debug("auth.failed",
				"remote", clientIP(r),
				"path", r.URL.Path,
				"reason", "invalid_api_key",
			)
			c.Header("Content-Type", "application/json")
			http.Error(c.Writer, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			c.Abort()

			return
		}

		s.logger.Log(r.Context(), logging.LevelTrace, "auth.success",
			"remote", clientIP(r),
			"path", r.URL.Path,
			"key_id", keyID,
		)

		c.Next()
	}
}

// rateLimitMiddleware applies per-IP rate limiting (Gin middleware).
func (s *Server) rateLimitMiddleware(rl RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		remote := clientIP(c.Request)
		if !rl.Allow(remote) {
			s.logger.Debug("rate_limit.denied",
				"remote", remote,
				"path", c.Request.URL.Path,
			)
			http.Error(c.Writer, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			c.Abort()

			return
		}

		c.Next()
	}
}

// requireJSONMiddleware preserves Chi's AllowContentType behavior: requests
// with a body must use application/json, with optional media-type parameters.
func requireJSONMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength != 0 {
			contentType := strings.ToLower(c.ContentType())
			if contentType != "application/json" {
				c.AbortWithStatus(http.StatusUnsupportedMediaType)

				return
			}
		}

		c.Next()
	}
}
