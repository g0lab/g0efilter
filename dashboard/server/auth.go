package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	// AuthModeSession serves a built-in login form backed by server-side sessions.
	AuthModeSession = "session"
	// AuthModeNone disables built-in auth; deploy behind an authenticating proxy.
	AuthModeNone = "none"
	// AuthModeForward trusts an identity header set by an authenticating proxy.
	AuthModeForward = "forward"

	sessionCookieBase = "g0e_session"
)

var errUnknownAuthMode = errors.New("unknown AUTH_MODE (want session, none, forward, or jwt)")

// generatedPasswordBytes yields ~27 URL-safe characters of entropy.
const generatedPasswordBytes = 20

// sessionCookieName returns the cookie name; the __Host- prefix binds the
// cookie to this host over HTTPS with Path=/ and no Domain attribute.
func (s *Server) sessionCookieName() string {
	if s.cookieSecure {
		return "__Host-" + sessionCookieBase
	}

	return sessionCookieBase
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	//nolint:gosec // HttpOnly+Strict are set; Secure follows COOKIE_SECURE (default true, off only for http dev)
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	//nolint:gosec // expiring cookie; Secure follows COOKIE_SECURE (default true, off only for http dev)
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

// authenticate resolves the request principal for browser-facing routes
// according to AUTH_MODE. In session mode a valid API key is also accepted
// so operators can script against UI endpoints.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	switch s.authMode {
	case AuthModeNone:
		return "anonymous", true

	case AuthModeForward:
		principal := strings.TrimSpace(r.Header.Get(s.forwardAuthHeader))

		return principal, principal != ""

	case AuthModeJWT:
		if s.jwtVerify == nil {
			return "", false
		}

		return s.jwtVerify(r)

	case AuthModeSession:
		c, err := r.Cookie(s.sessionCookieName())
		if err == nil {
			if sess, ok := s.sessions.Lookup(r.Context(), c.Value); ok {
				return sess.Username, true
			}
		}

		if keyID, ok := s.apiKeys.Validate(r.Context(), r.Header.Get("X-Api-Key")); ok {
			return "apikey:" + keyID, true
		}

		return "", false

	default:
		// Unknown mode is rejected at startup; fail closed if it slips through.
		return "", false
	}
}

// uiAuthMiddleware guards browser-facing endpoints and static files.
func (s *Server) uiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request

		principal, ok := s.authenticate(r)
		if !ok {
			s.logger.Debug("auth.denied",
				"remote", clientIP(r),
				"path", r.URL.Path,
				"mode", s.authMode,
			)
			s.denyUnauthenticated(c.Writer, r)
			c.Abort()

			return
		}

		_ = principal

		c.Next()
	}
}

// denyUnauthenticated returns 401 JSON for API calls and redirects page
// requests to the login form (session mode only).
func (s *Server) denyUnauthenticated(w http.ResponseWriter, r *http.Request) {
	isPage := r.Method == http.MethodGet &&
		!strings.HasPrefix(r.URL.Path, "/api/") &&
		strings.Contains(r.Header.Get("Accept"), "text/html")

	if isPage && s.authMode == AuthModeSession {
		http.Redirect(w, r, "/login.html", http.StatusFound)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}

// csrfMiddleware rejects cross-site state-changing requests using fetch
// metadata, falling back to an Origin/Host check. Requests without browser
// headers pass: SameSite=Strict already stops browsers attaching the session
// cookie cross-site, and non-browser clients carry no ambient credentials.
func (s *Server) csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()

			return
		}

		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" && site != "none" {
				s.denyCSRF(c.Writer, r, "sec-fetch-site="+site)
				c.Abort()

				return
			}

			c.Next()

			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				s.denyCSRF(c.Writer, r, "origin="+origin)
				c.Abort()

				return
			}
		}

		c.Next()
	}
}

func (s *Server) denyCSRF(w http.ResponseWriter, r *http.Request, reason string) {
	s.logger.Warn("auth.csrf_denied",
		"remote", clientIP(r),
		"path", r.URL.Path,
		"reason", reason,
	)
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error":"cross-site request rejected"}`, http.StatusForbidden)
}

// loginHandler handles POST /api/v1/auth/login.
func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	if s.authMode != AuthModeSession {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"login disabled"}`, http.StatusNotFound)

		return
	}

	const maxBody = 4096

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)

		return
	}

	user, ok := s.users.VerifyPassword(r.Context(), strings.TrimSpace(req.Username), req.Password)
	if !ok {
		s.logger.Warn("auth.login_failed",
			"remote", clientIP(r),
			"username", strings.TrimSpace(req.Username),
		)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)

		return
	}

	token, err := s.sessions.Create(r.Context(), user, s.sessionTTL)
	if err != nil {
		s.logger.Error("auth.session_create_failed", "error", err.Error())
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)

		return
	}

	s.setSessionCookie(w, token)
	s.logger.Info("auth.login", "remote", clientIP(r), "username", user.Username)
	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{"username": user.Username})
	if err != nil {
		s.logger.Error("failed to encode login response", "error", err)
	}
}

// logoutHandler handles POST /api/v1/auth/logout. Idempotent.
func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.sessionCookieName())
	if err == nil && c.Value != "" {
		err = s.sessions.Revoke(r.Context(), c.Value)
		if err != nil {
			s.logger.Error("auth.logout_revoke_failed", "error", err.Error())
		}
	}

	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// meHandler handles GET /api/v1/auth/me so the UI can resolve auth state.
func (s *Server) meHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	principal, ok := s.authenticate(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		err := json.NewEncoder(w).Encode(map[string]any{keyAuthMode: s.authMode})
		if err != nil {
			s.logger.Error("failed to encode me response", "error", err)
		}

		return
	}

	err := json.NewEncoder(w).Encode(map[string]any{
		keyAuthMode: s.authMode,
		"username":  principal,
	})
	if err != nil {
		s.logger.Error("failed to encode me response", "error", err)
	}
}

// validateAuthConfig rejects unknown AUTH_MODE values so a typo can never
// silently disable authentication.
func validateAuthConfig(cfg Config) error {
	switch cfg.AuthMode {
	case AuthModeSession, AuthModeNone, AuthModeForward, AuthModeJWT:
		return nil
	default:
		return fmt.Errorf("%w: %q", errUnknownAuthMode, cfg.AuthMode)
	}
}

// ensureAdminUser seeds/updates the admin login. In session mode with no
// ADMIN_PASSWORD_HASH and no existing user, it auto-generates a strong random
// password and logs it once (bootstrap) rather than failing startup - so a
// fresh dashboard is reachable. Recover a lost password with the
// reset-password subcommand.
func ensureAdminUser(ctx context.Context, cfg Config, users UserStore, lg *slog.Logger) error {
	if cfg.AuthMode != AuthModeSession {
		return nil
	}

	if cfg.AdminPasswordHash != "" {
		err := users.Upsert(ctx, cfg.AdminUsername, cfg.AdminPasswordHash)
		if err != nil {
			return fmt.Errorf("seed admin user: %w", err)
		}

		return nil
	}

	n, err := users.Count(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}

	if n > 0 {
		return nil
	}

	return generateAdminUser(ctx, cfg.AdminUsername, users, lg)
}

// generateAdminUser mints and persists a random admin password, logging it once.
func generateAdminUser(ctx context.Context, username string, users UserStore, lg *slog.Logger) error {
	password := generatePassword()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash generated password: %w", err)
	}

	err = users.Upsert(ctx, username, string(hash))
	if err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	}

	lg.Warn("dashboard.admin_password_generated",
		"username", username,
		"password", password,
		"msg", "auto-generated admin password on first startup; set ADMIN_PASSWORD_HASH or use reset-password to rotate")

	return nil
}

// generatePassword returns a high-entropy URL-safe password.
func generatePassword() string {
	b := make([]byte, generatedPasswordBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never errors on Linux (Go 1.20+)

	return base64.RawURLEncoding.EncodeToString(b)
}
