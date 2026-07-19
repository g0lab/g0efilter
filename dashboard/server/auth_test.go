//nolint:testpackage // Need access to internal implementation details
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	testAdminUser = "admin"
	testAdminPass = "correct horse battery staple"
)

func newSessionTestServer(t *testing.T) *Server {
	t.Helper()

	logger := slog.New(slog.DiscardHandler)
	cfg := Config{
		APIKey:     "test-api-key",
		BufferSize: 100,
		ReadLimit:  50,
		RateRPS:    100,
		RateBurst:  200,
		AuthMode:   AuthModeSession,
		SessionTTL: time.Hour,
		// CookieSecure false: httptest is plain http and __Host- cookies
		// require a secure context.
		CookieSecure: false,
	}

	srv := newServer(logger, cfg)

	hash, err := bcrypt.GenerateFromPassword([]byte(testAdminPass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	err = srv.users.Upsert(context.Background(), testAdminUser, string(hash))
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	return srv
}

func doLogin(t *testing.T, router http.Handler, pass string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"username":"` + testAdminUser + `","password":"` + pass + `"}`
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, sessionCookieBase) && c.Value != "" {
			return c
		}
	}

	t.Fatal("no session cookie set")

	return nil
}

//nolint:cyclop,funlen // sequential scenario test
func TestSessionMode_LoginFlow(t *testing.T) {
	t.Parallel()

	srv := newSessionTestServer(t)
	router := srv.routes()

	// Unauthenticated API request → 401 JSON.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/v1/logs = %d, want 401", w.Code)
	}

	// Unauthenticated page request → redirect to login.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login.html" {
		t.Fatalf("unauthenticated / = %d loc %q, want 302 /login.html", w.Code, w.Header().Get("Location"))
	}

	// Login page itself is reachable.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login.html", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/login.html = %d, want 200", w.Code)
	}

	// Wrong password → 401, no cookie.
	w = doLogin(t, router, "wrong")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", w.Code)
	}

	// Correct login → cookie.
	w = doLogin(t, router, testAdminPass)
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (body %q)", w.Code, w.Body.String())
	}

	cookie := sessionCookie(t, w)

	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags: HttpOnly=%v SameSite=%v, want HttpOnly Strict", cookie.HttpOnly, cookie.SameSite)
	}

	// Authenticated API request succeeds.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	req.AddCookie(cookie)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("authed /api/v1/logs = %d, want 200", w.Code)
	}

	// Logout revokes the session.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", w.Code)
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	req.AddCookie(cookie)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /api/v1/logs = %d, want 401", w.Code)
	}
}

func TestSessionMode_APIKeyFallback(t *testing.T) {
	t.Parallel()

	srv := newSessionTestServer(t)
	router := srv.routes()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	req.Header.Set("X-Api-Key", "test-api-key")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("api-key /api/v1/logs = %d, want 200", w.Code)
	}
}

func TestSessionMode_CSRFRejected(t *testing.T) {
	t.Parallel()

	srv := newSessionTestServer(t)
	router := srv.routes()

	w := doLogin(t, router, testAdminPass)
	cookie := sessionCookie(t, w)

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"cross-site fetch metadata", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"mismatched origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-origin fetch metadata", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"no browser headers", nil, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodDelete, "/api/v1/logs", nil)
			req.AddCookie(cookie)

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.want {
				t.Errorf("Status = %d, want %d (body %q)", w.Code, tt.want, w.Body.String())
			}
		})
	}
}

func TestForwardMode(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	srv := newServer(logger, Config{
		APIKey:            "test-api-key",
		BufferSize:        10,
		ReadLimit:         10,
		AuthMode:          AuthModeForward,
		ForwardAuthHeader: "X-Forwarded-User",
	})
	router := srv.routes()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no header = %d, want 401", w.Code)
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	req.Header.Set("X-Forwarded-User", "alice")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("with header = %d, want 200", w.Code)
	}
}

func TestValidateAuthConfig(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{AuthModeSession, AuthModeNone, AuthModeForward} {
		err := validateAuthConfig(Config{AuthMode: mode})
		if err != nil {
			t.Errorf("validateAuthConfig(%q) = %v, want nil", mode, err)
		}
	}

	// A typo must fail closed at startup, never fall back to no auth.
	err := validateAuthConfig(Config{AuthMode: "off"})
	if err == nil {
		t.Error("validateAuthConfig(off) = nil, want error")
	}
}

func TestEnsureAdminUser(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	lg := slog.New(slog.DiscardHandler)

	// No hash, no users → auto-generate a bootstrap admin (does not fail).
	gen := newMemUserStore()

	err := ensureAdminUser(ctx, Config{AuthMode: AuthModeSession, AdminUsername: "admin"}, gen, lg)
	if err != nil {
		t.Fatalf("auto-generate admin: %v", err)
	}

	if n, _ := gen.Count(ctx); n != 1 {
		t.Fatalf("auto-generated users = %d, want 1", n)
	}

	// Hash provided → seeded.
	users := newMemUserStore()
	cfg := Config{AuthMode: AuthModeSession, AdminUsername: "admin", AdminPasswordHash: "x"}

	err = ensureAdminUser(ctx, cfg, users, lg)
	if err != nil {
		t.Fatalf("ensureAdminUser: %v", err)
	}

	n, _ := users.Count(ctx)
	if n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}

	// None mode never requires credentials.
	err = ensureAdminUser(ctx, Config{AuthMode: AuthModeNone}, newMemUserStore(), lg)
	if err != nil {
		t.Fatalf("none mode: %v", err)
	}
}

func TestAPIKeyAdminEndpoints(t *testing.T) {
	t.Parallel()

	srv := newSessionTestServer(t)
	router := srv.routes()

	w := doLogin(t, router, testAdminPass)
	cookie := sessionCookie(t, w)

	// Create a key.
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/apikeys", strings.NewReader(`{"label":"ci"}`))
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create key = %d (body %q)", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, `"key":"g0e_`) {
		t.Fatalf("create response missing plaintext key: %q", body)
	}

	// Extract plaintext key and its id.
	key := extractJSONField(t, body, "key")
	id := extractJSONField(t, body, "id")

	// New key authenticates the machine realm.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks", nil)
	req.Header.Set("X-Api-Key", key)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("new key on machine realm = %d, want 200", w.Code)
	}

	// Revoke it → key stops working.
	req = httptest.NewRequestWithContext(context.Background(),
		http.MethodDelete, "/api/v1/apikeys/"+id, nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("revoke = %d (body %q)", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/unblocks", nil)
	req.Header.Set("X-Api-Key", key)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key = %d, want 401", w.Code)
	}
}

func TestListAPIKeys(t *testing.T) {
	t.Parallel()

	srv := newSessionTestServer(t)
	router := srv.routes()

	cookie := sessionCookie(t, doLogin(t, router, testAdminPass))

	listKeys := func() []map[string]any {
		req := httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/apikeys", nil)
		req.AddCookie(cookie)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("list apikeys = %d (%s)", w.Code, w.Body.String())
		}

		var out []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode apikeys: %v", err)
		}

		return out
	}

	// The config API key seeds one env-bootstrap record.
	if got := len(listKeys()); got != 1 {
		t.Fatalf("initial apikeys = %d, want 1 (env bootstrap)", got)
	}

	// Creating a key makes the list grow; the plaintext is never re-listed.
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/apikeys", strings.NewReader(`{"label":"ci"}`))
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create apikey = %d (%s)", w.Code, w.Body.String())
	}

	keys := listKeys()
	if len(keys) != 2 {
		t.Fatalf("apikeys after create = %d, want 2", len(keys))
	}

	for _, k := range keys {
		if _, leaked := k["key"]; leaked {
			t.Error("apikey list leaked plaintext key material")
		}
	}
}

func TestMeHandler(t *testing.T) {
	t.Parallel()

	// None mode: authenticated as the anonymous principal.
	none := newServer(slog.New(slog.DiscardHandler), Config{
		APIKey: "test-api-key", BufferSize: 10, ReadLimit: 10, AuthMode: AuthModeNone,
	})

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/auth/me", nil)
	w := httptest.NewRecorder()
	none.routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("me (none) = %d, want 200", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode me: %v", err)
	}

	if body["username"] != "anonymous" {
		t.Errorf("me username = %v, want anonymous", body["username"])
	}

	// Session mode without a cookie: 401, but still reports the auth_mode so the
	// UI knows which login flow to present.
	sess := newSessionTestServer(t)

	req = httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/auth/me", nil)
	w = httptest.NewRecorder()
	sess.routes().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("me (session, no cookie) = %d, want 401", w.Code)
	}

	body = nil
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode me: %v", err)
	}

	if body[keyAuthMode] != AuthModeSession {
		t.Errorf("me auth_mode = %v, want %q", body[keyAuthMode], AuthModeSession)
	}
}

// extractJSONField pulls a top-level-ish string field from a JSON body without
// depending on response struct shapes.
func extractJSONField(t *testing.T, body, field string) string {
	t.Helper()

	marker := `"` + field + `":"`

	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("field %q not in %q", field, body)
	}

	rest := body[i+len(marker):]

	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated field %q in %q", field, body)
	}

	return rest[:j]
}
