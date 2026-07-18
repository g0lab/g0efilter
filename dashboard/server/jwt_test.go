//nolint:testpackage // Need access to internal implementation details
package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const jwtTestSecret = "test-signing-secret-please-change"

func signHS256(t *testing.T, build func(b *jwt.Builder) *jwt.Builder) string {
	t.Helper()

	b := jwt.NewBuilder().
		Subject("alice").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))

	tok, err := build(b).Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte(jwtTestSecret)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}

func newJWTServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	cfg.AuthMode = AuthModeJWT
	cfg.APIKey = "test-api-key"
	cfg.BufferSize = 10
	cfg.ReadLimit = 10

	srv := newServer(slog.New(slog.DiscardHandler), cfg)

	err := srv.setupJWT(context.Background(), cfg)
	if err != nil {
		t.Fatalf("setupJWT: %v", err)
	}

	return srv
}

func getWithBearer(router http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/logs", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func TestJWTMode_HS256(t *testing.T) {
	t.Parallel()

	srv := newJWTServer(t, Config{JWTSecret: jwtTestSecret})
	router := srv.routes()

	// Valid token -> 200.
	valid := signHS256(t, func(b *jwt.Builder) *jwt.Builder { return b })
	if w := getWithBearer(router, valid); w.Code != http.StatusOK {
		t.Fatalf("valid token = %d, want 200", w.Code)
	}

	// No token -> 401.
	if w := getWithBearer(router, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", w.Code)
	}

	// Wrong-secret signature -> 401.
	bad, _ := jwt.Sign(
		func() jwt.Token {
			tk, _ := jwt.NewBuilder().Subject("x").Expiration(time.Now().Add(time.Hour)).Build()

			return tk
		}(),
		jwt.WithKey(jwa.HS256(), []byte("a-totally-different-secret-value")),
	)
	if w := getWithBearer(router, string(bad)); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret token = %d, want 401", w.Code)
	}

	// Expired token -> 401.
	expired := signHS256(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Expiration(time.Now().Add(-time.Hour))
	})
	if w := getWithBearer(router, expired); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d, want 401", w.Code)
	}
}

func TestJWTMode_IssuerAudienceClaim(t *testing.T) {
	t.Parallel()

	srv := newJWTServer(t, Config{
		JWTSecret:        jwtTestSecret,
		JWTIssuer:        "https://idp.example",
		JWTAudience:      "g0efilter",
		JWTUsernameClaim: "email",
	})
	router := srv.routes()

	good := signHS256(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Issuer("https://idp.example").Audience([]string{"g0efilter"}).Claim("email", "a@b.c")
	})
	if w := getWithBearer(router, good); w.Code != http.StatusOK {
		t.Fatalf("matching iss/aud/claim = %d, want 200", w.Code)
	}

	// Wrong issuer -> 401.
	wrongIss := signHS256(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Issuer("https://evil.example").Audience([]string{"g0efilter"}).Claim("email", "a@b.c")
	})
	if w := getWithBearer(router, wrongIss); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong issuer = %d, want 401", w.Code)
	}

	// Missing the configured username claim -> 401.
	noClaim := signHS256(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Issuer("https://idp.example").Audience([]string{"g0efilter"})
	})
	if w := getWithBearer(router, noClaim); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing claim = %d, want 401", w.Code)
	}
}

func TestJWTMode_SetupValidation(t *testing.T) {
	t.Parallel()

	srv := newServer(slog.New(slog.DiscardHandler), Config{AuthMode: AuthModeJWT})

	// No key source -> startup error (fail closed).
	noKey := srv.setupJWT(context.Background(), Config{AuthMode: AuthModeJWT})
	if noKey == nil {
		t.Fatal("want error with no key source")
	}

	// Two key sources -> error.
	multi := srv.setupJWT(context.Background(), Config{
		AuthMode: AuthModeJWT, JWTSecret: "x", JWKSURL: "https://idp/jwks",
	})
	if multi == nil {
		t.Fatal("want error with multiple key sources")
	}
}
