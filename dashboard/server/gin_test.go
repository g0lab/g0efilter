//nolint:testpackage // Tests Gin transport wiring and private middleware.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestGinRequestID(t *testing.T) {
	t.Parallel()

	router := newTestServer().routes()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "test-request-id")

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "test-request-id" {
		t.Fatalf("X-Request-ID = %q, want test-request-id", got)
	}
}

func TestGinRecoveryMiddleware(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	router := gin.New()
	router.Use(srv.recoveryMiddleware())
	router.GET("/panic", func(*gin.Context) { panic("test panic") })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestGinRequestTimeout(t *testing.T) {
	t.Parallel()

	router := gin.New()
	router.Use(requestTimeoutMiddleware(time.Minute))
	router.GET("/ordinary", func(c *gin.Context) {
		_, hasDeadline := c.Request.Context().Deadline()
		c.JSON(http.StatusOK, gin.H{"deadline": hasDeadline})
	})
	router.GET("/api/v1/events", func(c *gin.Context) {
		_, hasDeadline := c.Request.Context().Deadline()
		c.JSON(http.StatusOK, gin.H{"deadline": hasDeadline})
	})

	for _, tt := range []struct {
		path     string
		wantBody string
	}{
		{path: "/ordinary", wantBody: `{"deadline":true}`},
		{path: "/api/v1/events", wantBody: `{"deadline":false}`},
	} {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if got := rec.Body.String(); got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestGinTrustedProxyClientIP(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		trusted []string
		want    string
	}{
		{name: "untrusted peer ignores XFF", trusted: nil, want: "192.0.2.10"},
		{name: "trusted peer accepts XFF", trusted: []string{"192.0.2.0/24"}, want: "198.51.100.7"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newServer(slog.New(slog.DiscardHandler), Config{})
			router := gin.New()

			err := router.SetTrustedProxies(tt.trusted)
			if err != nil {
				t.Fatalf("SetTrustedProxies: %v", err)
			}

			router.Use(srv.clientIPMiddleware())
			router.GET("/ip", func(c *gin.Context) {
				c.String(http.StatusOK, clientIP(c.Request))
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ip", nil)
			req.RemoteAddr = "192.0.2.10:4321"
			req.Header.Set("X-Forwarded-For", "198.51.100.7")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if got := rec.Body.String(); got != tt.want {
				t.Fatalf("client IP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenFromRequestCookie(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:     "jwt",
		Value:    "cookie-token",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	if got := tokenFromRequest(req); got != "cookie-token" {
		t.Fatalf("tokenFromRequest = %q, want cookie-token", got)
	}
}

func TestGinUnknownAPIRoute(t *testing.T) {
	t.Parallel()

	router := newTestServer().routes()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/not-a-route", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
