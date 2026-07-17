//nolint:testpackage // Need access to internal implementation details
package dashboard

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsServer(t *testing.T, origins []string) http.Handler {
	t.Helper()

	srv := newServer(slog.New(slog.DiscardHandler), Config{
		APIKey: "test-api-key", BufferSize: 10, ReadLimit: 10,
		AuthMode: AuthModeNone, CORSAllowedOrigins: origins,
	})

	return srv.routes()
}

func preflight(router http.Handler, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/v1/logs", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func TestCORS_AllowedOrigin(t *testing.T) {
	t.Parallel()

	router := corsServer(t, []string{"https://ui.example"})

	w := preflight(router, "https://ui.example")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example" {
		t.Fatalf("allow-origin = %q, want https://ui.example", got)
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("allow-credentials = %q, want true", got)
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	t.Parallel()

	router := corsServer(t, []string{"https://ui.example"})

	w := preflight(router, "https://evil.example")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin echoed: %q", got)
	}
}

func TestCORS_DisabledByDefault(t *testing.T) {
	t.Parallel()

	router := corsServer(t, nil)

	w := preflight(router, "https://ui.example")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("CORS headers present with no configured origins: %q", got)
	}
}
