//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/metrics"
)

func freeAddr(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}

	addr := listener.Addr().String()

	err = listener.Close()
	if err != nil {
		t.Fatalf("release port: %v", err)
	}

	return addr
}

func scrape(t *testing.T, addr string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/metrics", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err //nolint:wrapcheck // the caller only checks reachability
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return string(body), nil
}

func waitForScrape(t *testing.T, addr string) string {
	t.Helper()

	var lastErr error

	for range 100 {
		body, err := scrape(t, addr)
		if err == nil {
			return body
		}

		lastErr = err

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("metrics endpoint never became reachable: %v", lastErr)

	return ""
}

func TestStartMetricsServerServesTheRegistry(t *testing.T) {
	t.Setenv("METRICS_ADDR", "")

	addr := freeAddr(t)
	t.Setenv("METRICS_ADDR", addr)

	registry := metrics.New()
	registry.RecordConnection("https", "BLOCKED")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	startMetricsServer(ctx, registry, slog.New(slog.DiscardHandler))

	body := waitForScrape(t, addr)

	want := `g0efilter_connections_total{component="https",action="BLOCKED"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("scrape missing %q:\n%s", want, body)
	}
}

func TestStartMetricsServerStopsWithTheContext(t *testing.T) {
	addr := freeAddr(t)
	t.Setenv("METRICS_ADDR", addr)

	ctx, cancel := context.WithCancel(t.Context())

	startMetricsServer(ctx, metrics.New(), slog.New(slog.DiscardHandler))
	waitForScrape(t, addr)

	cancel()

	for range 100 {
		_, err := scrape(t, addr)
		if err != nil {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Error("the metrics server was still serving after the context was canceled")
}

// Metrics open a listening port, so they must stay off unless enabled.
func TestStartMetricsServerStaysOffWhenNotConfigured(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		registry *metrics.Metrics
	}{
		{name: "no registry", addr: "127.0.0.1:0", registry: nil},
		{name: "no address", addr: "", registry: metrics.New()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := freeAddr(t)

			configured := tc.addr
			if configured != "" {
				configured = addr
			}

			t.Setenv("METRICS_ADDR", configured)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			startMetricsServer(ctx, tc.registry, slog.New(slog.DiscardHandler))

			time.Sleep(100 * time.Millisecond)

			_, err := scrape(t, addr)
			if err == nil {
				t.Error("a metrics server was started without being configured")
			}
		})
	}
}
