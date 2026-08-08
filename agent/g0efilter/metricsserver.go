package g0efilter

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/g0lab/g0efilter/agent/metrics"
)

const (
	metricsReadTimeout  = 5 * time.Second
	metricsWriteTimeout = 10 * time.Second
	metricsIdleTimeout  = 60 * time.Second
	metricsShutdown     = 5 * time.Second
)

// startMetricsServer exposes /metrics on METRICS_ADDR. A nil registry means metrics
// are disabled, and a failure to listen is never fatal: losing observability must
// not stop the workload from being filtered.
func startMetricsServer(ctx context.Context, registry *metrics.Metrics, lg *slog.Logger) {
	if registry == nil {
		return
	}

	addr := getenvDefault("METRICS_ADDR", "")
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", registry.Handler())

	//nolint:exhaustruct // only the timeouts and handler matter here
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: metricsReadTimeout,
		ReadTimeout:       metricsReadTimeout,
		WriteTimeout:      metricsWriteTimeout,
		IdleTimeout:       metricsIdleTimeout,
	}

	go func() {
		lg.Info("metrics.listen", "addr", addr, "path", "/metrics")

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Warn("metrics.serve_failed", "addr", addr, "err", err)
		}
	}()

	go func() {
		<-ctx.Done()

		// WithoutCancel because the parent is already cancelled; the timeout is what
		// bounds the drain.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metricsShutdown)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
	}()
}
