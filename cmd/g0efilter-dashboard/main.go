// Package main runs the g0efilter dashboard HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard"
	"github.com/g0lab/g0efilter/internal/logging"
)

const (
	name         = "g0efilter-dashboard"
	licenseYear  = "2025"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultBufferSize = 5000
	defaultReadLimit  = 500
	defaultSERetryMs  = 2000
	defaultRateRPS    = 50.0
	defaultRateBurst  = 100.0
)

// Set by GoReleaser via -ldflags.
var (
	version = ""
	commit  = "" //nolint:gochecknoglobals
	date    = "" //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	if version == "" {
		version = "0.0.0-dev"
	}

	if date == "" {
		date = "unknown"
	}

	if commit == "" {
		commit = "none"
	}
}

// printVersion prints version information to stderr.
func printVersion() {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, short, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

// getenv gets an environment variable with a default value if empty.
func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	return v
}

// getenvInt gets an integer environment variable with a default value if empty or invalid.
func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}

	return i
}

// getenvFloat gets a float environment variable with a default value if empty or invalid.
func getenvFloat(k string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}

	return f
}

// exitCodeError carries a process exit code.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", int(e)) }

// buildConfig builds dashboard configuration from environment variables.
func buildConfig() dashboard.Config {
	return dashboard.Config{
		Addr:         getenv("PORT", ":8081"),
		APIKey:       getenv("API_KEY", ""),
		LogLevel:     getenv("LOG_LEVEL", "INFO"),
		BufferSize:   getenvInt("BUFFER_SIZE", defaultBufferSize),
		ReadLimit:    getenvInt("READ_LIMIT", defaultReadLimit),
		SERetryMs:    getenvInt("SSE_RETRY_MS", defaultSERetryMs),
		RateRPS:      getenvFloat("RATE_RPS", defaultRateRPS),
		RateBurst:    getenvFloat("RATE_BURST", defaultRateBurst),
		WriteTimeout: getenvInt("WRITE_TIMEOUT", 0), // 0 = no timeout for SSE
		Version:      version,
	}
}

// normalizeAddr normalizes the listen address by prefixing with colon if needed.
func normalizeAddr(cfg *dashboard.Config) {
	if cfg.Addr != "" && !strings.Contains(cfg.Addr, ":") {
		_, aerr := strconv.Atoi(cfg.Addr)
		if aerr == nil {
			cfg.Addr = ":" + cfg.Addr
		}
	}
}

// setupLogging creates and configures the logger, validates API key.
func setupLogging(cfg dashboard.Config) (*slog.Logger, error) {
	lg := logging.NewWithContext(context.Background(), cfg.LogLevel, os.Stdout, version)
	slog.SetDefault(lg)

	if cfg.APIKey == "" {
		lg.Error("config.missing_api_key", "msg", "API_KEY is required")

		return nil, exitCodeError(1)
	}

	lg.Info("dashboard.starting",
		"addr", cfg.Addr,
		"buffer_size", cfg.BufferSize,
		"read_limit", cfg.ReadLimit,
		"sse_retry_ms", cfg.SERetryMs,
		"rate_rps", cfg.RateRPS,
		"rate_burst", cfg.RateBurst,
		"write_timeout", cfg.WriteTimeout,
		"version", version,
		"commit", commit,
		"date", date,
	)

	return lg, nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "version", "-V", "-v":
			printVersion()

			return
		}
	}

	cfg := buildConfig()
	normalizeAddr(&cfg)

	lg, err := setupLogging(cfg)
	if err != nil {
		var ec exitCodeError
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling for external shutdown (SIGTERM, SIGINT)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Run dashboard in goroutine
	errCh := make(chan error, 1)

	go func() {
		errCh <- dashboard.Run(ctx, cfg)
	}()

	// Wait for either error or shutdown signal
	select {
	case err = <-errCh:
		cancel() // Ensure context is cancelled before exit

		if err != nil {
			lg.Error("dashboard.failed", "err", err)
			os.Exit(1)
		}
	case sig := <-sigCh:
		lg.Info("shutdown.signal", "signal", sig.String())
		cancel() // Cancel context to stop dashboard

		// Give dashboard time to cleanup
		const shutdownGracePeriod = 3 * time.Second
		lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod)

		select {
		case <-errCh:
			// Dashboard stopped
		case <-time.After(shutdownGracePeriod):
			lg.Warn("shutdown.timeout", "timeout", shutdownGracePeriod)
		}

		// Shutdown logger to flush buffers
		logging.Shutdown(1 * time.Second)
		lg.Info("shutdown.complete")
	}
}
