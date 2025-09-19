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

	"g0filter/internal/dashboard"
	"g0filter/internal/logging"
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

func init() { //nolint:gochecknoinits
	// preserve build-time variables
	if version == "" {
		version = "dev"
	}

	if date == "" {
		date = "unknown"
	}

	if commit == "" {
		commit = "none"
	}
}

func printVersion() {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, short, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	return v
}

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

type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", int(e)) }

func main() {
	err := startMain()
	if err != nil {
		var ec exitCodeError
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startMain() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "version", "-V", "-v":
			printVersion()

			return nil
		}
	}

	cfg := dashboard.Config{
		Addr:       getenv("PORT", ":8081"),
		APIKey:     getenv("API_KEY", ""),
		LogLevel:   getenv("LOG_LEVEL", "INFO"),
		LogFormat:  "json",
		BufferSize: getenvInt("BUFFER_SIZE", defaultBufferSize),
		ReadLimit:  getenvInt("READ_LIMIT", defaultReadLimit),
		SERetryMs:  getenvInt("SSE_RETRY_MS", defaultSERetryMs),
		RateRPS:    getenvFloat("RATE_RPS", defaultRateRPS),
		RateBurst:  getenvFloat("RATE_BURST", defaultRateBurst),
	}

	if cfg.Addr != "" && !strings.Contains(cfg.Addr, ":") {
		_, aerr := strconv.Atoi(cfg.Addr)
		if aerr == nil {
			cfg.Addr = ":" + cfg.Addr
		}
	}

	// Structured logger
	lg := logging.NewWithFormat(cfg.LogLevel, cfg.LogFormat, os.Stdout, false)
	slog.SetDefault(lg)

	if cfg.APIKey == "" {
		lg.Error("config.missing_api_key", "msg", "API_KEY is not set; the dashboard requires API_KEY to run")

		return exitCodeError(1)
	}

	lg.Info("dashboard.starting",
		"addr", cfg.Addr,
		"buffer_size", cfg.BufferSize,
		"read_limit", cfg.ReadLimit,
		"sse_retry_ms", cfg.SERetryMs,
		"rate_rps", cfg.RateRPS,
		"rate_burst", cfg.RateBurst,
		"version", version,
		"commit", commit,
		"date", date,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e := dashboard.Run(ctx, cfg)
	if e != nil {
		lg.Error("dashboard.failed", "err", e)

		return exitCodeError(1)
	}

	return nil
}
