// Package main is the entrypoint for g0efilter.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/g0lab/g0efilter/internal/logging"
	"github.com/g0lab/g0efilter/internal/nftables"
	"github.com/g0lab/g0efilter/internal/policy"
)

const (
	name         = "g0efilter"
	licenseYear  = "2025"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultDialTimeout = 5000
	defaultIdleTimeout = 600000
	retryDelay         = 5 * time.Second
)

var errPortConflict = errors.New("port conflict detected")

// Set by GoReleaser via ldflags.
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

// getGoVersion returns the Go version used to build the binary.
func getGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}

	return "unknown"
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

func main() {
	if handleVersionFlag() {
		return
	}

	config := loadConfig()

	// Create logger without logging startup info yet
	lg := logging.NewWithContext(context.Background(), config.logLevel, os.Stdout, version)
	slog.SetDefault(lg)

	// Normalize mode before logging
	config = normalizeMode(config, lg)

	// Now log startup info with corrected mode
	logStartupInfo(lg, config)
	logDashboardInfo(lg)
	logNotificationInfo(lg)

	// Validate port configuration before proceeding
	err := validatePorts(config, lg)
	if err != nil {
		lg.Error("config.port_validation_failed", "err", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	domains, _, err := loadAndApplyPolicy(config, lg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for external shutdown (SIGTERM, SIGINT)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	startServices(ctx, config, domains, lg)
	startNflogStream(ctx, lg)

	// Log startup complete
	lg.Info("startup.ready", "mode", config.mode, "filter_count", len(domains))

	// Wait for shutdown signal
	sig := <-sigCh
	lg.Info("shutdown.signal", "signal", sig.String())
	cancel() // Cancel context to gracefully stop all services

	// Give services time to cleanup
	const shutdownGracePeriod = 3 * time.Second
	lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod.String())
	time.Sleep(shutdownGracePeriod)

	// Shutdown logger to flush buffers
	logging.Shutdown(1 * time.Second)
	lg.Info("shutdown.complete")
}

func handleVersionFlag() bool {
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "--version" || arg == "version" || arg == "-V" || arg == "-v" {
			printVersion()

			return true
		}
	}

	return false
}

// config holds application configuration from environment variables.
type config struct {
	policyPath string
	httpPort   string
	httpsPort  string
	dnsPort    string
	logLevel   string
	logFile    string
	hostname   string
	mode       string
}

// loadConfig reads configuration from environment variables.
func loadConfig() config {
	return config{
		policyPath: getenvDefault("POLICY_PATH", "/app/policy.yaml"),
		httpPort:   getenvDefault("HTTP_PORT", "8080"),
		httpsPort:  getenvDefault("HTTPS_PORT", "8443"),
		dnsPort:    getenvDefault("DNS_PORT", "53"),
		logLevel:   getenvDefault("LOG_LEVEL", "INFO"),
		logFile:    getenvDefault("LOG_FILE", ""),
		hostname:   getenvDefault("HOSTNAME", ""),
		mode:       strings.ToLower(getenvDefault("FILTER_MODE", "https")),
	}
}

// logStartupInfo logs application startup information and configuration.
func logStartupInfo(lg *slog.Logger, cfg config) {
	// Shorten commit hash for cleaner output
	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = commit[:7]
	}

	// Get nftables version
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	nftVersion, err := nftables.Version(ctx)
	if err != nil {
		nftVersion = "unavailable"

		lg.Debug("startup.nftables_version_error", "error", err.Error())
	}

	kv := []any{
		"name", name,
		"version", version,
		"commit", shortCommit,
		"go_version", getGoVersion(),
		"nft_version", nftVersion,
		"build_date", date,
		"mode", cfg.mode,
		"policy_path", cfg.policyPath,
		"log_level", cfg.logLevel,
	}

	if cfg.hostname != "" {
		kv = append(kv, "hostname", cfg.hostname)
	}

	if cfg.logFile != "" {
		kv = append(kv, "log_file", cfg.logFile)
	}

	lg.Info("startup.info", kv...)

	// Debug-level port info (detailed bind info logged later at INFO level)
	if cfg.mode == filter.ModeHTTPS {
		lg.Debug("startup.ports", "http_port", cfg.httpPort, "https_port", cfg.httpsPort)
	}

	if cfg.mode == filter.ModeDNS {
		lg.Debug("startup.ports", "dns_port", cfg.dnsPort)
	}
}
func logDashboardInfo(lg *slog.Logger) {
	dhost := strings.TrimSpace(getenvDefault("DASHBOARD_HOST", ""))
	if dhost != "" {
		disp := dhost
		if !strings.HasPrefix(disp, "http://") && !strings.HasPrefix(disp, "https://") {
			disp = "http://" + disp
		}

		lg.Info("shipping.enabled", "host", disp)
	} else {
		lg.Info("shipping.disabled")
	}
}

// logNotificationInfo logs notification configuration status.
func logNotificationInfo(lg *slog.Logger) {
	nhost := strings.TrimSpace(getenvDefault("NOTIFICATION_HOST", ""))
	ntoken := strings.TrimSpace(getenvDefault("NOTIFICATION_KEY", ""))

	if nhost != "" && ntoken != "" {
		lg.Info("notifications.enabled", "host", nhost)
	} else {
		lg.Info("notifications.disabled")
	}
}

// normalizeMode validates and normalizes the filter mode configuration.
// If an invalid mode is provided, it logs a warning and defaults to HTTPS mode.
func normalizeMode(cfg config, lg *slog.Logger) config {
	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	validModes := map[string]bool{
		filter.ModeHTTPS: true,
		filter.ModeDNS:   true,
	}

	if !validModes[mode] && mode != "" {
		lg.Warn("filter_mode.invalid", "mode", cfg.mode, "defaulting_to", filter.ModeHTTPS)
		cfg.mode = filter.ModeHTTPS
	} else if mode == "" {
		cfg.mode = filter.ModeHTTPS
	}

	return cfg
}

// validatePorts checks for port conflicts in the configuration.
func validatePorts(cfg config, lg *slog.Logger) error {
	// In HTTPS mode, check HTTP vs HTTPS port conflict
	if cfg.mode == filter.ModeHTTPS {
		if cfg.httpPort == cfg.httpsPort {
			return fmt.Errorf("%w: HTTP_PORT and HTTPS_PORT cannot be the same (%s)",
				errPortConflict, cfg.httpPort)
		}
	}

	// In DNS mode, check DNS port against HTTP/HTTPS ports (though they won't run together)
	if cfg.mode == filter.ModeDNS {
		if cfg.dnsPort == cfg.httpPort {
			lg.Warn("config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTP_PORT", cfg.httpPort,
				"note", "DNS mode active, HTTP port not used")
		}

		if cfg.dnsPort == cfg.httpsPort {
			lg.Warn("config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTPS_PORT", cfg.httpsPort,
				"note", "DNS mode active, HTTPS port not used")
		}
	}

	return nil
}

// loadAndApplyPolicy loads the policy file and applies nftables rules.
func loadAndApplyPolicy(cfg config, lg *slog.Logger) ([]string, []string, error) {
	ips, domains, err := policy.ReadPolicy(cfg.policyPath)
	if err != nil {
		lg.Error("policy.read_error", "path", cfg.policyPath, "err", err)

		return nil, nil, fmt.Errorf("failed to read policy: %w", err)
	}

	lg.Info("policy.loaded", "domain_count", len(domains), "ip_count", len(ips))
	lg.Debug("policy.loaded.details", "domains", domains, "ips", ips)

	err = nftables.ApplyNftRules(ips, cfg.httpsPort, cfg.httpPort, cfg.dnsPort)
	if err != nil {
		lg.Error("nftables.apply_failed", "err", err)

		return nil, nil, fmt.Errorf("apply nftables rules: %w", err)
	}

	lg.Info("nftables.applied")

	return domains, ips, nil
}

// runServiceWithRetry runs a service in a goroutine and restarts it on failure.
// Stops retrying when context is cancelled (e.g., on shutdown signal).
func runServiceWithRetry(ctx context.Context, serviceName string, lg *slog.Logger, serviceFunc func() error) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			default:
				err := serviceFunc()
				if err != nil {
					// Check if we're shutting down
					select {
					case <-ctx.Done():
						lg.Info(serviceName+".shutdown", "reason", "context cancelled")

						return
					default:
						lg.Error(serviceName+".stopped", "err", err, "action", "retrying")
						time.Sleep(retryDelay)
					}
				}
			}
		}
	}()
}

// startServices starts the appropriate filtering services based on mode.
func startServices(
	ctx context.Context,
	cfg config,
	domains []string,
	lg *slog.Logger,
) {
	opts := filter.Options{
		DialTimeout: defaultDialTimeout,
		IdleTimeout: defaultIdleTimeout,
		DropWithRST: true,
		Logger:      lg,
	}

	switch cfg.mode {
	case "dns":
		startDNSService(ctx, cfg.dnsPort, domains, opts, lg)
	case "https":
		startHTTPSServices(ctx, cfg, domains, opts, lg)
	default:
		lg.Warn("filter_mode.invalid", "mode", cfg.mode, "defaulting_to", "https")
		startHTTPSServices(ctx, cfg, domains, opts, lg)
	}
}

// startDNSService starts the DNS filtering service.
func startDNSService(
	ctx context.Context,
	dnsPort string,
	domains []string,
	opts filter.Options,
	lg *slog.Logger,
) {
	lg.Debug("dns.starting", "addr", ":"+dnsPort)

	dnsOpts := opts
	dnsOpts.ListenAddr = ":" + dnsPort

	runServiceWithRetry(ctx, "dns", lg, func() error {
		return filter.Serve53(ctx, domains, dnsOpts)
	})
}

// startHTTPSServices starts HTTPS and HTTP filtering services.
func startHTTPSServices(
	ctx context.Context,
	cfg config,
	domains []string,
	opts filter.Options,
	lg *slog.Logger,
) {
	lg.Debug("https.starting", "addr", ":"+cfg.httpsPort)

	httpsOpts := opts
	httpsOpts.ListenAddr = ":" + cfg.httpsPort

	runServiceWithRetry(ctx, "https", lg, func() error {
		return filter.Serve443(ctx, domains, httpsOpts)
	})

	lg.Debug("http.starting", "addr", ":"+cfg.httpPort)

	httpOpts := opts
	httpOpts.ListenAddr = ":" + cfg.httpPort

	runServiceWithRetry(ctx, "http", lg, func() error {
		return filter.Serve80(ctx, domains, httpOpts)
	})
}

// startNflogStream starts the nflog event stream listener.
func startNflogStream(ctx context.Context, lg *slog.Logger) {
	lg.Info("nflog.listen")

	go func() {
		err := nftables.StreamNfLogWithLogger(ctx, lg)
		if err != nil {
			lg.Warn("nflog.stream_error", "err", err)
		}
	}()
}

// getenvDefault gets an environment variable with a default value if empty.
func getenvDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}

	return v
}
