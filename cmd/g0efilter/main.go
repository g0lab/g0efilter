// Package main is the entrypoint for g0efilter.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
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

// exitCodeError carries a process exit code.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", int(e)) }

func main() {
	if handleVersionFlag() {
		return
	}

	config := loadConfig()
	lg := setupLogger(config)

	err := validateMode(config, lg)
	if err != nil {
		var ec exitCodeError
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	domains, _, err := loadAndApplyPolicy(config, lg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()

	startServices(ctx, config, domains, lg)
	startNflogStream(ctx, lg)

	select {}
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
		mode:       strings.ToLower(getenvDefault("FILTER_MODE", "sni")),
	}
}

// setupLogger creates and configures the application logger.
func setupLogger(cfg config) *slog.Logger {
	lg := logging.NewWithContext(context.Background(), cfg.logLevel, "console", os.Stdout, false, version)
	slog.SetDefault(lg)

	logStartupInfo(lg, cfg)
	logDashboardInfo(lg)
	logNotificationInfo(lg)

	return lg
}

// logStartupInfo logs application startup information and configuration.
func logStartupInfo(lg *slog.Logger, cfg config) {
	kv := []any{
		"name", name,
		"policy_path", cfg.policyPath,
		"mode", cfg.mode,
		"log_level", cfg.logLevel,
		"version", version,
		"commit", commit,
	}

	if cfg.logFile != "" {
		kv = append(kv, "log_file", cfg.logFile)
	}

	if cfg.hostname != "" {
		kv = append(kv, "hostname", cfg.hostname)
	}

	lg.Info("startup.info", kv...)

	if cfg.mode == filter.ModeSNI {
		lg.Info("startup.ports", "http_port", cfg.httpPort, "https_port", cfg.httpsPort)
	}

	if cfg.mode == filter.ModeDNS {
		lg.Info("startup.ports", "dns_port", cfg.dnsPort)
	}

	lg.Debug("startup.config",
		"http_port", cfg.httpPort,
		"https_port", cfg.httpsPort,
		"dns_port", cfg.dnsPort,
		"date", date,
	)
}

// logDashboardInfo logs dashboard shipping configuration status.
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

// validateMode validates the filter mode configuration.
func validateMode(cfg config, lg *slog.Logger) error {
	if cfg.mode != filter.ModeSNI && cfg.mode != filter.ModeDNS {
		lg.Error("config.invalid_mode", "filter_mode", cfg.mode)

		return exitCodeError(2)
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

	lg.Info("policy.loaded", "domains_count", len(domains), "ips_count", len(ips))
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
func runServiceWithRetry(serviceName string, lg *slog.Logger, serviceFunc func() error) {
	go func() {
		for {
			err := serviceFunc()
			if err != nil {
				lg.Error(serviceName+".stopped", "err", err, "action", "retrying")
				time.Sleep(retryDelay)
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
	case "sni":
		startSNIServices(ctx, cfg, domains, opts, lg)
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
	lg.Info("dns.starting", "addr", ":"+dnsPort)

	dnsOpts := opts
	dnsOpts.ListenAddr = ":" + dnsPort

	runServiceWithRetry("dns", lg, func() error {
		return filter.Serve53(ctx, domains, dnsOpts)
	})
}

// startSNIServices starts SNI and HTTP filtering services.
func startSNIServices(
	ctx context.Context,
	cfg config,
	domains []string,
	opts filter.Options,
	lg *slog.Logger,
) {
	lg.Info("sni.starting", "addr", ":"+cfg.httpsPort)

	sniOpts := opts
	sniOpts.ListenAddr = ":" + cfg.httpsPort

	runServiceWithRetry("sni", lg, func() error {
		return filter.Serve443(ctx, domains, sniOpts)
	})

	lg.Info("http.starting", "addr", ":"+cfg.httpPort)

	hostOpts := opts
	hostOpts.ListenAddr = ":" + cfg.httpPort

	runServiceWithRetry("http", lg, func() error {
		return filter.Serve80(ctx, domains, hostOpts)
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
