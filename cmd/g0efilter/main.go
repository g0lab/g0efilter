// Package main is the command-line entrypoint for g0efilter.
// It starts the filters and applies nftables rules according to the configured policy.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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

	modeSNI = "sni"
	modeDNS = "dns"

	defaultDialTimeout = 5000
	defaultIdleTimeout = 600000
)

// set by GoReleaser via ldflags.
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

func printVersion() {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, short, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

// exitCode is a lightweight way to carry a specific process exit code up to main().
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
	if handleVersionFlag() {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config := loadConfig()
	lg := setupLogger(config)

	err := validateAndSetMode(config, lg)
	if err != nil {
		return err
	}

	domains, _, err := loadAndApplyPolicy(config, lg)
	if err != nil {
		return err
	}

	startServices(ctx, config, domains, lg)

	startNflogStream(ctx, lg)

	<-ctx.Done()
	lg.Info("shutdown.graceful")
	logging.Shutdown(5 * time.Second)

	return nil
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

func setupLogger(cfg config) *slog.Logger {
	lg := logging.NewWithContext(context.Background(), cfg.logLevel, "console", os.Stdout, false)
	slog.SetDefault(lg)

	logStartupInfo(lg, cfg)
	logDashboardInfo(lg)
	logNotificationInfo(lg)

	return lg
}

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

	if cfg.mode == modeSNI {
		lg.Info("startup.ports", "http_port", cfg.httpPort, "https_port", cfg.httpsPort)
	}

	if cfg.mode == modeDNS {
		lg.Info("startup.ports", "dns_port", cfg.dnsPort)
	}

	lg.Debug("startup.config",
		"http_port", cfg.httpPort,
		"https_port", cfg.httpsPort,
		"dns_port", cfg.dnsPort,
		"date", date,
	)
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

func logNotificationInfo(lg *slog.Logger) {
	nhost := strings.TrimSpace(getenvDefault("NOTIFICATION_HOST", ""))
	ntoken := strings.TrimSpace(getenvDefault("NOTIFICATION_KEY", ""))

	if nhost != "" && ntoken != "" {
		lg.Info("notifications.enabled", "host", nhost)
	} else {
		lg.Info("notifications.disabled")
	}
}

func validateAndSetMode(cfg config, lg *slog.Logger) error {
	if cfg.mode != modeSNI && cfg.mode != "dns" {
		lg.Error("config.invalid_mode", "filter_mode", cfg.mode)

		return exitCodeError(2)
	}

	err := os.Setenv("FILTER_MODE", cfg.mode)
	if err != nil {
		lg.Warn("env.set_failed", "key", "FILTER_MODE", "err", err)
	}

	return nil
}

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

	go func() {
		for {
			// Check if context is cancelled before attempting to start
			select {
			case <-ctx.Done():
				lg.Info("dns.shutdown", "reason", "context_cancelled")

				return
			default:
			}

			err := filter.Serve53(ctx, domains, dnsOpts)
			if err != nil {
				// Check if this is a context cancellation (normal shutdown)
				select {
				case <-ctx.Done():
					lg.Info("dns.shutdown", "reason", "context_cancelled")

					return
				default:
					// Log error and retry after delay
					lg.Error("dns.stopped", "err", err, "action", "retrying")
					time.Sleep(5 * time.Second)
				}
			}
		}
	}()
}

//nolint:cyclop,funlen // Complexity and length from retry loops and context handling is acceptable
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

	go func() {
		for {
			// Check if context is cancelled before attempting to start
			select {
			case <-ctx.Done():
				lg.Info("sni.shutdown", "reason", "context_cancelled")

				return
			default:
			}

			err := filter.Serve443(ctx, domains, sniOpts)
			if err != nil {
				// Check if this is a context cancellation (normal shutdown)
				select {
				case <-ctx.Done():
					lg.Info("sni.shutdown", "reason", "context_cancelled")

					return
				default:
					// Log error and retry after delay
					lg.Error("sni.stopped", "err", err, "action", "retrying")
					time.Sleep(5 * time.Second)
				}
			}
		}
	}()

	lg.Info("http.starting", "addr", ":"+cfg.httpPort)

	hostOpts := opts
	hostOpts.ListenAddr = ":" + cfg.httpPort

	go func() {
		for {
			// Check if context is cancelled before attempting to start
			select {
			case <-ctx.Done():
				lg.Info("http.shutdown", "reason", "context_cancelled")

				return
			default:
			}

			err := filter.Serve80(ctx, domains, hostOpts)
			if err != nil {
				// Check if this is a context cancellation (normal shutdown)
				select {
				case <-ctx.Done():
					lg.Info("http.shutdown", "reason", "context_cancelled")

					return
				default:
					// Log error and retry after delay
					lg.Error("http.stopped", "err", err, "action", "retrying")
					time.Sleep(5 * time.Second)
				}
			}
		}
	}()
}

func startNflogStream(ctx context.Context, lg *slog.Logger) {
	lg.Info("nflog.listen")

	go func() {
		err := nftables.StreamNfLogWithLogger(ctx, lg)
		if err != nil {
			lg.Warn("nflog.stream_error", "err", err)
		}
	}()
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}
