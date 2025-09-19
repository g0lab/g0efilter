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

	"g0filter/internal/filter"
	"g0filter/internal/logging"
	"g0filter/internal/nftables"
	"g0filter/internal/policy"
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

//nolint:cyclop,funlen
func startMain() error {
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "--version" || arg == "version" || arg == "-V" || arg == "-v" {
			printVersion()

			return nil
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	policyPath := getenvDefault("POLICY_PATH", "/app/policy.yaml")
	httpPort := getenvDefault("HTTP_PORT", "8080")
	httpsPort := getenvDefault("HTTPS_PORT", "8443")
	dnsPort := getenvDefault("DNS_PORT", "53")
	logLevel := getenvDefault("LOG_LEVEL", "INFO")
	logFile := getenvDefault("LOG_FILE", "")
	hostname := getenvDefault("HOSTNAME", "")
	mode := strings.ToLower(getenvDefault("FILTER_MODE", "sni")) // "sni" or "dns"

	var err error

	// Structured logger
	lg := logging.NewWithFormat(logLevel, "console", os.Stdout, false)
	slog.SetDefault(lg)

	// Startup info
	kv := []any{"name", name, "policy_path", policyPath}

	kv = append(kv, "mode", mode, "log_level", logLevel, "version", version, "commit", commit)

	if logFile != "" {
		kv = append(kv, "log_file", logFile)
	}

	if hostname != "" {
		kv = append(kv, "hostname", hostname)
	}

	lg.Info("startup.info", kv...)

	if mode == modeSNI {
		lg.Info("startup.ports", "http_port", httpPort, "https_port", httpsPort)
	}

	if mode == modeDNS {
		lg.Info("startup.ports", "dns_port", dnsPort)
	}

	// Dashboard shipping info
	dhost := strings.TrimSpace(getenvDefault("DASHBOARD_HOST", ""))
	if dhost != "" {
		// normalise display of host
		disp := dhost
		if !strings.HasPrefix(disp, "http://") && !strings.HasPrefix(disp, "https://") {
			disp = "http://" + disp
		}

		lg.Info("shipping.enabled", "host", disp)
	} else {
		lg.Info("shipping.disabled")
	}

	if mode != modeSNI && mode != "dns" {
		lg.Error("config.invalid_mode", "filter_mode", mode)

		return exitCodeError(2)
	}

	err = os.Setenv("FILTER_MODE", mode)
	if err != nil {
		lg.Warn("env.set_failed", "key", "FILTER_MODE", "err", err)
	}

	lg.Debug("startup.config",
		"http_port", httpPort,
		"https_port", httpsPort,
		"dns_port", dnsPort,
		"date", date,
	)

	// Load policy
	ips, domains, err := policy.ReadPolicy(policyPath)
	if err != nil {
		lg.Error("policy.read_error", "path", policyPath, "err", err)

		return fmt.Errorf("failed to read policy: %w", err)
	}

	// Policy loaded — keep INFO quiet and DEBUG verbose
	lg.Info("policy.loaded",
		"domains_count", len(domains),
		"ips_count", len(ips),
	)
	lg.Debug("policy.loaded.details", "domains", domains, "ips", ips)

	// Apply nftables with configured ports
	err = nftables.ApplyNftRules(ips, httpsPort, httpPort, dnsPort)
	if err != nil {
		lg.Error("nftables.apply_failed", "err", err)

		return fmt.Errorf("apply nftables rules: %w", err)
	}

	lg.Info("nftables.applied")

	// Shared options for filters
	opts := filter.Options{
		DialTimeout: defaultDialTimeout,
		IdleTimeout: defaultIdleTimeout,
		DropWithRST: true,
		Logger:      lg,
	}

	switch mode {
	case "dns":
		lg.Info("dns.starting", "addr", ":"+dnsPort)

		dnsOpts := opts
		dnsOpts.ListenAddr = ":" + dnsPort

		go func() {
			e := filter.Serve53(ctx, domains, dnsOpts)
			if e != nil {
				lg.Error("dns.stopped", "err", e)
				// stop cancels the context; realMain will proceed to shutdown.
				stop()
			}
		}()
	case "sni":
		lg.Info("sni.starting", "addr", ":"+httpsPort)

		sniOpts := opts
		sniOpts.ListenAddr = ":" + httpsPort

		go func() {
			e := filter.Serve443(ctx, domains, sniOpts)
			if e != nil {
				lg.Error("sni.stopped", "err", e)
				stop()
			}
		}()

		lg.Info("http.starting", "addr", ":"+httpPort)

		hostOpts := opts
		hostOpts.ListenAddr = ":" + httpPort

		go func() {
			e := filter.Serve80(ctx, domains, hostOpts)
			if e != nil {
				lg.Error("http.stopped", "err", e)
				stop()
			}
		}()
	}

	lg.Info("nflog.listen")

	go func() {
		e := nftables.StreamNfLogWithLogger(ctx, lg)
		if e != nil {
			lg.Warn("nflog.stream_error", "err", e)
		}
	}()

	<-ctx.Done()
	lg.Info("shutdown.graceful")
	// Flush poster (wait up to 5s)
	logging.Shutdown(5 * time.Second)

	return nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}
