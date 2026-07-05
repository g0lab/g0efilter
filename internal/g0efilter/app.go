// Package g0efilter contains the g0efilter application wiring and run loop.
package g0efilter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/actions"
	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/g0lab/g0efilter/internal/logging"
	"github.com/g0lab/g0efilter/internal/nftables"
	"github.com/g0lab/g0efilter/internal/policy"
	"github.com/g0lab/g0efilter/internal/procinfo"
	"golang.org/x/sys/unix"
)

const (
	name         = "g0efilter"
	licenseYear  = "2026"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultDialTimeout = 5000
	defaultIdleTimeout = 600000
	retryDelay         = 5 * time.Second

	policyPollInterval = 5 * time.Second

	// fallbackPolicyPath is the directory-mount convention used by the compose examples.
	fallbackPolicyPath = "/app/policy/policy.yaml"
)

var (
	errPortConflict         = errors.New("port conflict detected")
	errPolicyPathEmpty      = errors.New("policy path is empty")
	errUnknownUnblockType   = errors.New("unknown unblock type")
	errAckFailed            = errors.New("unblock acknowledgment failed")
	errUnexpectedHTTPStatus = errors.New("unexpected HTTP status")
	errInodeLinked          = errors.New("inode still linked")
)

type policyUpdate struct {
	hash string
	pol  *policy.Policy
}

// Run starts the g0efilter application and blocks until shutdown.
func Run(version, date, commit string) error {
	cfg := loadConfig()

	lg := logging.NewWithContext(context.Background(), cfg.logLevel, os.Stdout, version)
	slog.SetDefault(lg)

	cfg = normalizeMode(cfg, lg)
	cfg = resolvePolicyPath(cfg, fallbackPolicyPath, lg)

	logStartupInfo(lg, cfg, version, date, commit)
	logDashboardInfo(lg, cfg)
	logNotificationInfo(lg, cfg)

	err := validatePorts(cfg, lg)
	if err != nil {
		lg.Error("config.port_validation_failed", "err", err)

		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, os.Interrupt, unix.SIGTERM)
	defer signal.Stop(sigCh)

	cfg = setupLearning(ctx, cfg, lg)
	cfg = setupProcInfo(cfg, lg)

	pol, initialHash, err := loadInitialPolicy(ctx, cfg, lg)
	if err != nil {
		return err
	}

	svcCancel := startServiceGroup(ctx, cfg, pol, lg)

	defer func() {
		if svcCancel != nil {
			svcCancel()
		}
	}()

	startNflogStream(ctx, lg)

	reloadCh := make(chan policyUpdate, 1)

	lg.Info("policy.watcher_started", "path", cfg.policyPath, "interval", policyPollInterval.String())

	go pollPolicyChanges(ctx, cfg, lg, initialHash, policyPollInterval, reloadCh)

	startRemoteUnblockPolling(ctx, cfg, lg)

	lg.Info("startup.ready", "mode", cfg.mode, "filter_count", len(pol.AllowDomains))

	supervise(ctx, cancel, sigCh, reloadCh, cfg, lg, &svcCancel)
	shutdownGracefully(lg)

	return nil
}

// HandleVersionFlag prints version info and returns true if the process should exit.
func HandleVersionFlag(args []string, version, date, commit string) bool {
	if len(args) > 1 {
		arg := args[1]
		if arg == "--version" || arg == "version" || arg == "-V" || arg == "-v" {
			printVersion(version, date, commit)

			return true
		}
	}

	return false
}

type config struct {
	policyPath          string
	httpPort            string
	httpsPort           string
	dnsPort             string
	logLevel            string
	logFile             string
	hostname            string
	mode                string
	defaultAction       string // bootstrap default; policy file default_action wins
	learningMode        bool
	learner             *learner
	auditMode           bool
	dnsHardening        bool
	dnsRateQPS          int
	dnsRateBurst        int
	procInfo            *procinfo.ProcProvider
	enableRemoteUnblock bool
	dashboardHost       string
	dashboardAPIKey     string
	unblockPollInterval time.Duration
	notificationHost    string
	notificationKey     string
}

func loadConfig() config {
	//nolint:exhaustruct // learner is wired up in Run when learning mode is enabled
	return config{
		policyPath:          getenvDefault("POLICY_PATH", "/app/policy.yaml"),
		httpPort:            getenvDefault("HTTP_PORT", "8080"),
		httpsPort:           getenvDefault("HTTPS_PORT", "8443"),
		dnsPort:             getenvDefault("DNS_PORT", "53"),
		logLevel:            getenvDefault("LOG_LEVEL", "INFO"),
		logFile:             getenvDefault("LOG_FILE", ""),
		hostname:            getenvDefault("HOSTNAME", ""),
		mode:                strings.ToLower(getenvDefault("FILTER_MODE", "https")),
		defaultAction:       strings.ToLower(getenvDefault("DEFAULT_ACTION", policy.DefaultActionDeny)),
		learningMode:        strings.EqualFold(getenvDefault("LEARNING_MODE", "false"), "true"),
		auditMode:           strings.EqualFold(getenvDefault("ENFORCE", "block"), "audit"),
		dnsHardening:        strings.EqualFold(getenvDefault("DNS_HARDENING", "true"), "true"),
		dnsRateQPS:          parseIntDefault(getenvDefault("DNS_RATE_QPS", ""), 0),
		dnsRateBurst:        parseIntDefault(getenvDefault("DNS_RATE_BURST", ""), 0),
		enableRemoteUnblock: strings.EqualFold(getenvDefault("ENABLE_REMOTE_UNBLOCK", "false"), "true"),
		dashboardHost:       strings.TrimSpace(getenvDefault("DASHBOARD_HOST", "")),
		dashboardAPIKey:     strings.TrimSpace(getenvDefault("DASHBOARD_API_KEY", "")),
		unblockPollInterval: parseDurationDefault(getenvDefault("UNBLOCK_POLL_INTERVAL", "10s"), 10*time.Second),
		notificationHost:    strings.TrimSpace(getenvDefault("NOTIFICATION_HOST", "")),
		notificationKey:     strings.TrimSpace(getenvDefault("NOTIFICATION_KEY", "")),
	}
}

// resolvePolicyPath applies the policy-file location fallback: an explicit
// POLICY_PATH always wins (even if missing), then the default location, then
// fallbackPath. A missing file is never auto-created - startup stays fail-closed.
func resolvePolicyPath(cfg config, fallbackPath string, lg *slog.Logger) config {
	if strings.TrimSpace(os.Getenv("POLICY_PATH")) != "" {
		return cfg
	}

	defaultExists := fileExists(cfg.policyPath)
	fallbackExists := fileExists(fallbackPath)

	switch {
	case defaultExists && fallbackExists:
		lg.Warn("policy.path_ambiguous",
			"chosen", cfg.policyPath,
			"ignored", fallbackPath,
			"hint", "both conventional locations exist; set POLICY_PATH to choose explicitly")
	case fallbackExists:
		lg.Info("policy.path_fallback",
			"path", fallbackPath,
			"reason", cfg.policyPath+" not found; using the directory-mount convention")

		cfg.policyPath = fallbackPath
	case !defaultExists:
		lg.Warn("policy.path_missing",
			"probed", cfg.policyPath+", "+fallbackPath,
			"hint", "mount a policy file or set POLICY_PATH; the file is not auto-created")
	}

	return cfg
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)

	return err == nil && st.Mode().IsRegular()
}

// setupLearning wires up the learner and starts its flush loop when learning mode is on.
func setupLearning(ctx context.Context, cfg config, lg *slog.Logger) config {
	if !cfg.learningMode {
		return cfg
	}

	cfg.learner = newLearner(cfg.policyPath, lg)

	go cfg.learner.run(ctx)

	lg.Info("learning_mode.enabled",
		"note", "no traffic will be blocked; observed domains/IPs are appended to the policy file",
		"path", cfg.policyPath,
	)

	return cfg
}

// effectiveDefaultAllow resolves the policy stance: the policy file's default_action
// wins over the DEFAULT_ACTION env var, which defaults to deny.
func effectiveDefaultAllow(cfg config, pol *policy.Policy) bool {
	action := cfg.defaultAction
	if pol != nil && pol.DefaultAction != "" {
		action = pol.DefaultAction
	}

	return action == policy.DefaultActionAllow
}

func supervise(
	ctx context.Context,
	cancel context.CancelFunc,
	sigCh <-chan os.Signal,
	reloadCh <-chan policyUpdate,
	cfg config,
	lg *slog.Logger,
	svcCancel *context.CancelFunc,
) {
	for {
		select {
		case sig := <-sigCh:
			lg.Info("shutdown.signal", "signal", sig.String())
			cancel()
			stopServices(svcCancel)

			return

		case upd := <-reloadCh:
			if ctx.Err() != nil {
				stopServices(svcCancel)

				return
			}

			lg.Info(
				"policy.reloaded",
				"hash", upd.hash,
				"domain_count", len(upd.pol.AllowDomains),
				"ip_count", len(upd.pol.AllowIPs),
				"deny_domain_count", len(upd.pol.DenyDomains),
				"deny_ip_count", len(upd.pol.DenyIPs),
			)

			restartServices(ctx, cfg, upd.pol, lg, svcCancel)
			lg.Info("policy.applied", "mode", cfg.mode, "filter_count", len(upd.pol.AllowDomains))

		case <-ctx.Done():
			stopServices(svcCancel)

			return
		}
	}
}

func startServiceGroup(ctx context.Context, cfg config, pol *policy.Policy, lg *slog.Logger) context.CancelFunc {
	svcCtx, cancel := context.WithCancel(ctx)
	startServices(svcCtx, cfg, pol, lg)

	return cancel
}

func stopServices(svcCancel *context.CancelFunc) {
	if svcCancel == nil || *svcCancel == nil {
		return
	}

	(*svcCancel)()
}

func restartServices(
	ctx context.Context,
	cfg config,
	pol *policy.Policy,
	lg *slog.Logger,
	svcCancel *context.CancelFunc,
) {
	stopServices(svcCancel)
	*svcCancel = startServiceGroup(ctx, cfg, pol, lg)
}

func shutdownGracefully(lg *slog.Logger) {
	const shutdownGracePeriod = 3 * time.Second
	lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod.String())
	time.Sleep(shutdownGracePeriod)

	lg.Info("shutdown.complete")
	logging.Shutdown(1 * time.Second)
}

func loadInitialPolicy(ctx context.Context, cfg config, lg *slog.Logger) (*policy.Policy, string, error) {
	pol, err := loadAndApplyPolicy(ctx, cfg, lg)
	if err != nil {
		return nil, "", err
	}

	hash, err := fileSHA256Hex(cfg.policyPath)
	if err != nil {
		lg.Warn("policy.hash_read_failed", "path", cfg.policyPath, "err", err)

		return pol, "", nil
	}

	return pol, hash, nil
}

func getGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}

	return "unknown"
}

func printVersion(version, date, commit string) {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	_, _ = fmt.Fprintf(os.Stdout, "%s v%s %s (%s)\n", name, version, short, date)
	_, _ = fmt.Fprintf(os.Stdout, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(os.Stdout, "Licensed under the %s license\n", licenseType)
}

func logStartupInfo(lg *slog.Logger, cfg config, version, date, commit string) {
	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = commit[:7]
	}

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
		"default_action", cfg.defaultAction,
		"learning_mode", cfg.learningMode,
		"enforce", enforceLabel(cfg.auditMode),
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

	if cfg.mode == actions.ModeHTTPS {
		lg.Debug("startup.ports", "http_port", cfg.httpPort, "https_port", cfg.httpsPort)
	}

	if isDNSMode(cfg.mode) {
		lg.Debug("startup.ports", "dns_port", cfg.dnsPort)
	}
}

func logDashboardInfo(lg *slog.Logger, cfg config) {
	if cfg.dashboardHost == "" {
		lg.Info("dashboard.logging_disabled")

		return
	}

	disp := cfg.dashboardHost
	if !strings.HasPrefix(disp, "http://") && !strings.HasPrefix(disp, "https://") {
		disp = "http://" + disp
	}

	lg.Info("dashboard.logging_enabled", "host", disp)
}

func logNotificationInfo(lg *slog.Logger, cfg config) {
	if cfg.notificationHost != "" && cfg.notificationKey != "" {
		lg.Info("notifications.enabled", "host", cfg.notificationHost)

		return
	}

	lg.Info("notifications.disabled")
}

func normalizeMode(cfg config, lg *slog.Logger) config {
	switch cfg.defaultAction {
	case policy.DefaultActionDeny, policy.DefaultActionAllow:
	default:
		lg.Warn("default_action.invalid", "default_action", cfg.defaultAction, "defaulting_to", policy.DefaultActionDeny)
		cfg.defaultAction = policy.DefaultActionDeny
	}

	switch cfg.mode {
	case actions.ModeHTTPS, actions.ModeDNS, actions.ModeDNSStrict:
		return cfg
	case "":
		cfg.mode = actions.ModeHTTPS

		return cfg
	default:
		lg.Warn("filter_mode.invalid", "mode", cfg.mode, "defaulting_to", actions.ModeHTTPS)
		cfg.mode = actions.ModeHTTPS

		return cfg
	}
}

// isDNSMode reports whether the mode runs the DNS proxy (plain or strict).
func isDNSMode(mode string) bool {
	return mode == actions.ModeDNS || mode == actions.ModeDNSStrict
}

func enforceLabel(audit bool) string {
	if audit {
		return "audit"
	}

	return "block"
}

// setupProcInfo enables /proc-based process attribution when PROCESS_INFO=true.
func setupProcInfo(cfg config, lg *slog.Logger) config {
	if !strings.EqualFold(getenvDefault("PROCESS_INFO", "false"), "true") {
		return cfg
	}

	cfg.procInfo = procinfo.New()

	lg.Info("process_info.enabled",
		"note", "flow logs carry pid/process attribution; requires a shared PID namespace with clients")

	return cfg
}

func validatePorts(cfg config, lg *slog.Logger) error {
	if cfg.mode == actions.ModeHTTPS && cfg.httpPort == cfg.httpsPort {
		return fmt.Errorf("%w: HTTP_PORT and HTTPS_PORT cannot be the same (%s)", errPortConflict, cfg.httpPort)
	}

	if isDNSMode(cfg.mode) {
		if cfg.dnsPort == cfg.httpPort {
			lg.Warn(
				"config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTP_PORT", cfg.httpPort,
				"note", "DNS mode active, HTTP port not used",
			)
		}

		if cfg.dnsPort == cfg.httpsPort {
			lg.Warn(
				"config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTPS_PORT", cfg.httpsPort,
				"note", "DNS mode active, HTTPS port not used",
			)
		}
	}

	return nil
}

func loadAndApplyPolicy(ctx context.Context, cfg config, lg *slog.Logger) (*policy.Policy, error) {
	pol, err := policy.Read(cfg.policyPath)
	if err != nil {
		lg.Error("policy.read_error", "path", cfg.policyPath, "err", err)

		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	defaultAllow := effectiveDefaultAllow(cfg, pol)

	lg.Info("policy.loaded",
		"default_allow", defaultAllow,
		"domain_count", len(pol.AllowDomains),
		"ip_count", len(pol.AllowIPs),
		"deny_domain_count", len(pol.DenyDomains),
		"deny_ip_count", len(pol.DenyIPs),
	)
	lg.Debug("policy.loaded.details",
		"domains", pol.AllowDomains, "ips", pol.AllowIPs,
		"deny_domains", pol.DenyDomains, "deny_ips", pol.DenyIPs,
	)

	if !defaultAllow && !cfg.learningMode && (len(pol.DenyIPs) > 0 || len(pol.DenyDomains) > 0) {
		lg.Warn("policy.denylist_ignored",
			"reason", "default_action is deny; denylist only applies with default_action: allow")
	}

	rules := nftables.PolicyRules{
		AllowIPs:     pol.AllowIPs,
		DenyIPs:      pol.DenyIPs,
		DefaultAllow: defaultAllow,
		Audit:        cfg.auditMode,
	}

	// Learning mode must never block: force a permissive ruleset with no IP denies.
	if cfg.learningMode {
		rules.DefaultAllow = true
		rules.DenyIPs = nil
	}

	err = nftables.ApplyPolicyRulesWithContext(ctx, rules, cfg.httpsPort, cfg.httpPort, cfg.dnsPort)
	if err != nil {
		lg.Error("nftables.apply_failed", "err", err)

		return nil, fmt.Errorf("apply nftables rules: %w", err)
	}

	lg.Info("nftables.applied")

	return pol, nil
}

func runServiceWithRetry(ctx context.Context, serviceName string, lg *slog.Logger, serviceFunc func() error) {
	go func() {
		for {
			if ctx.Err() != nil {
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			}

			err := serviceFunc()
			if err == nil {
				continue
			}

			if ctx.Err() != nil {
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			}

			lg.Error(serviceName+".stopped", "err", err, "action", "retrying")

			select {
			case <-ctx.Done():
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			case <-time.After(retryDelay):
			}
		}
	}()
}

func startServices(ctx context.Context, cfg config, pol *policy.Policy, lg *slog.Logger) {
	//nolint:exhaustruct
	opts := filter.Options{
		DialTimeout:  defaultDialTimeout,
		IdleTimeout:  defaultIdleTimeout,
		DropWithRST:  true,
		Logger:       lg,
		DefaultAllow: effectiveDefaultAllow(cfg, pol),
		Denylist:     pol.DenyDomains,
		LearningMode: cfg.learningMode,
		OnLearn:      learnFunc(cfg.learner),
		AuditMode:    cfg.auditMode,
		DNSHardening: cfg.dnsHardening,
		DNSRateQPS:   cfg.dnsRateQPS,
		DNSRateBurst: cfg.dnsRateBurst,
	}

	// Assign conditionally: wrapping a nil pointer would make the interface non-nil
	if cfg.procInfo != nil {
		opts.ProcInfo = cfg.procInfo
	}

	if cfg.mode == actions.ModeDNSStrict {
		opts.OnResolved = strictResolvedHook(ctx, opts, lg)
	}

	if isDNSMode(cfg.mode) {
		startDNSService(ctx, cfg.dnsPort, pol.AllowDomains, opts, lg)

		return
	}

	startHTTPSServices(ctx, cfg, pol.AllowDomains, opts, lg)
}

// strictResolvedHook returns the dns-strict callback that pushes resolved IPs into
// the kernel timeout set. Under default-allow or learning mode the ruleset is
// permissive, so strict enforcement degrades to plain DNS mode with a warning.
func strictResolvedHook(
	ctx context.Context,
	opts filter.Options,
	lg *slog.Logger,
) func(ips []string, ttl uint32) {
	if opts.DefaultAllow || opts.LearningMode {
		lg.Warn("dns_strict.degraded",
			"reason", "default_action=allow or learning mode active; connection-time enforcement disabled",
			"behaves_as", actions.ModeDNS,
		)

		return nil
	}

	return func(ips []string, ttl uint32) {
		err := nftables.AddResolvedIPs(ctx, ips, time.Duration(ttl)*time.Second)
		if err != nil {
			lg.Warn("dns_strict.set_update_failed", "ips", ips, "err", err)
		}
	}
}

func startDNSService(ctx context.Context, dnsPort string, domains []string, opts filter.Options, lg *slog.Logger) {
	lg.Debug("dns.starting", "addr", ":"+dnsPort)

	dnsOpts := opts
	dnsOpts.ListenAddr = ":" + dnsPort

	runServiceWithRetry(ctx, "dns", lg, func() error {
		return filter.Serve53(ctx, domains, dnsOpts)
	})
}

func startHTTPSServices(ctx context.Context, cfg config, domains []string, opts filter.Options, lg *slog.Logger) {
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

func startNflogStream(ctx context.Context, lg *slog.Logger) {
	lg.Info("nflog.listen")

	go func() {
		err := nftables.StreamNfLogWithLogger(ctx, lg)
		if err != nil {
			lg.Warn("nflog.stream_error", "err", err)
		}
	}()
}

func startRemoteUnblockPolling(ctx context.Context, cfg config, lg *slog.Logger) {
	if !cfg.enableRemoteUnblock {
		lg.Debug("remote_unblock.disabled", "reason", "ENABLE_REMOTE_UNBLOCK=false")

		return
	}

	if cfg.dashboardHost == "" || cfg.dashboardAPIKey == "" {
		lg.Warn("remote_unblock.disabled", "reason", "missing DASHBOARD_HOST or DASHBOARD_API_KEY")

		return
	}

	lg.Info("remote_unblock.enabled",
		"dashboard", cfg.dashboardHost,
		"poll_interval", cfg.unblockPollInterval.String(),
	)

	go pollRemoteUnblocks(ctx, cfg, lg)
}

func pollPolicyChanges(
	ctx context.Context,
	cfg config,
	lg *slog.Logger,
	initialHash string,
	interval time.Duration,
	reloadCh chan policyUpdate,
) {
	lastHash := initialHash

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-t.C:
			lastHash = checkPolicyTick(ctx, cfg, lg, lastHash, reloadCh)
		}
	}
}

// checkPolicyTick runs one poll iteration: hashes the policy file, warns on a
// stale bind-mount inode, and triggers a reload when the content has changed.
// It returns the updated lastHash value.
func checkPolicyTick(
	ctx context.Context,
	cfg config,
	lg *slog.Logger,
	lastHash string,
	reloadCh chan policyUpdate,
) string {
	newHash, err := fileSHA256Hex(cfg.policyPath)
	if err != nil {
		lg.Warn("policy.hash_read_failed", "path", cfg.policyPath, "err", err)

		return lastHash
	}

	// Detect stale single-file bind-mount: editors that use atomic save
	// (write + rename) leave the container's bind-mount pointing at an
	// unlinked inode (nlink == 0). The path still resolves inside the
	// container but only returns the old content, so the hash never
	// changes and no reload fires. Fix: mount the parent directory.
	unlinkErr := isInodeUnlinked(cfg.policyPath)
	if unlinkErr == nil {
		lg.Warn("policy.stale_inode",
			"path", cfg.policyPath,
			"hint", "inode is unlinked (nlink=0); live reload is broken. "+
				"Mount a directory instead of a single file: './policy/:/app/policy/' (see README)")
	}

	if lastHash == "" {
		return newHash
	}

	if newHash == lastHash {
		return lastHash
	}

	lg.Info("policy.change_detected", "old_hash", lastHash, "new_hash", newHash)

	pol, err := loadAndApplyPolicy(ctx, cfg, lg)
	if err != nil {
		lg.Error("policy.reload_failed", "err", err)

		return lastHash
	}

	sendLatest(ctx, reloadCh, policyUpdate{hash: newHash, pol: pol})

	return newHash
}

// sendLatest sends the most recent policy update to reloadCh, dropping any
// stale update already buffered ("drop oldest, push newest") so the consumer
// always sees the latest version.
func sendLatest(ctx context.Context, reloadCh chan policyUpdate, upd policyUpdate) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Fast path: channel is empty, send directly.
	select {
	case reloadCh <- upd:
		return
	default:
	}

	select {
	case <-ctx.Done():
		return
	case <-reloadCh:
	default:
	}

	select {
	case <-ctx.Done():
		return
	case reloadCh <- upd:
	}
}

// isInodeUnlinked returns nil if the file at path has an nlink count of zero,
// meaning its inode has been unlinked (e.g. by an atomic-save editor) while a
// Docker single-file bind-mount still holds a reference to the old inode.
// Returns a non-nil error if lstat fails or if nlink is non-zero.
func isInodeUnlinked(path string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))

	var st unix.Stat_t

	err := unix.Lstat(cleanPath, &st)
	if err != nil {
		return fmt.Errorf("lstat %q: %w", cleanPath, err)
	}

	if st.Nlink != 0 {
		return errInodeLinked
	}

	return nil
}

func fileSHA256Hex(path string) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return "", errPolicyPathEmpty
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", cleanPath, err)
	}

	h := sha256.New()

	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()

	if copyErr != nil {
		if closeErr != nil {
			return "", fmt.Errorf("read %q: %w (close error: %w)", cleanPath, copyErr, closeErr)
		}

		return "", fmt.Errorf("read %q: %w", cleanPath, copyErr)
	}

	if closeErr != nil {
		return "", fmt.Errorf("close %q: %w", cleanPath, closeErr)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func getenvDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}

	return v
}

func parseIntDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}

	return n
}

func parseDurationDefault(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}

	return d
}

// pollRemoteUnblocks polls the dashboard for pending unblock requests and applies them to the policy.
func pollRemoteUnblocks(
	ctx context.Context,
	cfg config,
	lg *slog.Logger,
) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	baseURL := cfg.dashboardHost
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	t := time.NewTicker(cfg.unblockPollInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			processRemoteUnblocks(ctx, client, baseURL, cfg, lg)
		}
	}
}

// unblockResponse represents the API response from /api/v1/unblocks.
type unblockResponse struct {
	Pending []unblockRequest `json:"pending"`
}

// unblockRequest represents a single unblock request from the dashboard.
type unblockRequest struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func processRemoteUnblocks(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	cfg config,
	lg *slog.Logger,
) {
	unblocks, err := fetchPendingUnblocks(ctx, client, baseURL, cfg, lg)
	if err != nil {
		lg.Warn("remote_unblock.fetch_failed", "err", err)

		return
	}

	if len(unblocks) == 0 {
		return
	}

	lg.Debug("remote_unblock.pending", "count", len(unblocks))

	// Process each unblock request
	// The file watcher will detect the policy file change and trigger a reload
	processUnblockBatch(ctx, client, baseURL, cfg, lg, unblocks)
}

func fetchPendingUnblocks(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	cfg config,
	lg *slog.Logger,
) ([]unblockRequest, error) {
	endpoint := baseURL + "/api/v1/unblocks"
	if cfg.hostname != "" {
		endpoint += "?hostname=" + url.QueryEscape(cfg.hostname)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Api-Key", cfg.dashboardAPIKey)

	lg.Log(ctx, logging.LevelTrace, "remote_unblock.request",
		"method", req.Method,
		"url", endpoint,
		"has_api_key", cfg.dashboardAPIKey != "",
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		lg.Log(ctx, logging.LevelTrace, "remote_unblock.response",
			"status", resp.StatusCode,
			"url", endpoint,
		)

		return nil, fmt.Errorf("%w: %d", errUnexpectedHTTPStatus, resp.StatusCode)
	}

	var unblocks unblockResponse

	err = json.NewDecoder(resp.Body).Decode(&unblocks)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return unblocks.Pending, nil
}

func processUnblockBatch(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	cfg config,
	lg *slog.Logger,
	unblocks []unblockRequest,
) {
	for _, ub := range unblocks {
		err := applyUnblock(cfg.policyPath, ub, lg)
		if err != nil {
			lg.Error("remote_unblock.apply_failed",
				"id", ub.ID,
				"type", ub.Type,
				"value", ub.Value,
				"err", err,
			)

			continue
		}

		// Acknowledge the unblock
		err = acknowledgeUnblock(ctx, client, baseURL, cfg.dashboardAPIKey, ub.ID)
		if err != nil {
			lg.Warn("remote_unblock.ack_failed", "id", ub.ID, "err", err)
		} else {
			lg.Info("remote_unblock.applied",
				"id", ub.ID,
				"type", ub.Type,
				"value", ub.Value,
			)
		}
	}
}

func applyUnblock(policyPath string, ub unblockRequest, lg *slog.Logger) error {
	switch ub.Type {
	case "domain":
		err := policy.AppendDomain(policyPath, ub.Value)
		if err != nil {
			return fmt.Errorf("append domain: %w", err)
		}

		return nil
	case "ip":
		err := policy.AppendIP(policyPath, ub.Value)
		if err != nil {
			return fmt.Errorf("append ip: %w", err)
		}

		return nil
	default:
		lg.Warn("remote_unblock.unknown_type", "type", ub.Type)

		return fmt.Errorf("%w: %s", errUnknownUnblockType, ub.Type)
	}
}

func acknowledgeUnblock(ctx context.Context, client *http.Client, baseURL, apiKey, id string) error {
	body, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return fmt.Errorf("marshal ack body: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		baseURL+"/api/v1/unblocks/ack",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create ack request: %w", err)
	}

	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send ack request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", errAckFailed, resp.StatusCode)
	}

	return nil
}
