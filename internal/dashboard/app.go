package dashboard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/store"
	"github.com/g0lab/g0efilter/internal/logging"
	"golang.org/x/crypto/bcrypt"
)

const (
	name         = "g0efilter-dashboard"
	licenseYear  = "2026"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultBufferSize = 5000
	defaultReadLimit  = 5000
	defaultSERetryMs  = 2000
	defaultRateRPS    = 50.0
	defaultRateBurst  = 100.0
	defaultSessionTTL = 24 * time.Hour

	shutdownGracePeriod = 3 * time.Second
	resetTimeout        = 10 * time.Second
)

var (
	errMissingAPIKey = errors.New("API_KEY is required but not set")
	errEmptyPassword = errors.New("empty password on stdin")
	errResetNeedsDB  = errors.New("reset-password requires DB_PATH (persistence must be enabled)")
)

// RunDashboard is the dashboard entrypoint used by cmd/g0efilter-.
func RunDashboard(args []string, version, date, commit string) error {
	if handled, err := dispatchSubcommand(args, version, date, commit); handled {
		return err
	}

	cfg := buildConfig(version)
	normalizeAddr(&cfg)

	lg, err := setupLogging(cfg, version, date, commit)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, cfg)
	}()

	select {
	case err = <-errCh:
		cancel()

		if err != nil {
			lg.Error("failed", "err", err)

			return err
		}

		return nil

	case sig := <-sigCh:
		lg.Info("shutdown.signal", "signal", sig.String())
		cancel()

		lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod.String())

		select {
		case <-errCh:
		case <-time.After(shutdownGracePeriod):
			lg.Warn("shutdown.timeout", "timeout", shutdownGracePeriod.String())
		}

		logging.Shutdown(1 * time.Second)
		lg.Info("shutdown.complete")

		return nil
	}
}

// dispatchSubcommand runs a CLI subcommand if args name one. handled is true
// when a subcommand ran (err carries its result); false continues to the server.
func dispatchSubcommand(args []string, version, date, commit string) (bool, error) {
	if handleVersionFlag(args, version, date, commit) {
		return true, nil
	}

	if done, err := handleHashPassword(args); done {
		return true, err
	}

	if done, err := handleResetPassword(args); done {
		return true, err
	}

	return false, nil
}

func handleVersionFlag(args []string, version, date, commit string) bool {
	if len(args) > 1 {
		switch args[1] {
		case "--version", "version", "-V", "-v":
			printVersion(version, date, commit)

			return true
		}
	}

	return false
}

// handleHashPassword implements the hash-password subcommand: reads a
// password from stdin and prints its bcrypt hash for ADMIN_PASSWORD_HASH.
func handleHashPassword(args []string) (bool, error) {
	if len(args) < 2 || args[1] != "hash-password" {
		return false, nil
	}

	pw, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return true, fmt.Errorf("read password: %w", err)
	}

	pw = strings.TrimRight(pw, "\r\n")
	if pw == "" {
		return true, errEmptyPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return true, fmt.Errorf("hash password: %w", err)
	}

	_, _ = fmt.Fprintln(os.Stdout, string(hash))

	return true, nil
}

// handleResetPassword implements the reset-password subcommand: sets a new
// random password for a user (default ADMIN_USERNAME, else "admin") in the
// persistent DB and prints it once. Recovers a locked-out dashboard without
// dashboard access. Requires DB_PATH.
func handleResetPassword(args []string) (bool, error) {
	if len(args) < 2 || args[1] != "reset-password" {
		return false, nil
	}

	dbPath := getenv("DB_PATH", "")
	if dbPath == "" {
		return true, errResetNeedsDB
	}

	username := getenv("ADMIN_USERNAME", "admin")
	if len(args) >= 3 && strings.TrimSpace(args[2]) != "" {
		username = strings.TrimSpace(args[2])
	}

	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()

	client, db, err := store.Open(ctx, dbPath)
	if err != nil {
		return true, fmt.Errorf("open db: %w", err)
	}

	defer func() { _ = client.Close() }()

	err = store.Migrate(ctx, db)
	if err != nil {
		return true, fmt.Errorf("migrate db: %w", err)
	}

	password := generatePassword()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return true, fmt.Errorf("hash password: %w", err)
	}

	users := store.NewUserStore(client, slog.New(slog.DiscardHandler))

	err = users.Upsert(ctx, username, string(hash))
	if err != nil {
		return true, fmt.Errorf("reset password: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "reset password for %q:\n%s\n", username, password)

	return true, nil
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

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s) %s\n", name, version, short, date, getGoVersion())
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

func buildConfig(version string) Config {
	return Config{
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

		AuthMode:          strings.ToLower(getenv("AUTH_MODE", AuthModeSession)),
		DBPath:            getenv("DB_PATH", ""),
		CookieSecure:      getenvBool("COOKIE_SECURE", true),
		SessionTTL:        getenvDuration("SESSION_TTL", defaultSessionTTL),
		ForwardAuthHeader: getenv("FORWARD_AUTH_HEADER", "X-Forwarded-User"),
		AdminUsername:     getenv("ADMIN_USERNAME", "admin"),
		AdminPasswordHash: getenv("ADMIN_PASSWORD_HASH", ""),

		JWTSecret:        getenv("JWT_SECRET", ""),
		JWTPublicKeyPEM:  getenv("JWT_PUBLIC_KEY", ""),
		JWKSURL:          getenv("JWKS_URL", ""),
		JWTUsernameClaim: getenv("JWT_USERNAME_CLAIM", ""),
		JWTIssuer:        getenv("JWT_ISSUER", ""),
		JWTAudience:      getenv("JWT_AUDIENCE", ""),

		CORSAllowedOrigins: getenvList("CORS_ALLOWED_ORIGINS"),

		LogPersist:   getenvBool("LOG_PERSIST", false),
		LogRetention: getenvInt("LOG_RETENTION", 0),

		FleetEnabled: getenvBool("FLEET_ENABLED", false),
	}
}

// getenvList parses a comma-separated env var into a trimmed, non-empty slice.
func getenvList(k string) []string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return nil
	}

	var out []string

	for part := range strings.SplitSeq(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}

	return out
}

func getenvBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}

	return b
}

func getenvDuration(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}

	return d
}

func normalizeAddr(cfg *Config) {
	if cfg.Addr != "" && !strings.Contains(cfg.Addr, ":") {
		_, aerr := strconv.Atoi(cfg.Addr)
		if aerr == nil {
			cfg.Addr = ":" + cfg.Addr
		}
	}
}

func setupLogging(cfg Config, version, date, commit string) (*slog.Logger, error) {
	lg := logging.NewWithContext(context.Background(), cfg.LogLevel, os.Stdout, version)
	slog.SetDefault(lg)

	// API_KEY is validated in Run once stores are wired: with a database the
	// key set can live in the api_keys table instead of the environment.
	if cfg.APIKey == "" && cfg.DBPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: API_KEY environment variable is required but not set")
		fmt.Fprintln(os.Stderr, "The dashboard requires an API key for secure log ingestion")
		fmt.Fprintln(os.Stderr, "Please set API_KEY to a secure random string")

		lg.Error("config.missing_api_key", "msg", "API_KEY is required")

		return nil, errMissingAPIKey
	}

	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = commit[:7]
	}

	lg.Info(
		"starting",
		"version", version,
		"commit", shortCommit,
		"go_version", getGoVersion(),
		"build_date", date,
		"addr", cfg.Addr,
		"buffer_size", cfg.BufferSize,
		"read_limit", cfg.ReadLimit,
		"sse_retry_ms", cfg.SERetryMs,
		"rate_rps", cfg.RateRPS,
		"rate_burst", cfg.RateBurst,
		"write_timeout", cfg.WriteTimeout,
	)

	return lg, nil
}
