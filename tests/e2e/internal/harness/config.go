// Package harness starts and drives g0efilter stacks for the Go e2e suite.
package harness

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FilterMode is the agent's egress filtering mode.
type FilterMode string

// Supported filter modes.
const (
	FilterModeHTTPS     FilterMode = "https"
	FilterModeDNS       FilterMode = "dns"
	FilterModeDNSStrict FilterMode = "dns-strict"
)

// DefaultAPIKey authenticates the test stack.
const DefaultAPIKey = "your-secure-api-key-here"

const (
	defaultAgentImage     = "g0efilter:test"
	defaultDashboardImage = "g0efilter-dashboard:test"
)

// StackConfig describes a test stack.
type StackConfig struct {
	Mode          FilterMode
	DefaultAction string
	LearningMode  bool
	Enforce       string

	APIKey       string
	AuthMode     string
	AdminHash    string
	CookieSecure bool
	Ephemeral    bool
	FleetEnabled bool
	CORSOrigin   string

	NotifyURLs string

	// PolicyDir is bind-mounted at /app/policy. Leave empty to have the harness
	// allocate one per stack; its lifetime then matches the stack, not the test
	// that happened to start it (shared stacks outlive their first test).
	PolicyDir string

	AgentImage     string
	DashboardImage string
	TesterImage    string
}

// BaselineConfig is the default-deny stack the shared behaviour phases use.
func BaselineConfig(t *testing.T, mode FilterMode) StackConfig {
	t.Helper()

	return StackConfig{
		Mode:           mode,
		DefaultAction:  "deny",
		LearningMode:   false,
		Enforce:        "block",
		APIKey:         DefaultAPIKey,
		AuthMode:       "none",
		AdminHash:      "",
		CookieSecure:   true,
		Ephemeral:      false,
		FleetEnabled:   false,
		CORSOrigin:     "",
		NotifyURLs:     "",
		PolicyDir:      "",
		AgentImage:     Env("G0EFILTER_IMAGE", defaultAgentImage),
		DashboardImage: Env("G0EFILTER_DASHBOARD_IMAGE", defaultDashboardImage),
		TesterImage:    Env("E2E_TESTER_IMAGE", "alpine/curl:latest"),
	}
}

// LearningConfig never blocks and reports unlisted hosts instead.
func LearningConfig(t *testing.T, mode FilterMode) StackConfig {
	t.Helper()

	cfg := BaselineConfig(t, mode)
	cfg.LearningMode = true

	return cfg
}

// AuditConfig is dry-run enforcement: would-be blocks are logged and allowed.
func AuditConfig(t *testing.T, mode FilterMode) StackConfig {
	t.Helper()

	cfg := BaselineConfig(t, mode)
	cfg.Enforce = "audit"

	return cfg
}

// NotifyConfig points the agent at the sink, which is never allow-listed: the
// agent has to reach its own notification server without policy permitting it.
func NotifyConfig(t *testing.T, mode FilterMode) StackConfig {
	t.Helper()

	cfg := BaselineConfig(t, mode)
	cfg.NotifyURLs = NotifySinkURLs

	return cfg
}

// DNSStrictConfig enforces at connection time from the resolved-IP sets.
func DNSStrictConfig(t *testing.T) StackConfig {
	t.Helper()

	return BaselineConfig(t, FilterModeDNSStrict)
}

// newPolicyDir creates a policy mount owned by the stack rather than by a test:
// a shared stack outlives the test that started it, so t.TempDir would delete
// the mount from underneath it. The agent runs as a different user than the test
// process, so the directory must be world-writable for policy rewrites to work.
func newPolicyDir() (string, error) {
	dir, err := os.MkdirTemp("", "g0efilter-policy-")
	if err != nil {
		return "", fmt.Errorf("create policy dir: %w", err)
	}

	err = os.Chmod(dir, 0o777) //nolint:gosec // shared with a container user
	if err != nil {
		return "", fmt.Errorf("chmod policy dir: %w", err)
	}

	return dir, nil
}

func (c StackConfig) fingerprint() string {
	return strings.Join([]string{
		string(c.Mode), c.DefaultAction, strconv.FormatBool(c.LearningMode), c.Enforce,
		c.APIKey, c.AuthMode, c.AdminHash, strconv.FormatBool(c.CookieSecure),
		strconv.FormatBool(c.Ephemeral), strconv.FormatBool(c.FleetEnabled), c.CORSOrigin,
		c.NotifyURLs,
		c.PolicyDir, c.AgentImage, c.DashboardImage, c.TesterImage,
	}, "|")
}

// ModeFromEnv reads E2E_FILTER_MODE, defaulting to https.
func ModeFromEnv(t *testing.T) FilterMode {
	t.Helper()

	switch mode := FilterMode(strings.ToLower(Env("E2E_FILTER_MODE", string(FilterModeHTTPS)))); mode {
	case FilterModeHTTPS, FilterModeDNS, FilterModeDNSStrict:
		return mode
	default:
		t.Fatalf("unsupported E2E_FILTER_MODE %q (want https, dns or dns-strict)", mode)

		return ""
	}
}

// Env reads a string environment variable with a fallback.
func Env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}

	return fallback
}

// EnvInt reads an integer environment variable with a fallback.
func EnvInt(name string, fallback int) int {
	v, err := strconv.Atoi(Env(name, ""))
	if err != nil {
		return fallback
	}

	return v
}

// EnvDuration reads a duration environment variable with a fallback.
func EnvDuration(name string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(Env(name, ""))
	if err != nil {
		return fallback
	}

	return d
}
