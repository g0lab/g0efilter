package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/internal/dashboard"
)

func TestExitCodeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     exitCodeError
		expected string
	}{
		{
			name:     "exit code 0",
			code:     exitCodeError(0),
			expected: "exit code 0",
		},
		{
			name:     "exit code 1",
			code:     exitCodeError(1),
			expected: "exit code 1",
		},
		{
			name:     "exit code 255",
			code:     exitCodeError(255),
			expected: "exit code 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.code.Error(); got != tt.expected {
				t.Errorf("exitCodeError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

//nolint:dupl // Similar test pattern but tests different function (getenv vs getenvFloat)
func TestGetenv(t *testing.T) {
	// Cannot use t.Parallel() with subtests that use t.Setenv()
	tests := []struct {
		name       string
		key        string
		defaultVal string
		envVal     string
		setEnv     bool
		expected   string
	}{
		{
			name:       "environment variable not set",
			key:        "TEST_UNSET_VAR",
			defaultVal: "default_value",
			expected:   "default_value",
		},
		{
			name:       "environment variable set",
			key:        "TEST_SET_VAR",
			defaultVal: "default_value",
			envVal:     "env_value",
			setEnv:     true,
			expected:   "env_value",
		},
		{
			name:       "environment variable empty",
			key:        "TEST_EMPTY_VAR",
			defaultVal: "default_value",
			envVal:     "",
			setEnv:     true,
			expected:   "default_value",
		},
		{
			name:       "environment variable with whitespace",
			key:        "TEST_WHITESPACE_VAR",
			defaultVal: "default_value",
			envVal:     "  trimmed_value  ",
			setEnv:     true,
			expected:   "trimmed_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv()
			if tt.setEnv {
				t.Setenv(tt.key, tt.envVal)
			}

			result := getenv(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("getenv(%q, %q) = %q, want %q", tt.key, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

func TestGetenvInt(t *testing.T) {
	// Cannot use t.Parallel() with subtests that use t.Setenv()
	tests := []struct {
		name       string
		key        string
		defaultVal int
		envVal     string
		setEnv     bool
		expected   int
	}{
		{
			name:       "not set",
			key:        "TEST_INT_UNSET",
			defaultVal: 42,
			expected:   42,
		},
		{
			name:       "valid integer",
			key:        "TEST_INT_VALID",
			defaultVal: 42,
			envVal:     "100",
			setEnv:     true,
			expected:   100,
		},
		{
			name:       "invalid integer",
			key:        "TEST_INT_INVALID",
			defaultVal: 42,
			envVal:     "not_a_number",
			setEnv:     true,
			expected:   42,
		},
		{
			name:       "empty string",
			key:        "TEST_INT_EMPTY",
			defaultVal: 42,
			envVal:     "",
			setEnv:     true,
			expected:   42,
		},
		{
			name:       "whitespace",
			key:        "TEST_INT_WHITESPACE",
			defaultVal: 42,
			envVal:     "  200  ",
			setEnv:     true,
			expected:   200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv()
			if tt.setEnv {
				t.Setenv(tt.key, tt.envVal)
			}

			result := getenvInt(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("getenvInt(%q, %d) = %d, want %d", tt.key, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

//nolint:dupl // Similar test pattern but tests different function (getenv vs getenvFloat)
func TestGetenvFloat(t *testing.T) {
	// Cannot use t.Parallel() with subtests that use t.Setenv()
	tests := []struct {
		name       string
		key        string
		defaultVal float64
		envVal     string
		setEnv     bool
		expected   float64
	}{
		{
			name:       "not set",
			key:        "TEST_FLOAT_UNSET",
			defaultVal: 3.14,
			expected:   3.14,
		},
		{
			name:       "valid float",
			key:        "TEST_FLOAT_VALID",
			defaultVal: 3.14,
			envVal:     "2.71",
			setEnv:     true,
			expected:   2.71,
		},
		{
			name:       "invalid float",
			key:        "TEST_FLOAT_INVALID",
			defaultVal: 3.14,
			envVal:     "not_a_number",
			setEnv:     true,
			expected:   3.14,
		},
		{
			name:       "empty string",
			key:        "TEST_FLOAT_EMPTY",
			defaultVal: 3.14,
			envVal:     "",
			setEnv:     true,
			expected:   3.14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv()
			if tt.setEnv {
				t.Setenv(tt.key, tt.envVal)
			}

			result := getenvFloat(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("getenvFloat(%q, %f) = %f, want %f", tt.key, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

//nolint:paralleltest // Cannot parallelize due to global variable modification (version, commit, date)
func TestPrintVersion(t *testing.T) {
	// Cannot use t.Parallel() because we modify global variables
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date

	// Restore original values after test
	t.Cleanup(func() {
		version = origVersion
		commit = origCommit
		date = origDate
	})

	// Set test values
	version = "1.2.3"
	commit = "abc1234567"
	date = "2025-01-01"

	// Capture stderr output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	printVersion()

	_ = w.Close()
	os.Stderr = oldStderr

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	expectedSubstrings := []string{
		"g0efilter-dashboard",
		"1.2.3",
		"abc1234", // Short commit hash
		"2025-01-01",
		"MIT",
	}

	for _, expected := range expectedSubstrings {
		if !strings.Contains(output, expected) {
			t.Errorf("printVersion() output missing %q, got: %s", expected, output)
		}
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	if name != "g0efilter-dashboard" {
		t.Errorf("name = %v, want g0efilter-dashboard", name)
	}

	if licenseType != "MIT" {
		t.Errorf("licenseType = %v, want MIT", licenseType)
	}

	if defaultBufferSize != 5000 {
		t.Errorf("defaultBufferSize = %v, want 5000", defaultBufferSize)
	}

	if defaultReadLimit != 500 {
		t.Errorf("defaultReadLimit = %v, want 500", defaultReadLimit)
	}

	if defaultSERetryMs != 2000 {
		t.Errorf("defaultSERetryMs = %v, want 2000", defaultSERetryMs)
	}

	if defaultRateRPS != 50.0 {
		t.Errorf("defaultRateRPS = %v, want 50.0", defaultRateRPS)
	}

	if defaultRateBurst != 100.0 {
		t.Errorf("defaultRateBurst = %v, want 100.0", defaultRateBurst)
	}
}

// Helper function to compare dashboard configs.
func compareDashboardConfig(t *testing.T, got, want dashboard.Config) {
	t.Helper()

	if got.Addr != want.Addr {
		t.Errorf("Addr = %v, want %v", got.Addr, want.Addr)
	}

	if got.APIKey != want.APIKey {
		t.Errorf("APIKey = %v, want %v", got.APIKey, want.APIKey)
	}

	if got.LogLevel != want.LogLevel {
		t.Errorf("LogLevel = %v, want %v", got.LogLevel, want.LogLevel)
	}

	if got.BufferSize != want.BufferSize {
		t.Errorf("BufferSize = %v, want %v", got.BufferSize, want.BufferSize)
	}

	if got.ReadLimit != want.ReadLimit {
		t.Errorf("ReadLimit = %v, want %v", got.ReadLimit, want.ReadLimit)
	}

	if got.SERetryMs != want.SERetryMs {
		t.Errorf("SERetryMs = %v, want %v", got.SERetryMs, want.SERetryMs)
	}

	if got.RateRPS != want.RateRPS {
		t.Errorf("RateRPS = %v, want %v", got.RateRPS, want.RateRPS)
	}

	if got.RateBurst != want.RateBurst {
		t.Errorf("RateBurst = %v, want %v", got.RateBurst, want.RateBurst)
	}
}

// Test buildConfig with environment variables.
func TestBuildConfig(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv()
	tests := []struct {
		name     string
		envVars  map[string]string
		expected dashboard.Config
	}{
		{
			name:    "all defaults",
			envVars: map[string]string{},
			expected: dashboard.Config{
				Addr:         ":8081",
				APIKey:       "",
				LogLevel:     "INFO",
				LogFormat:    "json",
				BufferSize:   defaultBufferSize,
				ReadLimit:    defaultReadLimit,
				SERetryMs:    defaultSERetryMs,
				RateRPS:      defaultRateRPS,
				RateBurst:    defaultRateBurst,
				WriteTimeout: 0,
			},
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"API_KEY":      "test-key-123",
				"PORT":         "9000",
				"LOG_LEVEL":    "DEBUG",
				"BUFFER_SIZE":  "2000",
				"READ_LIMIT":   "250",
				"SSE_RETRY_MS": "5000",
				"RATE_RPS":     "100.5",
				"RATE_BURST":   "200.5",
			},
			expected: dashboard.Config{
				Addr:         "9000",
				APIKey:       "test-key-123",
				LogLevel:     "DEBUG",
				LogFormat:    "json",
				BufferSize:   2000,
				ReadLimit:    250,
				SERetryMs:    5000,
				RateRPS:      100.5,
				RateBurst:    200.5,
				WriteTimeout: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv()
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := buildConfig()
			compareDashboardConfig(t, cfg, tt.expected)
		})
	}
}

// Test normalizeAddr function.
func TestNormalizeAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"port number only", "8080", ":8080"},
		{"already normalized", ":8080", ":8080"},
		{"host:port", "localhost:8080", "localhost:8080"},
		{"empty string", "", ""},
		{"non-numeric", "abc", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := dashboard.Config{Addr: tt.input}
			normalizeAddr(&cfg)

			if cfg.Addr != tt.expected {
				t.Errorf("normalizeAddr(%q) = %q, want %q", tt.input, cfg.Addr, tt.expected)
			}
		})
	}
}
