//nolint:testpackage // Need access to internal implementation details
package server

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

type envCase[T any] struct {
	name string
	key  string
	def  T
	set  bool
	val  string
	want T
}

func runEnvCases[T comparable](t *testing.T, cases []envCase[T], fn func(key string, def T) T) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(tc.key, tc.val)
			}

			got := fn(tc.key, tc.def)
			if got != tc.want {
				t.Fatalf("env(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

// These getenv tests use t.Setenv(), so they must not run in parallel.
//
//nolint:paralleltest // t.Setenv() mutates global process environment
func TestGetenv(t *testing.T) {
	cases := []envCase[string]{
		{name: "unset", key: "TEST_UNSET_VAR", def: "default", want: "default"},
		{name: "set", key: "TEST_SET_VAR", def: "default", set: true, val: "env", want: "env"},
		{name: "empty uses default", key: "TEST_EMPTY_VAR", def: "default", set: true, val: "", want: "default"},
		{name: "whitespace trimmed", key: "TEST_WS_VAR", def: "default", set: true, val: "  trimmed  ", want: "trimmed"},
	}

	runEnvCases(t, cases, getenv)
}

//nolint:paralleltest // t.Setenv() mutates global process environment
func TestGetenvInt(t *testing.T) {
	cases := []envCase[int]{
		{name: "unset", key: "TEST_INT_UNSET", def: 42, want: 42},
		{name: "valid", key: "TEST_INT_VALID", def: 42, set: true, val: "100", want: 100},
		{name: "invalid", key: "TEST_INT_INVALID", def: 42, set: true, val: "nope", want: 42},
		{name: "empty", key: "TEST_INT_EMPTY", def: 42, set: true, val: "", want: 42},
		{name: "whitespace ok", key: "TEST_INT_WS", def: 42, set: true, val: "  200  ", want: 200},
	}

	runEnvCases(t, cases, getenvInt)
}

//nolint:paralleltest // t.Setenv() mutates global process environment
func TestGetenvFloat(t *testing.T) {
	cases := []envCase[float64]{
		{name: "unset", key: "TEST_FLOAT_UNSET", def: 3.14, want: 3.14},
		{name: "valid", key: "TEST_FLOAT_VALID", def: 3.14, set: true, val: "2.71", want: 2.71},
		{name: "invalid", key: "TEST_FLOAT_INVALID", def: 3.14, set: true, val: "nope", want: 3.14},
		{name: "empty", key: "TEST_FLOAT_EMPTY", def: 3.14, set: true, val: "", want: 3.14},
	}

	runEnvCases(t, cases, getenvFloat)
}

func compareDashboardConfig(t *testing.T, got, want Config) {
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

	if got.WriteTimeout != want.WriteTimeout {
		t.Errorf("WriteTimeout = %v, want %v", got.WriteTimeout, want.WriteTimeout)
	}
}

func TestBuildConfigDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("API_KEY", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("BUFFER_SIZE", "")
	t.Setenv("READ_LIMIT", "")
	t.Setenv("SSE_RETRY_MS", "")
	t.Setenv("RATE_RPS", "")
	t.Setenv("RATE_BURST", "")
	t.Setenv("WRITE_TIMEOUT", "")

	want := Config{
		Addr:         ":8081",
		APIKey:       "",
		LogLevel:     "INFO",
		BufferSize:   defaultBufferSize,
		ReadLimit:    defaultReadLimit,
		SERetryMs:    defaultSERetryMs,
		RateRPS:      defaultRateRPS,
		RateBurst:    defaultRateBurst,
		WriteTimeout: 0,
	}

	got := buildConfig("1.2.3")
	compareDashboardConfig(t, got, want)
}

func TestBuildConfigCustomValues(t *testing.T) {
	t.Setenv("API_KEY", "test-key-123")
	t.Setenv("PORT", "9000")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("BUFFER_SIZE", "2000")
	t.Setenv("READ_LIMIT", "250")
	t.Setenv("SSE_RETRY_MS", "5000")
	t.Setenv("RATE_RPS", "100.5")
	t.Setenv("RATE_BURST", "200.5")

	want := Config{
		Addr:         "9000",
		APIKey:       "test-key-123",
		LogLevel:     "DEBUG",
		BufferSize:   2000,
		ReadLimit:    250,
		SERetryMs:    5000,
		RateRPS:      100.5,
		RateBurst:    200.5,
		WriteTimeout: 0,
	}

	got := buildConfig("1.2.3")
	compareDashboardConfig(t, got, want)
}

func TestNormalizeAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "port only", input: "8080", expected: ":8080"},
		{name: "already ok", input: ":8080", expected: ":8080"},
		{name: "host:port", input: "localhost:8080", expected: "localhost:8080"},
		{name: "empty", input: "", expected: ""},
		{name: "non-numeric", input: "abc", expected: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := Config{Addr: tt.input}
			normalizeAddr(&cfg)

			if cfg.Addr != tt.expected {
				t.Fatalf("normalizeAddr(%q) = %q, want %q", tt.input, cfg.Addr, tt.expected)
			}
		})
	}
}

//nolint:paralleltest // Touches os.Stderr and creates loggers
func TestSetupLoggingMissingAPIKey(t *testing.T) {
	cfg := Config{
		Addr:         ":8081",
		APIKey:       "",
		LogLevel:     "INFO",
		BufferSize:   defaultBufferSize,
		ReadLimit:    defaultReadLimit,
		SERetryMs:    defaultSERetryMs,
		RateRPS:      defaultRateRPS,
		RateBurst:    defaultRateBurst,
		WriteTimeout: 0,
		Version:      "dev",
	}

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	lg, err := setupLogging(cfg, "1.2.3", "2026-01-01", "abc1234")

	_ = w.Close()
	os.Stderr = oldStderr

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	_ = buf.String()

	if lg != nil {
		t.Fatal("expected nil logger when API_KEY missing")
	}

	if !errors.Is(err, errMissingAPIKey) {
		t.Fatalf("expected errMissingAPIKey, got %v", err)
	}
}
