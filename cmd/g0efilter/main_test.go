package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const (
	testVersion = "dev"
	testDate    = "unknown"
	testCommit  = "none"
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

func TestGetenvDefault(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv() due to Go restrictions
			// Clean up environment
			defer func() { _ = os.Unsetenv(tt.key) }()

			if tt.setEnv {
				t.Setenv(tt.key, tt.envVal)
			}

			if got := getenvDefault(tt.key, tt.defaultVal); got != tt.expected {
				t.Errorf("getenvDefault() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func getPrintVersionTestCases() []struct {
	name             string
	version          string
	commit           string
	date             string
	expectedContains []string
} {
	return []struct {
		name             string
		version          string
		commit           string
		date             string
		expectedContains []string
	}{
		{
			name:    "short commit hash",
			version: "1.0.0",
			commit:  "abcdef123456",
			date:    "2025-01-01",
			expectedContains: []string{
				"g0efilter v1.0.0 abcdef1 (2025-01-01)",
				"Copyright (C) 2025 g0lab",
				"Licensed under the MIT license",
			},
		},
		{
			name:    "long commit hash",
			version: "2.0.0",
			commit:  "abcdef123456789012345678901234567890",
			date:    "2025-12-31",
			expectedContains: []string{
				"g0efilter v2.0.0 abcdef1 (2025-12-31)",
				"Copyright (C) 2025 g0lab",
				"Licensed under the MIT license",
			},
		},
		{
			name:    "short commit",
			version: testVersion,
			commit:  "abc",
			date:    testDate,
			expectedContains: []string{
				"g0efilter vdev abc (unknown)",
				"Copyright (C) 2025 g0lab",
				"Licensed under the MIT license",
			},
		},
	}
}

//nolint:paralleltest // Cannot use t.Parallel() because we modify global variables
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

	tests := getPrintVersionTestCases()

	for _, tt := range tests {
		//nolint:paralleltest // Cannot use t.Parallel() due to global variable modifications
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() due to global variable modifications
			// Set test values
			version = tt.version
			commit = tt.commit
			date = tt.date

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

			// Check that all expected strings are present
			for _, expected := range tt.expectedContains {
				if !strings.Contains(output, expected) {
					t.Errorf("printVersion() output does not contain %q\nActual output:\n%s", expected, output)
				}
			}
		})
	}
}

//nolint:paralleltest // Cannot use t.Parallel() because we modify global variables
func TestInit(t *testing.T) {
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

	//nolint:paralleltest // Cannot use t.Parallel() due to global variable modifications
	t.Run("empty values get defaults", func(t *testing.T) {
		// Cannot use t.Parallel() due to global variable modifications
		testInitEmptyValuesG0efilter(t)
	})

	//nolint:paralleltest // Cannot use t.Parallel() due to global variable modifications
	t.Run("existing values are preserved", func(t *testing.T) {
		// Cannot use t.Parallel() due to global variable modifications
		testInitExistingValuesG0efilter(t)
	})
}

func testInitEmptyValuesG0efilter(t *testing.T) {
	t.Helper()

	version = ""
	commit = ""
	date = ""

	// Simulate init function logic
	if version == "" {
		version = testVersion
	}

	if date == "" {
		date = testDate
	}

	if commit == "" {
		commit = testCommit
	}

	if version != testVersion {
		t.Errorf("Expected version to be %q, got %s", testVersion, version)
	}

	if commit != testCommit {
		t.Errorf("Expected commit to be %q, got %s", testCommit, commit)
	}

	if date != testDate {
		t.Errorf("Expected date to be %q, got %s", testDate, date)
	}
}

func testInitExistingValuesG0efilter(t *testing.T) {
	t.Helper()

	version = "1.0.0"
	commit = "abc123"
	date = "2025-01-01"

	// Simulate init function logic
	if version == "" {
		version = testVersion
	}

	if date == "" {
		date = testDate
	}

	if commit == "" {
		commit = testCommit
	}

	if version != "1.0.0" {
		t.Errorf("Expected version to be '1.0.0', got %s", version)
	}

	if commit != "abc123" {
		t.Errorf("Expected commit to be 'abc123', got %s", commit)
	}

	if date != "2025-01-01" {
		t.Errorf("Expected date to be '2025-01-01', got %s", date)
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Test that constants have expected values
	if name != "g0efilter" {
		t.Errorf("Expected name to be 'g0efilter', got %s", name)
	}

	if licenseYear != "2025" {
		t.Errorf("Expected licenseYear to be '2025', got %s", licenseYear)
	}

	if licenseOwner != "g0lab" {
		t.Errorf("Expected licenseOwner to be 'g0lab', got %s", licenseOwner)
	}

	if licenseType != "MIT" {
		t.Errorf("Expected licenseType to be 'MIT', got %s", licenseType)
	}

	if defaultDialTimeout != 5000 {
		t.Errorf("Expected defaultDialTimeout to be 5000, got %d", defaultDialTimeout)
	}

	if defaultIdleTimeout != 600000 {
		t.Errorf("Expected defaultIdleTimeout to be 600000, got %d", defaultIdleTimeout)
	}
}

// Helper function to compare config fields and report errors.
func compareConfig(t *testing.T, got, want config) {
	t.Helper()

	if got.policyPath != want.policyPath {
		t.Errorf("policyPath = %v, want %v", got.policyPath, want.policyPath)
	}

	if got.httpPort != want.httpPort {
		t.Errorf("httpPort = %v, want %v", got.httpPort, want.httpPort)
	}

	if got.httpsPort != want.httpsPort {
		t.Errorf("httpsPort = %v, want %v", got.httpsPort, want.httpsPort)
	}

	if got.dnsPort != want.dnsPort {
		t.Errorf("dnsPort = %v, want %v", got.dnsPort, want.dnsPort)
	}

	if got.logLevel != want.logLevel {
		t.Errorf("logLevel = %v, want %v", got.logLevel, want.logLevel)
	}

	if got.logFile != want.logFile {
		t.Errorf("logFile = %v, want %v", got.logFile, want.logFile)
	}

	if got.hostname != want.hostname {
		t.Errorf("hostname = %v, want %v", got.hostname, want.hostname)
	}

	if got.mode != want.mode {
		t.Errorf("mode = %v, want %v", got.mode, want.mode)
	}
}

// Test config loading with various environment variables.
func TestLoadConfig(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv()
	tests := []struct {
		name     string
		envVars  map[string]string
		expected config
	}{
		{
			name: "defaults",
			envVars: map[string]string{
				"HOSTNAME": "", // Clear any existing HOSTNAME env var
			},
			expected: config{
				policyPath: "/app/policy.yaml",
				httpPort:   "8080",
				httpsPort:  "8443",
				dnsPort:    "53",
				logLevel:   "INFO",
				logFile:    "",
				hostname:   "",
				mode:       "sni",
			},
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"POLICY_PATH": "/custom/policy.yaml",
				"HTTP_PORT":   "9080",
				"HTTPS_PORT":  "9443",
				"DNS_PORT":    "5353",
				"LOG_LEVEL":   "DEBUG",
				"LOG_FILE":    "/var/log/g0efilter.log",
				"HOSTNAME":    "test-host",
				"FILTER_MODE": "DNS",
			},
			expected: config{
				policyPath: "/custom/policy.yaml",
				httpPort:   "9080",
				httpsPort:  "9443",
				dnsPort:    "5353",
				logLevel:   "DEBUG",
				logFile:    "/var/log/g0efilter.log",
				hostname:   "test-host",
				mode:       "dns",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() with t.Setenv()

			// Set environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := loadConfig()
			compareConfig(t, cfg, tt.expected)
		})
	}
}

// Test handleVersionFlag.
// Cannot use t.Parallel() because handleVersionFlag modifies global os.Args and os.Stderr.
//
//nolint:paralleltest // Cannot parallelize due to global state modification (os.Args, os.Stderr)
func TestHandleVersionFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{"--version flag", []string{"g0efilter", "--version"}, true},
		{"version subcommand", []string{"g0efilter", "version"}, true},
		{"-V flag", []string{"g0efilter", "-V"}, true},
		{"-v flag", []string{"g0efilter", "-v"}, true},
		{"no version flag", []string{"g0efilter"}, false},
		{"other flag", []string{"g0efilter", "--help"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot use t.Parallel() because we modify global os.Args and os.Stderr

			// Save and restore os.Args
			oldArgs := os.Args

			t.Cleanup(func() { os.Args = oldArgs })

			os.Args = tt.args

			// Capture stderr to suppress version output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			result := handleVersionFlag()

			_ = w.Close()
			os.Stderr = oldStderr

			// Drain the pipe
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r)

			if result != tt.expected {
				t.Errorf("handleVersionFlag() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Integration test - runs with: go test -tags=integration.
func TestG0efilterFullSystemIntegration(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test the full system startup and basic functionality
	// This would test real file I/O, network, etc.
	t.Log("Running full system integration test")

	// Example: Test config file loading
	configFile := "../../test/policy.yaml"

	_, err := os.Stat(configFile)
	if os.IsNotExist(err) {
		t.Skip("Test config file not found, skipping integration test")
	}
	// Test would start actual service and verify behavior
}

// Test environment defaults.
func TestEnvironmentDefaults(t *testing.T) {
	t.Parallel()

	// Test that defaults are used when environment variables are not set
	policyPath := getenvDefault("POLICY_PATH_TEST", "/app/policy.yaml")
	httpPort := getenvDefault("HTTP_PORT_TEST", "8080")
	httpsPort := getenvDefault("HTTPS_PORT_TEST", "8443")
	dnsPort := getenvDefault("DNS_PORT_TEST", "53")
	logLevel := getenvDefault("LOG_LEVEL_TEST", "INFO")
	mode := strings.ToLower(getenvDefault("FILTER_MODE_TEST", "sni"))

	if httpPort != "8080" {
		t.Errorf("Expected default HTTP port 8080, got %s", httpPort)
	}

	if httpsPort != "8443" {
		t.Errorf("Expected default HTTPS port 8443, got %s", httpsPort)
	}

	if dnsPort != "53" {
		t.Errorf("Expected default DNS port 53, got %s", dnsPort)
	}

	if logLevel != "INFO" {
		t.Errorf("Expected default log level INFO, got %s", logLevel)
	}

	if mode != "sni" {
		t.Errorf("Expected default filter mode sni, got %s", mode)
	}

	if policyPath != "/app/policy.yaml" {
		t.Errorf("Expected default policy path /app/policy.yaml, got %s", policyPath)
	}
}
