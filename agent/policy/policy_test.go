//nolint:testpackage // Need access to internal implementation details
package policy

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testEmptyPolicy = `allowlist:
  ips: []
  domains: []
`

func TestValidateIP(t *testing.T) {
	t.Parallel()

	tests := getValidateIPTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateIP(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateIP(%q) = nil, want error", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("validateIP(%q) = %v, want nil", tt.input, err)
				}
			}
		})
	}
}

func getValidateIPTests() []struct {
	name    string
	input   string
	wantErr bool
} {
	return []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid IPv4 cases
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 with whitespace", "  192.168.1.1  ", false},
		{"valid CIDR", "192.168.1.0/24", false},
		{"valid single IP CIDR", "192.168.1.1/32", false},
		{"valid large subnet", "10.0.0.0/8", false},

		// Valid IPv6 cases
		{"valid IPv6", "2001:db8::1", false},
		{"valid IPv6 loopback", "::1", false},
		{"valid IPv6 CIDR", "2001:db8::/32", false},
		{"valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"valid IPv6 /128", "2001:db8::1/128", false},

		// Invalid cases
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"invalid IP", "999.999.999.999", true},
		{"hostname", "example.com", true},
		{"IP with port", "192.168.1.1:80", true},
		{"invalid CIDR", "192.168.1.0/99", true},
		{"partial IP", "192.168.1", true},
		{"non-numeric", "not.an.ip.address", true},
		{"bracketed IPv6 with port", "[::1]:80", true},
		{"scoped IPv6", "fe80::1%eth0", true},
	}
}

func TestValidateDomain(t *testing.T) {
	t.Parallel()

	tests := getValidateDomainTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateDomain(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateDomain(%q) = nil, want error", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("validateDomain(%q) = %v, want nil", tt.input, err)
				}
			}
		})
	}
}

func getValidateDomainTests() []struct {
	name    string
	input   string
	wantErr bool
} {
	return []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid cases
		{"wildcard all", "*", false},
		{"simple domain", "example.com", false},
		{"subdomain", "sub.example.com", false},
		{"wildcard subdomain", "*.example.com", false},
		{"domain with trailing dot", "example.com.", false},
		{"long domain", "very-long-subdomain-name.example.com", false},
		{"domain with numbers", "test123.example.com", false},
		{"domain with hyphens", "test-domain.example-site.com", false},

		// Invalid cases
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"no TLD", "example", true},
		{"starts with dot", ".example.com", true},
		{"ends with dot after trim", "example.com..", true},
		{"double dots", "example..com", true},
		{"wildcard in middle", "ex*ample.com", false},
		{"wildcard between labels", "sub.*.example.com", false},
		{"consecutive wildcards", "sub.**.example.com", true},
		{"wildcard no dot", "example*", true},
		{"invalid wildcard", "*.", true},
		{"IP address as domain", "192.168.1.1", true},
		{"numeric TLD", "example.123", true},
		{"hyphen at start of label", "-example.com", true},
		{"hyphen at end of label", "example-.com", true},
		{"label too long", strings.Repeat("a", 64) + ".com", true},
		{"domain too long", strings.Repeat("a", 250) + ".com", true},
	}
}

func TestDomainToASCII(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		domain   string
		orig     string
		wantErr  bool
		expected string
	}{
		{
			name:     "simple ASCII domain",
			domain:   "example.com",
			orig:     "example.com",
			wantErr:  false,
			expected: "example.com",
		},
		{
			name:    "too long domain",
			domain:  strings.Repeat("a", 255) + ".com",
			orig:    strings.Repeat("a", 255) + ".com",
			wantErr: true,
		},
		{
			name:    "starts with dot",
			domain:  ".example.com",
			orig:    ".example.com",
			wantErr: true,
		},
		{
			name:    "IP literal",
			domain:  "192.168.1.1",
			orig:    "192.168.1.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := domainToASCII(tt.domain, tt.orig)
			if tt.wantErr {
				if err == nil {
					t.Errorf("domainToASCII(%q, %q) = %q, nil; want error", tt.domain, tt.orig, result)
				}
			} else {
				if err != nil {
					t.Errorf("domainToASCII(%q, %q) = %q, %v; want %q, nil", tt.domain, tt.orig, result, err, tt.expected)
				}

				if result != tt.expected {
					t.Errorf("domainToASCII(%q, %q) = %q; want %q", tt.domain, tt.orig, result, tt.expected)
				}
			}
		})
	}
}

func TestValidateDomainLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ascii   string
		orig    string
		wantErr bool
	}{
		{"valid domain", "example.com", "example.com", false},
		{"valid with hyphens", "test-site.example-domain.com", "test-site.example-domain.com", false},
		{"empty label", "example..com", "example..com", true},
		{"label too long", strings.Repeat("a", 64) + ".com", strings.Repeat("a", 64) + ".com", true},
		{"hyphen at start", "-example.com", "-example.com", true},
		{"hyphen at end", "example-.com", "example-.com", true},
		{"numeric TLD", "example.123", "example.123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateDomainLabels(tt.ascii, tt.orig)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateDomainLabels(%q, %q) = nil, want error", tt.ascii, tt.orig)
				}
			} else {
				if err != nil {
					t.Errorf("validateDomainLabels(%q, %q) = %v, want nil", tt.ascii, tt.orig, err)
				}
			}
		})
	}
}

func TestValidateLabelChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		label   string
		orig    string
		wantErr bool
	}{
		{"lowercase letters", "example", "example.com", false},
		{"uppercase letters", "EXAMPLE", "EXAMPLE.com", false},
		{"numbers", "test123", "test123.com", false},
		{"hyphens", "test-site", "test-site.com", false},
		{"mixed valid", "Test-123", "Test-123.com", false},
		{"invalid underscore", "test_site", "test_site.com", true},
		{"invalid space", "test site", "test site.com", true},
		{"invalid special chars", "test@site", "test@site.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateLabelChars(tt.label, tt.orig)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateLabelChars(%q, %q) = nil, want error", tt.label, tt.orig)
				}
			} else {
				if err != nil {
					t.Errorf("validateLabelChars(%q, %q) = %v, want nil", tt.label, tt.orig, err)
				}
			}
		})
	}
}

func TestIsAllDigits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"all digits", "123", true},
		{"single digit", "5", true},
		{"empty string", "", true},
		{"mixed", "123abc", false},
		{"letters", "abc", false},
		{"with hyphen", "12-3", false},
		{"with space", "1 23", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := isAllDigits(tt.input)
			if result != tt.expected {
				t.Errorf("isAllDigits(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid config file", func(t *testing.T) {
		t.Parallel()

		content := `allowlist:
  ips:
    - "192.168.1.1"
    - "10.0.0.0/8"
  domains:
    - "example.com"
    - "*.google.com"
`
		tmpFile := createTempFile(t, content)

		config, err := loadConfig(tmpFile)
		if err != nil {
			t.Fatalf("loadConfig() = %v, want nil", err)
		}

		if len(config.AllowList.IPs) != 2 {
			t.Errorf("Expected 2 IPs, got %d", len(config.AllowList.IPs))
		}

		if len(config.AllowList.Domains) != 2 {
			t.Errorf("Expected 2 domains, got %d", len(config.AllowList.Domains))
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()

		_, err := loadConfig("nonexistent-file.yaml")
		if err == nil {
			t.Error("loadConfig() = nil, want error for nonexistent file")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		t.Parallel()

		content := "invalid: yaml: content: ["
		tmpFile := createTempFile(t, content)

		_, err := loadConfig(tmpFile)
		if err == nil {
			t.Error("loadConfig() = nil, want error for invalid YAML")
		}
	})
}

func TestLoadConfigPathTraversal(t *testing.T) {
	t.Parallel()

	t.Run("path traversal with .. in path", func(t *testing.T) {
		t.Parallel()

		// Try to access a file using path traversal
		_, err := loadConfig("../../../etc/passwd")
		if err == nil {
			t.Error("loadConfig() = nil, want error for path traversal attempt")
		}

		// Check that it's specifically a path traversal error
		if err != nil && !strings.Contains(err.Error(), "path traversal not allowed") {
			t.Errorf("Expected path traversal error, got: %v", err)
		}
	})

	t.Run("path traversal with relative path", func(t *testing.T) {
		t.Parallel()

		// Try various path traversal patterns
		traversalPaths := []string{
			"./config/../../etc/passwd",
			"config/../../../etc/passwd",
			"config/./../../etc/passwd",
		}

		for _, path := range traversalPaths {
			_, err := loadConfig(path)
			if err == nil {
				t.Errorf("loadConfig(%q) = nil, want error for path traversal attempt", path)
			}

			// Check that it's caught by our validation - split into multiple checks to reduce line length
			if err != nil {
				hasTraversalError := strings.Contains(err.Error(), "path traversal not allowed")

				if !hasTraversalError {
					t.Errorf("Expected path traversal error for %q, got: %v", path, err)
				}
			}
		}
	})
}

func TestLoadConfigInvalidPaths(t *testing.T) {
	t.Parallel()

	t.Run("invalid file path with unusual characters", func(t *testing.T) {
		t.Parallel()

		// Test paths that would be cleaned differently by filepath.Clean
		invalidPaths := []string{
			"config//policy.yaml",          // double slash
			"config/./policy.yaml",         // current directory reference
			"config/../config/policy.yaml", // up and down
		}

		for _, path := range invalidPaths {
			_, err := loadConfig(path)
			if err == nil {
				t.Errorf("loadConfig(%q) = nil, want error for invalid file path", path)
			}

			// Some of these will be caught by file not found, others by path validation
			if err != nil {
				hasTraversalError := strings.Contains(err.Error(), "path traversal not allowed")
				hasAccessError := strings.Contains(err.Error(), "error accessing file")

				if !hasTraversalError && !hasAccessError {
					t.Errorf("Expected path validation error for %q, got: %v", path, err)
				}
			}
		}
	})

	t.Run("directory instead of file", func(t *testing.T) {
		t.Parallel()

		// Create a temporary directory
		tmpDir := t.TempDir()

		_, err := loadConfig(tmpDir)
		if err == nil {
			t.Error("loadConfig() = nil, want error when trying to load a directory")
		}

		// Check that it's specifically a "not a regular file" error
		if err != nil && !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})
}

func TestReadPolicy(t *testing.T) {
	t.Parallel()

	t.Run("valid policy file", func(t *testing.T) {
		t.Parallel()
		testReadPolicyValidFile(t)
	})

	t.Run("invalid IP in policy", func(t *testing.T) {
		t.Parallel()
		testReadPolicyInvalidIP(t)
	})

	t.Run("invalid domain in policy", func(t *testing.T) {
		t.Parallel()
		testReadPolicyInvalidDomain(t)
	})

	t.Run("empty lists", func(t *testing.T) {
		t.Parallel()
		testReadPolicyEmptyLists(t)
	})
}

func testReadPolicyValidFile(t *testing.T) {
	t.Helper()

	content := `allowlist:
  ips:
    - "192.168.1.1"
    - "10.0.0.0/24"
  domains:
    - "example.com"
    - "*.google.com"
`
	tmpFile := createTempFile(t, content)

	ips, domains, err := ReadPolicy(tmpFile)
	if err != nil {
		t.Fatalf("ReadPolicy() = %v, want nil", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}
}

func testReadPolicyInvalidIP(t *testing.T) {
	t.Helper()

	content := `allowlist:
  ips:
    - "invalid-ip"
  domains:
    - "example.com"
`
	tmpFile := createTempFile(t, content)

	_, _, err := ReadPolicy(tmpFile)
	if err == nil {
		t.Error("ReadPolicy() = nil, want error for invalid IP")
	}
}

func testReadPolicyInvalidDomain(t *testing.T) {
	t.Helper()

	content := `allowlist:
  ips:
    - "192.168.1.1"
  domains:
    - "invalid..domain"
`
	tmpFile := createTempFile(t, content)

	_, _, err := ReadPolicy(tmpFile)
	if err == nil {
		t.Error("ReadPolicy() = nil, want error for invalid domain")
	}
}

func testReadPolicyEmptyLists(t *testing.T) {
	t.Helper()

	tmpFile := createTempFile(t, testEmptyPolicy)

	ips, domains, err := ReadPolicy(tmpFile)
	if err != nil {
		t.Fatalf("ReadPolicy() = %v, want nil", err)
	}

	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(ips))
	}

	if len(domains) != 0 {
		t.Errorf("Expected 0 domains, got %d", len(domains))
	}
}

func TestValidateIPs(t *testing.T) {
	t.Parallel()

	tests := getValidateSliceTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var testData []string

			switch tt.name {
			case "valid IPs":
				testData = []string{"192.168.1.1", "10.0.0.0/8"}
			case "mixed with empty strings":
				testData = []string{"192.168.1.1", "", "10.0.0.0/8", "  "}
			case "invalid IP":
				testData = []string{"192.168.1.1", "invalid-ip"}
			default:
				testData = []string{}
			}

			result, err := validateIPs(slog.Default(), "test.yaml", testData)
			validateSliceResult(t, "validateIPs", result, err, tt.wantErr, tt.expected)
		})
	}
}

func TestValidateDomains(t *testing.T) {
	t.Parallel()

	tests := getValidateSliceTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var testData []string

			switch tt.name {
			case "valid IPs":
				testData = []string{"example.com", "*.google.com"}
			case "mixed with empty strings":
				testData = []string{"example.com", "", "*.google.com", "  "}
			case "invalid IP":
				testData = []string{"example.com", "invalid..domain"}
			default:
				testData = []string{}
			}

			result, err := validateDomains(slog.Default(), "test.yaml", testData)
			validateSliceResult(t, "validateDomains", result, err, tt.wantErr, tt.expected)
		})
	}
}

// getValidateSliceTests returns common test cases for slice validation functions.
func getValidateSliceTests() []struct {
	name     string
	wantErr  bool
	expected int
} {
	return []struct {
		name     string
		wantErr  bool
		expected int
	}{
		{
			name:     "valid IPs",
			wantErr:  false,
			expected: 2,
		},
		{
			name:     "mixed with empty strings",
			wantErr:  false,
			expected: 2,
		},
		{
			name:    "invalid IP",
			wantErr: true,
		},
		{
			name:     "empty slice",
			wantErr:  false,
			expected: 0,
		},
	}
}

// validateSliceResult is a helper function to validate slice test results.
func validateSliceResult(t *testing.T, funcName string, result []string, err error, wantErr bool, expected int) {
	t.Helper()

	if wantErr {
		if err == nil {
			t.Errorf("%s() = nil, want error", funcName)
		}
	} else {
		if err != nil {
			t.Errorf("%s() = %v, want nil", funcName, err)
		}

		if len(result) != expected {
			t.Errorf("%s() returned %d items, want %d", funcName, len(result), expected)
		}
	}
}

// createTempFile creates a temporary file with the given content for testing.
func createTempFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-policy.yaml")

	err := os.WriteFile(tmpFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	return tmpFile
}

func TestLoadFromEnv(t *testing.T) {
	t.Parallel()

	tests := getLoadFromEnvTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := loadFromEnv(slog.Default(), tt.envIPs, tt.envDomains, "", "")

			if tt.wantErr {
				if err == nil {
					t.Errorf("loadFromEnv() = nil, want error")
				}

				return
			}

			if err != nil {
				t.Errorf("loadFromEnv() = %v, want nil", err)

				return
			}

			if !stringSlicesEqual(pol.AllowIPs, tt.expectedIPs) {
				t.Errorf("loadFromEnv() IPs = %v, want %v", pol.AllowIPs, tt.expectedIPs)
			}

			if !stringSlicesEqual(pol.AllowDomains, tt.expectedDomains) {
				t.Errorf("loadFromEnv() domains = %v, want %v", pol.AllowDomains, tt.expectedDomains)
			}
		})
	}
}

type envTestCase struct {
	name            string
	envIPs          string
	envDomains      string
	expectedIPs     []string
	expectedDomains []string
	wantErr         bool
}

func getLoadFromEnvTests() []envTestCase {
	return []envTestCase{
		{"Both IPs and domains", "1.1.1.1,8.8.8.8", "google.com,*.github.com",
			[]string{"1.1.1.1", "8.8.8.8"}, []string{"google.com", "*.github.com"}, false},
		{"Only IPs", "192.168.1.0/24,10.0.0.1", "",
			[]string{"192.168.1.0/24", "10.0.0.1"}, nil, false},
		{"Only domains", "", "example.com,*.cloudflare.com",
			nil, []string{"example.com", "*.cloudflare.com"}, false},
		{"Empty values", "", "", nil, nil, false},
		{"Whitespace trimming", " 1.1.1.1 , 8.8.8.8 ", " google.com , *.github.com ",
			[]string{"1.1.1.1", "8.8.8.8"}, []string{"google.com", "*.github.com"}, false},
		{"Skip empty entries", "1.1.1.1,,8.8.8.8", "google.com,,*.github.com",
			[]string{"1.1.1.1", "8.8.8.8"}, []string{"google.com", "*.github.com"}, false},
		{"Invalid IP", "1.1.1.1,invalid-ip", "google.com", nil, nil, true},
		{"Invalid domain", "1.1.1.1", "google.com,invalid domain with spaces", nil, nil, true},
	}
}

func TestReadPolicyWithEnvVars(t *testing.T) {
	tests := getReadPolicyWithEnvVarsTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			t.Setenv("ALLOWLIST_IPS", tt.envIPs)
			t.Setenv("ALLOWLIST_DOMAINS", tt.envDomains)

			// Create temp policy file
			tmpFile := createTempFile(t, tt.policyContent)

			ips, domains, err := ReadPolicy(tmpFile)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ReadPolicy() = nil, want error")
				}

				return
			}

			if err != nil {
				t.Errorf("ReadPolicy() = %v, want nil", err)

				return
			}

			if !stringSlicesEqual(ips, tt.expectedIPs) {
				t.Errorf("ReadPolicy() IPs = %v, want %v", ips, tt.expectedIPs)
			}

			if !stringSlicesEqual(domains, tt.expectedDomains) {
				t.Errorf("ReadPolicy() domains = %v, want %v", domains, tt.expectedDomains)
			}
		})
	}
} // policyTestCase defines test case structure for ReadPolicy with environment variables.
type policyTestCase struct {
	name            string
	envIPs          string
	envDomains      string
	policyContent   string
	expectedIPs     []string
	expectedDomains []string
	wantErr         bool
}

func getReadPolicyWithEnvVarsTests() []policyTestCase {
	filePolicy := `allowlist:
  ips:
    - "192.168.1.1"
  domains:
    - "file.example.com"`

	return []policyTestCase{
		{
			"Env vars take precedence over file", "1.1.1.1", "env.example.com",
			filePolicy, []string{"1.1.1.1"}, []string{"env.example.com"}, false,
		},
		{
			"Fall back to file when env vars empty", "", "",
			filePolicy, []string{"192.168.1.1"}, []string{"file.example.com"}, false,
		},
		{
			"Only IP env var set", "1.1.1.1,8.8.8.8", "",
			filePolicy, []string{"1.1.1.1", "8.8.8.8"}, nil, false,
		},
		{
			"Only domain env var set", "", "env.example.com,*.github.com",
			filePolicy, nil, []string{"env.example.com", "*.github.com"}, false,
		},
	}
}

// stringSlicesEqual compares two string slices for equality, handling nil cases.
func stringSlicesEqual(a, b []string) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

//nolint:cyclop,dupl,gosec,funlen,noinlineerr // Test function with setup/teardown patterns
func TestAppendDomain(t *testing.T) {
	t.Parallel()

	t.Run("appends new domain to policy file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		initialPolicy := `allowlist:
  ips: []
  domains:
    - example.com
`
		if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendDomain(policyFile, "newdomain.com")
		if err != nil {
			t.Fatalf("AppendDomain failed: %v", err)
		}

		// Read back and verify
		ips, domains, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(domains) != 2 {
			t.Errorf("Got %d domains, want 2", len(domains))
		}

		found := slices.Contains(domains, "newdomain.com")

		if !found {
			t.Errorf("newdomain.com not found in domains: %v", domains)
		}

		if len(ips) != 0 {
			t.Errorf("Got %d IPs, want 0", len(ips))
		}
	})

	t.Run("skips duplicate domain", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		initialPolicy := `allowlist:
  ips: []
  domains:
    - example.com
`
		if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendDomain(policyFile, "example.com")
		if err != nil {
			t.Fatalf("AppendDomain failed: %v", err)
		}

		// Read back and verify no duplicate
		_, domains, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(domains) != 1 {
			t.Errorf("Got %d domains, want 1 (no duplicate)", len(domains))
		}
	})

	t.Run("validates domain before appending", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		if err := os.WriteFile(policyFile, []byte(testEmptyPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendDomain(policyFile, "invalid..domain")
		if err == nil {
			t.Error("AppendDomain should fail for invalid domain")
		}
	})

	t.Run("rejects empty domain", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		err := AppendDomain(policyFile, "")
		if err == nil {
			t.Error("AppendDomain should fail for empty domain")
		}
	})
}

//nolint:gocognit,dupl,gosec,cyclop,noinlineerr,funlen // Test function with setup/teardown patterns
func TestAppendIP(t *testing.T) {
	t.Parallel()

	t.Run("appends new IP to policy file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		initialPolicy := `allowlist:
  ips:
    - 192.168.1.1
  domains: []
`
		if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendIP(policyFile, "10.0.0.1")
		if err != nil {
			t.Fatalf("AppendIP failed: %v", err)
		}

		// Read back and verify
		ips, domains, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(ips) != 2 {
			t.Errorf("Got %d IPs, want 2", len(ips))
		}

		found := slices.Contains(ips, "10.0.0.1")

		if !found {
			t.Errorf("10.0.0.1 not found in IPs: %v", ips)
		}

		if len(domains) != 0 {
			t.Errorf("Got %d domains, want 0", len(domains))
		}
	})

	t.Run("appends CIDR to policy file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		if err := os.WriteFile(policyFile, []byte(testEmptyPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendIP(policyFile, "10.0.0.0/24")
		if err != nil {
			t.Fatalf("AppendIP failed: %v", err)
		}

		ips, _, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(ips) != 1 || ips[0] != "10.0.0.0/24" {
			t.Errorf("Got IPs %v, want [10.0.0.0/24]", ips)
		}
	})

	t.Run("skips duplicate IP", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		initialPolicy := `allowlist:
  ips:
    - 192.168.1.1
  domains: []
`
		if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendIP(policyFile, "192.168.1.1")
		if err != nil {
			t.Fatalf("AppendIP failed: %v", err)
		}

		ips, _, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(ips) != 1 {
			t.Errorf("Got %d IPs, want 1 (no duplicate)", len(ips))
		}
	})

	t.Run("validates IP before appending", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		if err := os.WriteFile(policyFile, []byte(testEmptyPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendIP(policyFile, "invalid-ip")
		if err == nil {
			t.Error("AppendIP should fail for invalid IP")
		}
	})

	t.Run("rejects empty IP", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		err := AppendIP(policyFile, "")
		if err == nil {
			t.Error("AppendIP should fail for empty IP")
		}
	})

	t.Run("accepts IPv6", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy.yaml")

		if err := os.WriteFile(policyFile, []byte(testEmptyPolicy), 0o644); err != nil {
			t.Fatalf("Failed to write initial policy: %v", err)
		}

		err := AppendIP(policyFile, "2001:db8::1")
		if err != nil {
			t.Fatalf("AppendIP should accept IPv6: %v", err)
		}

		ips, _, err := ReadPolicy(policyFile)
		if err != nil {
			t.Fatalf("ReadPolicy failed: %v", err)
		}

		if len(ips) != 1 || ips[0] != "2001:db8::1" {
			t.Errorf("Got IPs %v, want [2001:db8::1]", ips)
		}
	})
}
