//nolint:testpackage // Need access to internal implementation details
package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		// Valid cases
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 with whitespace", "  192.168.1.1  ", false},
		{"valid CIDR", "192.168.1.0/24", false},
		{"valid single IP CIDR", "192.168.1.1/32", false},
		{"valid large subnet", "10.0.0.0/8", false},

		// Invalid cases
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"IPv6 address", "2001:db8::1", true},
		{"IPv6 CIDR", "2001:db8::/32", true},
		{"invalid IP", "999.999.999.999", true},
		{"hostname", "example.com", true},
		{"IP with port", "192.168.1.1:80", true},
		{"invalid CIDR", "192.168.1.0/99", true},
		{"partial IP", "192.168.1", true},
		{"non-numeric", "not.an.ip.address", true},
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
		{"wildcard in middle", "ex*ample.com", true},
		{"wildcard at end", "example.com*", true},
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

	content := `allowlist:
  ips: []
  domains: []
`
	tmpFile := createTempFile(t, content)

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

			result, err := validateIPs(nil, "test.yaml", testData)
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

			result, err := validateDomains(nil, "test.yaml", testData)
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
