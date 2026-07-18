//nolint:testpackage // Testing internal functions
package alerting

import (
	"testing"
)

func TestLoadIgnoreList(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected []string
	}{
		{"No env var", "", nil},
		{"Empty env var", "", nil},
		{"Single domain", "google.com", []string{"google.com"}},
		{
			"Multiple domains",
			"google.com,*.facebook.com,example.org",
			[]string{"google.com", "*.facebook.com", "example.org"},
		},
		{
			"Lowercase normalization",
			"GOOGLE.COM,*.FACEBOOK.COM",
			[]string{"google.com", "*.facebook.com"},
		},
		{
			"Trim whitespace",
			" google.com , *.facebook.com , example.org ",
			[]string{"google.com", "*.facebook.com", "example.org"},
		},
		{
			"Skip empty entries",
			"google.com,,*.facebook.com",
			[]string{"google.com", "*.facebook.com"},
		},
		{
			"Skip invalid entries",
			"google.com,invalid domain,*.facebook.com",
			[]string{"google.com", "*.facebook.com"},
		},
		{"All whitespace", "   ", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("NOTIFICATION_IGNORE_DOMAINS", tt.envValue)
			}

			result := loadIgnoreList()
			validatePatterns(t, result, tt.expected)
		})
	}
}

func validatePatterns(t *testing.T, patterns, expected []string) {
	t.Helper()

	if expected == nil {
		if patterns != nil {
			t.Errorf("Expected nil patterns, got %v", patterns)
		}

		return
	}

	if len(patterns) != len(expected) {
		t.Fatalf("Expected %d patterns, got %d: %v", len(expected), len(patterns), patterns)
	}

	for i, exp := range expected {
		if patterns[i] != exp {
			t.Errorf("Pattern %d: expected %q, got %q", i, exp, patterns[i])
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	t.Parallel()

	tests := getMatchesPatternTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := matchesPattern(tt.destination, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v",
					tt.destination, tt.pattern, result, tt.expected)
			}
		})
	}
}

type patternTest struct {
	name        string
	destination string
	pattern     string
	expected    bool
}

func getMatchesPatternTests() []patternTest {
	return []patternTest{
		{"Exact match", "google.com", "google.com", true},
		{"No match", "google.com", "facebook.com", false},
		{"Wildcard matches subdomain", "api.facebook.com", "*.facebook.com", true},
		{"Wildcard matches nested subdomain", "api.v2.facebook.com", "*.facebook.com", true},
		{"Wildcard does not match base domain", "facebook.com", "*.facebook.com", false},
		{"Wildcard does not match different domain", "google.com", "*.facebook.com", false},
		{"Case insensitive (already normalized)", "google.com", "google.com", true},
		{"Wildcard with different suffix", "api.example.org", "*.example.com", false},
	}
}

func TestIsIgnored(t *testing.T) {
	t.Parallel()

	t.Run("Empty ignore list", func(t *testing.T) {
		t.Parallel()

		n := &Notifier{ignoreList: nil}
		if n.isIgnored("google.com") {
			t.Error("Expected false for empty ignore list")
		}
	})

	t.Run("Empty destination", func(t *testing.T) {
		t.Parallel()

		n := &Notifier{ignoreList: []string{"google.com"}}
		if n.isIgnored("") {
			t.Error("Expected false for empty destination")
		}
	})

	t.Run("Match in ignore list", func(t *testing.T) {
		t.Parallel()

		n := &Notifier{
			ignoreList: []string{"google.com", "*.facebook.com", "example.org"},
		}

		checkIgnoredDomains(t, n)
	})

	t.Run("Case insensitive matching", func(t *testing.T) {
		t.Parallel()

		n := &Notifier{
			ignoreList: []string{"google.com"}, // stored as lowercase
		}

		// Destination gets normalized in isIgnored
		if !n.isIgnored("GOOGLE.COM") {
			t.Error("Expected case-insensitive match for GOOGLE.COM")
		}

		if !n.isIgnored("Google.Com") {
			t.Error("Expected case-insensitive match for Google.Com")
		}
	})
}

func checkIgnoredDomains(t *testing.T, n *Notifier) {
	t.Helper()

	tests := []struct {
		destination string
		expected    bool
	}{
		{"google.com", true},
		{"example.org", true},
		{"api.facebook.com", true},
		{"www.facebook.com", true},
		{"facebook.com", false}, // wildcard doesn't match base
		{"twitter.com", false},
		{"google.org", false},
	}

	for _, tt := range tests {
		result := n.isIgnored(tt.destination)
		if result != tt.expected {
			t.Errorf("isIgnored(%q) = %v, want %v", tt.destination, result, tt.expected)
		}
	}
}

func TestNotifierWithIgnoreList(t *testing.T) {
	t.Run("Integration: ignored destination skips notification", func(t *testing.T) {
		t.Setenv("NOTIFICATION_IGNORE_DOMAINS", "google.com,*.facebook.com")
		t.Setenv("NOTIFICATION_HOST", "http://localhost:8080")
		t.Setenv("NOTIFICATION_KEY", "test-key")

		notifier := NewNotifier()
		if notifier == nil {
			t.Fatal("Expected notifier to be created")

			return
		}

		defer notifier.Close()

		// Verify ignore list was loaded
		if len(notifier.ignoreList) != 2 {
			t.Fatalf("Expected 2 patterns in ignore list, got %d", len(notifier.ignoreList))
		}

		// Test that ignored domains return true
		if !notifier.isIgnored("google.com") {
			t.Error("Expected google.com to be ignored")
		}

		if !notifier.isIgnored("api.facebook.com") {
			t.Error("Expected api.facebook.com to be ignored")
		}

		if notifier.isIgnored("twitter.com") {
			t.Error("Expected twitter.com NOT to be ignored")
		}
	})
}
