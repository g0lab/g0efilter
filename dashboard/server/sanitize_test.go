package server_test

import (
	"testing"

	"github.com/g0lab/g0efilter/dashboard/server"
)

func TestSanitizeDomainField(t *testing.T) {
	t.Parallel()

	tests := []domainFieldTest{
		{"Valid domain", "example.com", "example.com"},
		{"Valid subdomain", "api.example.com", "api.example.com"},
		{"Empty string", "", ""},
		{"CRLF injection attempt", "evil.com\r\nX-Injected: header", "[invalid]"},
		{"Newline injection", "evil.com\nmalicious", "[invalid]"},
		{"Null byte injection", "evil.com\x00", "[invalid]"},
		{"Tab character", "evil.com\tmalicious", "[invalid]"},
		{"Control characters", "evil\x01\x02.com", "[invalid]"},
		{"XSS attempt", "<script>alert(1)</script>", "[invalid]"},
		{"Double dots", "evil..com", "[invalid]"},
		{"Leading hyphen", "-evil.com", "[invalid]"},
		{"Leading dot", ".evil.com", "[invalid]"},
		{"Too long", string(make([]byte, 300)), "[invalid]"},
		{"Non-ASCII characters", "münchen.de", "[invalid]"},
		{"Valid with hyphen", "my-site.example.com", "my-site.example.com"},
		{"Valid with underscore", "my_site.example.com", "my_site.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := server.SanitizeDomainField(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeDomainField(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

type domainFieldTest struct {
	name     string
	input    string
	expected string
}

func TestSanitizePayloadFields(t *testing.T) {
	t.Parallel()

	t.Run("Sanitizes known domain fields", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"host":   "example.com\r\nX-Injected: header",
			"https":  "valid.com",
			"qname":  "evil\x00.com",
			"other":  "not-sanitized",
			"number": 123,
		}

		server.SanitizePayloadFields(payload)

		if payload["host"] != "[invalid]" {
			t.Errorf("Expected host to be sanitized, got %v", payload["host"])
		}

		if payload["https"] != "valid.com" {
			t.Errorf("Expected https to remain valid, got %v", payload["https"])
		}

		if payload["qname"] != "[invalid]" {
			t.Errorf("Expected qname to be sanitized, got %v", payload["qname"])
		}

		// Other fields should not be modified
		if payload["other"] != "not-sanitized" {
			t.Errorf("Expected other field to be unchanged, got %v", payload["other"])
		}

		if payload["number"] != 123 {
			t.Errorf("Expected number field to be unchanged, got %v", payload["number"])
		}
	})

	t.Run("Handles missing fields", func(t *testing.T) {
		t.Parallel()

		payload := map[string]any{
			"msg": "test message",
		}

		// Should not panic
		server.SanitizePayloadFields(payload)

		if len(payload) != 1 {
			t.Errorf("Expected payload to have 1 field, got %d", len(payload))
		}
	})
}

func TestSanitizeSearchQuery(t *testing.T) {
	t.Parallel()

	tests := []searchQueryTest{
		{"Valid query", "blocked", "blocked"},
		{"Valid query with space", "blocked example", "blocked example"},
		{"Empty query", "", ""},
		{"CRLF injection", "query\r\nX-Injected: header", ""},
		{"Newline injection", "query\nmalicious", ""},
		{"Null byte", "query\x00", ""},
		{"Control characters", "query\x01\x02", ""},
		{"XSS attempt", "<script>alert(1)</script>", ""},
		{"JavaScript protocol", "javascript:alert(1)", ""},
		{"Too long query", string(make([]byte, 300)), ""},
		{"Valid special characters", "example.com:443", "example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := server.SanitizeSearchQuery(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeSearchQuery(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

type searchQueryTest struct {
	name     string
	input    string
	expected string
}

func BenchmarkSanitizeDomainField(b *testing.B) {
	testCases := []string{
		"example.com",
		"api.staging.example.com",
		"evil.com\r\nX-Injected: header",
	}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for range b.N {
				_ = server.SanitizeDomainField(tc)
			}
		})
	}
}
