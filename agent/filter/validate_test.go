//nolint:testpackage // Internal testing required
package filter

import "testing"

const (
	domain254Chars = "aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddddd.eeeeeeeeee.ffffffffff." +
		"gggggggggg.hhhhhhhhhh.iiiiiiiiii.jjjjjjjjjj.kkkkkkkkkk.llllllllll." +
		"mmmmmmmmmm.nnnnnnnnnn.oooooooooo.pppppppppp.qqqqqqqqqq.rrrrrrrrrr." +
		"ssssssssss.tttttttttt.uuuuuuuuuu.vvvvvvvvvv.wwwwwwwwww.xxxxxxxxxx.yyyy"
)

//nolint:funlen // Test table requires comprehensive valid cases
func TestSanitizeHostValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantHost string
	}{
		{
			name:     "valid domain",
			input:    "example.com",
			wantHost: "example.com",
		},
		{
			name:     "valid subdomain",
			input:    "api.example.com",
			wantHost: "api.example.com",
		},
		{
			name:     "valid deep subdomain",
			input:    "api.v1.staging.example.com",
			wantHost: "api.v1.staging.example.com",
		},
		{
			name:     "valid with hyphens",
			input:    "my-api.my-site.com",
			wantHost: "my-api.my-site.com",
		},
		{
			name:     "valid with double hyphen (punycode-style)",
			input:    "xn--mnchen-3ya.de",
			wantHost: "xn--mnchen-3ya.de",
		},
		{
			name:     "valid with numbers",
			input:    "api1.example2.com",
			wantHost: "api1.example2.com",
		},
		{
			name:     "valid single char labels",
			input:    "a.b.c.com",
			wantHost: "a.b.c.com",
		},
		{
			name:     "valid max label length (63 chars)",
			input:    "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy.com",
			wantHost: "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy.com",
		},
		{
			name:     "shortest realistic domain (4 chars)",
			input:    "a.co",
			wantHost: "a.co",
		},
		{
			name:     "only numbers in label (valid)",
			input:    "123.456.com",
			wantHost: "123.456.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotHost, gotOK := sanitizeHost(tt.input)
			if gotHost != tt.wantHost || !gotOK {
				t.Errorf("sanitizeHost(%q) = (%q, %v), want (%q, true)",
					tt.input, gotHost, gotOK, tt.wantHost)
			}
		})
	}
}

func TestSanitizeHostInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		// Invalid cases - empty/length
		{name: "empty string", input: ""},
		{name: "too long (254 chars)", input: domain254Chars},
		{name: "label too long (64 chars)", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"},

		// Invalid cases - control characters
		{name: "null byte", input: "evil.com\x00"},
		{name: "newline", input: "evil.com\n"},
		{name: "carriage return", input: "evil.com\r"},
		{name: "tab", input: "evil.com\t"},
		{name: "space", input: "evil .com"},

		// Invalid cases - special characters
		{name: "slash", input: "evil.com/path"},
		{name: "backslash", input: "evil.com\\path"},
		{name: "question mark", input: "evil.com?query"},
		{name: "hash", input: "evil.com#anchor"},
		{name: "at symbol", input: "user@evil.com"},
		{name: "colon (port)", input: "evil.com:8080"},
		{name: "semicolon", input: "evil.com;"},
		{name: "underscore", input: "evil_site.com"},

		// Invalid cases - malformed structure
		{name: "leading dot", input: ".example.com"},
		{name: "trailing hyphen", input: "example-.com"},
		{name: "leading hyphen", input: "-example.com"},
		{name: "double dot", input: "example..com"},
		{name: "label starting with hyphen", input: "example.-bad.com"},
		{name: "label ending with hyphen", input: "example.bad-.com"},

		// Invalid cases - injection attempts
		{name: "path traversal", input: "../../../../etc/passwd"},
		{name: "script tag", input: "<script>alert(1)</script>"},
		{name: "sql injection", input: "evil.com'; DROP TABLE users--"},
		{name: "header injection", input: "evil.com\r\nX-Injected: header"},
		{name: "log injection", input: "evil.com\naction: ALLOWED\nhost: legitimate.com"},

		// Edge cases
		{name: "uppercase", input: "EXAMPLE.COM"},
		{name: "mixed case", input: "Example.Com"},
		{name: "single char TLD (unrealistic)", input: "example.c"},
		{name: "numeric TLD (invalid)", input: "example.123"},
		{name: "single label (no dot)", input: "localhost"},
		{name: "ip address (rejected - numeric TLD)", input: "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotHost, gotOK := sanitizeHost(tt.input)
			if gotHost != "" || gotOK {
				t.Errorf("sanitizeHost(%q) = (%q, %v), want (\"\", false)", tt.input, gotHost, gotOK)
			}
		})
	}
}

func TestIsValidDNSChar(t *testing.T) {
	t.Parallel()

	validChars := "abcdefghijklmnopqrstuvwxyz0123456789.-"
	for _, r := range validChars {
		if !isValidDNSChar(r) {
			t.Errorf("isValidDNSChar(%c) = false, want true", r)
		}
	}

	invalidChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ_!@#$%^&*()+=[]{}|\\;:'\",<>?/\n\r\t\x00 "
	for _, r := range invalidChars {
		if isValidDNSChar(r) {
			t.Errorf("isValidDNSChar(%c) = true, want false", r)
		}
	}
}

func TestIsValidLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		label string
		want  bool
	}{
		{"valid simple", "example", true},
		{"valid with number", "example123", true},
		{"valid with hyphen", "my-example", true},
		{"valid single char", "a", true},
		{"valid max length (63 chars)", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy", true},
		{"empty", "", false},
		{"too long (64 chars)", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"starts with hyphen", "-example", false},
		{"ends with hyphen", "example-", false},
		{"only hyphen", "-", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isValidLabel(tt.label); got != tt.want {
				t.Errorf("isValidLabel(%q) = %v, want %v", tt.label, got, tt.want)
			}
		})
	}
}

// Benchmark to ensure validation is fast.
func BenchmarkSanitizeHost(b *testing.B) {
	testCases := []string{
		"example.com",
		"api.staging.example.com",
		"very-long-subdomain-name.example.com",
		"invalid..domain",
		"evil.com\r\nX-Injected: header",
	}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for range b.N {
				_, _ = sanitizeHost(tc)
			}
		})
	}
}

// BenchmarkSanitizeHostWithLogger benchmarks validation with logger (but nil, so no actual logging).
func BenchmarkSanitizeHostWithLogger(b *testing.B) {
	testCases := []string{
		"example.com",
		"api.staging.example.com",
		"very-long-subdomain-name.example.com",
	}

	for _, tc := range testCases {
		b.Run(tc+"_no_logger", func(b *testing.B) {
			for range b.N {
				_, _ = sanitizeHostWithLogger(tc, nil, "")
			}
		})
	}
}

func TestSanitizeDNSQname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		qname string
		want  string
		ok    bool
	}{
		{"plain name", "github.com", "github.com", true},
		{"lowercased", "GitHub.COM", "github.com", true},
		{"underscore service label", "_dmarc.example.com", "_dmarc.example.com", true},
		{"srv-style name", "_ldap._tcp.example.com", "_ldap._tcp.example.com", true},
		{"single label", "localhost", "localhost", true},
		{"reverse lookup", "5.0.18.172.in-addr.arpa", "5.0.18.172.in-addr.arpa", true},
		{"empty", "", "", false},
		{"space", "bad name.example.com", "", false},
		{"empty label", "bad..example.com", "", false},
		{"label starts with hyphen", "-bad.example.com", "", false},
		{"too long", domain254Chars, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := sanitizeDNSQname(tt.qname)
			if got != tt.want || ok != tt.ok {
				t.Errorf("sanitizeDNSQname(%q) = (%q, %v), want (%q, %v)", tt.qname, got, ok, tt.want, tt.ok)
			}
		})
	}
}
