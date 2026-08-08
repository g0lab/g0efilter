//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"strings"
	"testing"
	"unicode"
)

func hostSeeds(f *testing.F) {
	f.Helper()

	for _, seed := range []string{
		"example.com", "EXAMPLE.COM", "example.com.", "sub.example.com",
		"xn--nxasmq6b.example", "localhost", "1.2.3.4", "[::1]", "::1",
		"", ".", "..", "a..b", "-a.example.com", "a-.example.com",
		"example.com:443", "example.com/path", "exa mple.com", "example.com\r\n",
		"a@example.com", strings.Repeat("a", 300), strings.Repeat("a.", 200) + "com",
		"\x00example.com", "exa\tmple.com", "example.123",
	} {
		f.Add(seed)
	}
}

// sanitizeHost is the boundary between an attacker-controlled Host header or SNI
// and every policy decision that follows, so what it accepts has to be a name the
// matcher can reason about - and re-sanitising it must change nothing.
func FuzzSanitizeHost(f *testing.F) {
	hostSeeds(f)

	f.Fuzz(func(t *testing.T, host string) {
		clean, ok := sanitizeHost(host)
		if !ok {
			if clean != "" {
				t.Fatalf("rejected %q but returned %q", host, clean)
			}

			return
		}

		assertSanitisedHost(t, host, clean)

		again, ok := sanitizeHost(clean)
		if !ok {
			t.Fatalf("%q sanitised to %q, which is then rejected", host, clean)
		}

		if again != clean {
			t.Fatalf("not idempotent: %q -> %q -> %q", host, clean, again)
		}
	})
}

func assertSanitisedHost(t *testing.T, host, clean string) {
	t.Helper()

	if clean == "" {
		t.Fatalf("accepted %q but returned an empty host", host)
	}

	if len(clean) > maxHostLength {
		t.Fatalf("accepted %q as a %d-byte host", host, len(clean))
	}

	if clean != strings.ToLower(clean) {
		t.Fatalf("accepted %q without lowercasing: %q", host, clean)
	}

	// Anything below is either a matcher-confusing separator or a control byte
	// that would end up in a log line.
	for _, r := range clean {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("accepted %q with a control character: %q", host, clean)
		}

		if unicode.IsSpace(r) {
			t.Fatalf("accepted %q with whitespace: %q", host, clean)
		}
	}

	for _, bad := range []string{"..", "/", "@", ":", "?", "#", "\\", "%"} {
		if strings.Contains(clean, bad) {
			t.Fatalf("accepted %q containing %q: %q", host, bad, clean)
		}
	}
}

// A qname reaches the same policy check as a Host header, by a different route.
func FuzzSanitizeDNSQname(f *testing.F) {
	hostSeeds(f)
	f.Add("_dmarc.example.com.")
	f.Add("*.example.com.")
	f.Add(strings.Repeat("a", 64) + ".example.com.")

	f.Fuzz(func(t *testing.T, qname string) {
		clean, ok := sanitizeDNSQname(qname)
		if !ok {
			if clean != "" {
				t.Fatalf("rejected %q but returned %q", qname, clean)
			}

			return
		}

		if clean == "" {
			t.Fatalf("accepted %q but returned an empty name", qname)
		}

		if clean != strings.ToLower(clean) {
			t.Fatalf("accepted %q without lowercasing: %q", qname, clean)
		}

		if strings.HasSuffix(clean, ".") {
			t.Fatalf("accepted %q leaving the root label: %q", qname, clean)
		}

		for label := range strings.SplitSeq(clean, ".") {
			if len(label) > maxLabelLength {
				t.Fatalf("accepted %q with a %d-byte label", qname, len(label))
			}
		}

		again, ok := sanitizeDNSQname(clean)
		if !ok {
			t.Fatalf("%q sanitised to %q, which is then rejected", qname, clean)
		}

		if again != clean {
			t.Fatalf("not idempotent: %q -> %q -> %q", qname, clean, again)
		}
	})
}
