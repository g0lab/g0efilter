package policy_test

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

// A rule that parses is one the filter will enforce, so anything it accepts has to
// be a destination the filter can actually express.
func FuzzParseIPPortRule(f *testing.F) {
	for _, seed := range []string{
		"1.2.3.4", "10.0.0.0/8", "tcp/1.2.3.4:443", "udp/[::1]:53",
		"1.2.3.4:0", "1.2.3.4:65536", "sctp/1.2.3.4:443", "tcp/1.2.3.4",
		"::1", "2001:db8::/32", "", " ", ":", "/", "1.2.3.4:443:443",
		"[:: ]", "0.0.0.0 :1", " 1.2.3.4 ",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, entry string) {
		rule, err := policy.ParseIPPortRule(entry)
		if err != nil {
			return
		}

		assertAddress(t, entry, rule.Addr)
		assertConstraint(t, entry, rule.Proto, rule.Port)

		if rule.Constrained() != (rule.Port != 0) {
			t.Fatalf("%q: Constrained()=%v with port %d", entry, rule.Constrained(), rule.Port)
		}
	})
}

func assertAddress(t *testing.T, entry, addr string) {
	t.Helper()

	if addr == "" {
		t.Fatalf("%q parsed to an empty address", entry)
	}

	_, _, err := net.ParseCIDR(addr)
	if err != nil && net.ParseIP(addr) == nil {
		t.Fatalf("%q parsed to %q, which is neither an IP nor a CIDR", entry, addr)
	}
}

func assertConstraint(t *testing.T, entry, proto string, port int) {
	t.Helper()

	if proto != "" && proto != policy.ProtoTCP && proto != policy.ProtoUDP {
		t.Fatalf("%q parsed to protocol %q", entry, proto)
	}

	if port < 0 || port > 65535 {
		t.Fatalf("%q parsed to port %d", entry, port)
	}

	// A protocol without a port would constrain nothing while looking like it does.
	if proto != "" && port == 0 {
		t.Fatalf("%q parsed to protocol %q with no port", entry, proto)
	}
}

func FuzzParseDomainRule(f *testing.F) {
	for _, seed := range []string{
		"example.com", "*.example.com", "tcp/example.com:443", "udp/a.example.com:53",
		`/^api\.example\.com$/`, `/^a:b$/`, "example.com:0", "example.com:99999",
		"*", "", ".", "..", "a..b", "xn--nxasmq6b.example", "EXAMPLE.COM",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, entry string) {
		rule, err := policy.ParseDomainRule(entry)
		if err != nil {
			return
		}

		if rule.Pattern == "" {
			t.Fatalf("%q parsed to an empty pattern", entry)
		}

		assertConstraint(t, entry, rule.Proto, rule.Port)

		// The port constraint must not have been folded into the matched pattern, or
		// the rule would match a different set of hosts than it names.
		if strings.HasSuffix(rule.Pattern, ":") {
			t.Fatalf("%q left a trailing colon in the pattern %q", entry, rule.Pattern)
		}
	})
}

// An accepted pattern must be anchored: an unanchored regex would match any host
// that merely contains the pattern, which silently widens the allowlist.
func FuzzCompileDomainPattern(f *testing.F) {
	for _, seed := range []string{
		"example.com", "*.example.com", "sub.*.example.com", `/^api\.example\.com$/`,
		"/a/", "//", "/(/", `/(?i)EXAMPLE\.com/`, "*", "*.*", "a*b.example.com",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		re, err := policy.CompileDomainPattern(pattern)
		if err != nil {
			return
		}

		if re == nil {
			t.Fatalf("%q compiled to a nil expression", pattern)
		}

		if !policy.IsRegexPattern(pattern) {
			source := re.String()
			if !strings.HasPrefix(source, "^") || !strings.HasSuffix(source, "$") {
				t.Fatalf("wildcard %q compiled to the unanchored %q", pattern, source)
			}
		}

		// Compiling twice must agree; the matcher caches compiled patterns.
		again, err := policy.CompileDomainPattern(pattern)
		if err != nil {
			t.Fatalf("%q compiled once but not twice: %v", pattern, err)
		}

		if again.String() != re.String() {
			t.Fatalf("%q compiled to %q then %q", pattern, re.String(), again.String())
		}
	})
}

// A policy file is attacker-adjacent: it may be rendered by the controller from a
// custom resource. Anything Read accepts is enforced, so it must be well formed.
func FuzzReadPolicy(f *testing.F) {
	for _, seed := range []string{
		"allowlist:\n  domains:\n    - 'example.com'\n  ips:\n    - '1.2.3.4'\n",
		"allowlist:\n  domains: []\n  ips: []\n",
		"allowlist:\n  domains:\n    - '*'\n",
		"allowlist:\n  ips:\n    - '10.0.0.0/8'\n",
		"default_action: deny\nallowlist:\n  domains:\n    - 'a.example.com'\n",
		"denylist:\n  domains:\n    - 'bad.example.com'\n",
		"", "{", "allowlist: 3\n", "allowlist:\n  domains: 'notalist'\n",
	} {
		f.Add(seed)
	}

	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, document string) {
		file := filepath.Join(dir, "policy.yaml")

		err := os.WriteFile(file, []byte(document), 0o600)
		if err != nil {
			t.Fatalf("write policy: %v", err)
		}

		loaded, err := policy.Read(file)
		if err != nil {
			return
		}

		if loaded == nil {
			t.Fatal("Read returned no policy and no error")
		}

		for _, domain := range loaded.AllowDomains {
			_, ruleErr := policy.ParseDomainRule(domain)
			if ruleErr != nil {
				t.Fatalf("loaded domain %q does not parse as a rule: %v", domain, ruleErr)
			}
		}

		for _, ip := range loaded.AllowIPs {
			_, ruleErr := policy.ParseIPPortRule(ip)
			if ruleErr != nil {
				t.Fatalf("loaded ip %q does not parse as a rule: %v", ip, ruleErr)
			}
		}
	})
}
