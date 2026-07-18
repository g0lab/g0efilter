//nolint:testpackage // Need access to internal implementation details
package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDomainRegexPatterns(t *testing.T) {
	t.Parallel()

	valid := []string{
		`/^gitea-pull-through-cache\.\w+\.r2\.cloudflarestorage\.com$/`,
		`/^subdomain\.\w+\.domain\.com$/`,
		`/api-[0-9]+\.example\.com/`,
	}
	for _, p := range valid {
		err := validateDomain(p)
		if err != nil {
			t.Errorf("validateDomain(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		`/[unclosed/`,
		`/(?P<bad/`,
		`//`,                                  // empty is not a regex pattern (len <= 2)
		`/` + strings.Repeat("a", 2000) + `/`, // over length cap
	}
	for _, p := range invalid {
		err := validateDomain(p)
		if err == nil {
			t.Errorf("validateDomain(%q) = nil, want error", p)
		}
	}
}

func TestCompileDomainPatternAnchorsAndCase(t *testing.T) {
	t.Parallel()

	re, err := CompileDomainPattern(`/sub\.\w+\.example\.com/`)
	if err != nil {
		t.Fatalf("CompileDomainPattern: %v", err)
	}

	if !re.MatchString("sub.abc.example.com") {
		t.Error("expected match for sub.abc.example.com")
	}

	if !re.MatchString("SUB.ABC.EXAMPLE.COM") {
		t.Error("expected case-insensitive match")
	}

	// Anchored: substring matches must not pass
	if re.MatchString("evil-sub.abc.example.com") {
		t.Error("unanchored prefix must not match")
	}

	if re.MatchString("sub.abc.example.com.attacker.net") {
		t.Error("unanchored suffix must not match")
	}
}

func TestReadPolicyDefaultActionAndDenylist(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	content := `default_action: allow
allowlist:
  ips:
    - "1.1.1.1"
  domains:
    - "github.com"
denylist:
  ips:
    - "10.0.0.0/8"
  domains:
    - "*.doubleclick.net"
    - '/^tracker-\w+\.example\.com$/'
`

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	pol, err := Read(file)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if pol.DefaultAction != DefaultActionAllow {
		t.Errorf("DefaultAction = %q, want allow", pol.DefaultAction)
	}

	if len(pol.DenyIPs) != 1 || pol.DenyIPs[0] != "10.0.0.0/8" {
		t.Errorf("DenyIPs = %v", pol.DenyIPs)
	}

	if len(pol.DenyDomains) != 2 {
		t.Errorf("DenyDomains = %v", pol.DenyDomains)
	}
}

func TestReadPolicyInvalidDefaultAction(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	content := "default_action: maybe\nallowlist:\n  domains:\n    - github.com\n"

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Read(file)
	if err == nil {
		t.Error("Read() = nil, want error for invalid default_action")
	}
}

func TestReadPolicyInvalidDenylistEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	content := "allowlist:\n  domains:\n    - github.com\ndenylist:\n  ips:\n    - not-an-ip\n"

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Read(file)
	if err == nil {
		t.Error("Read() = nil, want error for invalid denylist IP")
	}
}

func TestReadPolicyDenylistFromEnv(t *testing.T) {
	t.Setenv("ALLOWLIST_IPS", "")
	t.Setenv("ALLOWLIST_DOMAINS", "github.com")
	t.Setenv("DENYLIST_IPS", "192.168.0.0/16")
	t.Setenv("DENYLIST_DOMAINS", "*.ads.example.com")

	pol, err := Read("nonexistent.yaml")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(pol.AllowDomains) != 1 || pol.AllowDomains[0] != "github.com" {
		t.Errorf("AllowDomains = %v", pol.AllowDomains)
	}

	if len(pol.DenyIPs) != 1 || pol.DenyIPs[0] != "192.168.0.0/16" {
		t.Errorf("DenyIPs = %v", pol.DenyIPs)
	}

	if len(pol.DenyDomains) != 1 || pol.DenyDomains[0] != "*.ads.example.com" {
		t.Errorf("DenyDomains = %v", pol.DenyDomains)
	}
}

// AppendDomain rewrites the whole file, so it must preserve default_action and denylist.
func TestAppendDomainPreservesNewFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	content := `default_action: allow
allowlist:
  domains:
    - "github.com"
denylist:
  domains:
    - "*.doubleclick.net"
`

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = AppendDomain(file, "example.org")
	if err != nil {
		t.Fatalf("AppendDomain: %v", err)
	}

	pol, err := Read(file)
	if err != nil {
		t.Fatalf("Read after append: %v", err)
	}

	if pol.DefaultAction != DefaultActionAllow {
		t.Errorf("DefaultAction lost on append: %q", pol.DefaultAction)
	}

	if len(pol.DenyDomains) != 1 {
		t.Errorf("DenyDomains lost on append: %v", pol.DenyDomains)
	}

	if len(pol.AllowDomains) != 2 {
		t.Errorf("AllowDomains = %v, want 2 entries", pol.AllowDomains)
	}
}

// A plain allowlist-only file must not gain default_action/denylist keys on append.
func TestAppendDomainDoesNotAddNewFieldsToPlainFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(file, []byte("allowlist:\n  domains:\n    - github.com\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = AppendDomain(file, "example.org")
	if err != nil {
		t.Fatalf("AppendDomain: %v", err)
	}

	data, readErr := os.ReadFile(file) //nolint:gosec // t.TempDir path
	if readErr != nil {
		t.Fatal(readErr)
	}

	if strings.Contains(string(data), "default_action") || strings.Contains(string(data), "denylist") {
		t.Errorf("plain policy gained unexpected keys:\n%s", data)
	}
}

func TestAppendRegexDomain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(file, []byte("allowlist:\n  domains:\n    - github.com\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = AppendDomain(file, `/^cache\.\w+\.example\.com$/`)
	if err != nil {
		t.Fatalf("AppendDomain regex: %v", err)
	}

	pol, err := Read(file)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(pol.AllowDomains) != 2 {
		t.Errorf("AllowDomains = %v", pol.AllowDomains)
	}
}

func TestValidateDomainMidNameWildcards(t *testing.T) {
	t.Parallel()

	valid := []string{
		"sub.*.sub.domain.com",
		"gitea-pull-through-cache.*.r2.cloudflarestorage.com",
		"*.foo.*.com",
		"telemetry.*.example.com",
		"sub.*", // trailing wildcard - symmetric with a leading *.com being valid
	}
	for _, p := range valid {
		err := validateDomain(p)
		if err != nil {
			t.Errorf("validateDomain(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"sub.**.domain.com",    // consecutive wildcards
		"sub*domain",           // no dot at all
		"sub.*..domain.com",    // double dot
		"sub.*_bad.domain.com", // invalid characters
		".*.domain.com",        // leading dot
	}
	for _, p := range invalid {
		err := validateDomain(p)
		if err == nil {
			t.Errorf("validateDomain(%q) = nil, want error", p)
		}
	}
}

func TestCompileWildcardPattern(t *testing.T) {
	t.Parallel()

	re, err := CompileWildcardPattern("sub.*.domain.com")
	if err != nil {
		t.Fatalf("CompileWildcardPattern: %v", err)
	}

	if !re.MatchString("sub.x.domain.com") || !re.MatchString("sub.a.b.domain.com") {
		t.Error("wildcard must span one or more labels")
	}

	if re.MatchString("sub.domain.com") {
		t.Error("wildcard requires at least one character")
	}

	if re.MatchString("evil-sub.x.domain.com") || re.MatchString("sub.x.domain.com.evil.net") {
		t.Error("pattern must be anchored")
	}

	if !re.MatchString("SUB.X.DOMAIN.COM") {
		t.Error("match must be case-insensitive")
	}
}
