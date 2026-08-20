//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

func TestLearnerFlushAppendsToPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(file, []byte("allowlist:\n  domains:\n    - github.com\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	l := newLearner(file, slog.New(slog.DiscardHandler))

	l.record("domain", "new.example.com")
	l.record("domain", "new.example.com") // dedup
	l.record("ip", "9.9.9.9")
	l.record("domain", "")
	l.flush()

	pol, err := policy.Read(file)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(pol.AllowDomains) != 2 {
		t.Errorf("AllowDomains = %v, want github.com + new.example.com", pol.AllowDomains)
	}

	if len(pol.AllowIPs) != 1 || pol.AllowIPs[0] != "9.9.9.9" {
		t.Errorf("AllowIPs = %v, want [9.9.9.9]", pol.AllowIPs)
	}

	// A second flush with nothing pending must not duplicate entries
	l.flush()
	l.record("domain", "new.example.com")
	l.flush()

	pol, err = policy.Read(file)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(pol.AllowDomains) != 2 {
		t.Errorf("AllowDomains after re-record = %v, want no duplicates", pol.AllowDomains)
	}
}

func TestLearnerInvalidValuesDoNotCorruptPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(file, []byte("allowlist:\n  domains:\n    - github.com\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	l := newLearner(file, slog.New(slog.DiscardHandler))

	l.record("domain", "not a domain!!")
	l.record("ip", "999.999.999.999")
	l.flush()

	pol, err := policy.Read(file)
	if err != nil {
		t.Fatalf("policy must still parse: %v", err)
	}

	if len(pol.AllowDomains) != 1 || len(pol.AllowIPs) != 0 {
		t.Errorf("invalid values must be rejected, got domains=%v ips=%v", pol.AllowDomains, pol.AllowIPs)
	}
}

func TestLearnerSeenCap(t *testing.T) {
	t.Parallel()

	l := newLearner(filepath.Join(t.TempDir(), "policy.yaml"), slog.New(slog.DiscardHandler))

	for i := range learnerMaxSeen + 50 {
		l.record("domain", "host-"+strconv.Itoa(i)+".example.com")
	}

	if len(l.seen) != learnerMaxSeen {
		t.Errorf("seen = %d entries, want capped at %d", len(l.seen), learnerMaxSeen)
	}

	if len(l.pending) != learnerMaxSeen {
		t.Errorf("pending = %d entries, want capped at %d", len(l.pending), learnerMaxSeen)
	}
}

func TestEffectiveDefaultAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		envAction  string
		fileAction string
		want       bool
	}{
		{"env deny, file unset", "deny", "", false},
		{"env allow, file unset", "allow", "", true},
		{"env deny, file allow wins", "deny", "allow", true},
		{"env allow, file deny wins", "allow", "deny", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config{defaultAction: tt.envAction}
			pol := &policy.Policy{DefaultAction: tt.fileAction}

			if got := effectiveDefaultAllow(cfg, pol); got != tt.want {
				t.Errorf("effectiveDefaultAllow = %v, want %v", got, tt.want)
			}
		})
	}
}
