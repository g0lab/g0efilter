//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

func learningConfig(t *testing.T, policyPath string, learning bool) config {
	t.Helper()

	//nolint:exhaustruct // only the learning-mode fields matter here
	return config{policyPath: policyPath, learningMode: learning}
}

// Auto-creating a policy in an enforcing mode would turn a fail-closed startup
// error into a silently empty allowlist.
func TestSeedLearningPolicyOnlyRunsInLearningMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	cfg := setupLearning(t.Context(), learningConfig(t, path, false), slog.New(slog.DiscardHandler))

	_, err := os.Stat(path)
	if !os.IsNotExist(err) {
		t.Errorf("a policy file was created outside learning mode: %v", err)
	}

	if cfg.learner != nil {
		t.Error("a learner was started outside learning mode")
	}
}

func TestSetupLearningSeedsAWritablePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := setupLearning(ctx, learningConfig(t, path, true), slog.New(slog.DiscardHandler))

	if cfg.learner == nil {
		t.Fatal("learning mode did not start a learner")
	}

	pol, err := policy.Read(path)
	if err != nil {
		t.Fatalf("seeded policy is not loadable: %v", err)
	}

	if len(pol.AllowDomains) != 0 || len(pol.AllowIPs) != 0 {
		t.Errorf("seeded policy is not empty: %+v", pol)
	}
}

func TestSeedLearningPolicyNeverOverwrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	const existing = "allowlist:\n  domains:\n    - 'api.example.com'\n"

	err := os.WriteFile(path, []byte(existing), 0o600)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	seedLearningPolicy(path, slog.New(slog.DiscardHandler))

	got, err := os.ReadFile(path) //nolint:gosec // a path this test just created
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}

	if string(got) != existing {
		t.Errorf("existing policy was overwritten:\n%s", got)
	}
}

// The expected failure when learning is enabled without a writable volume.
func TestSeedLearningPolicySurvivesAnUnwritablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := os.Chmod(dir, 0o500) //nolint:gosec // a directory mode, and read-only is the point
	if err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restores the temp dir for cleanup

	path := filepath.Join(dir, "policy.yaml")

	seedLearningPolicy(path, slog.New(slog.DiscardHandler))

	// Root ignores the directory mode.
	if os.Geteuid() == 0 {
		return
	}

	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		t.Errorf("a policy was written to an unwritable directory: %v", err)
	}
}
