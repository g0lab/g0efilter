//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/metrics"
)

type recordedError struct {
	causes []error
}

func (r *recordedError) RecordPolicyError(_ context.Context, cause error) {
	r.causes = append(r.causes, cause)
}

func policyFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(path, []byte(contents), 0o600)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	return path
}

func rendered(t *testing.T, m *metrics.Metrics) string {
	t.Helper()

	var b strings.Builder

	err := m.Render(&b)
	if err != nil {
		t.Fatalf("render metrics: %v", err)
	}

	return b.String()
}

// A policy the agent will not load must leave the previous one in force. Returning
// the new hash would mark the bad policy as applied and stop further retries.
func TestApplyPolicyChangeKeepsThePreviousPolicy(t *testing.T) {
	t.Parallel()

	reporter := &recordedError{causes: nil}

	cfg := config{
		policyPath:   policyFile(t, "allowlist:\n  domains: not-a-list\n"),
		metrics:      metrics.New(),
		policyErrors: reporter,
	}

	got := applyPolicyChange(context.Background(), cfg, discardLogger(), "old-hash", "new-hash", nil)

	if got != "old-hash" {
		t.Errorf("returned %q; a rejected policy must keep the previous hash so the reload retries", got)
	}

	if len(reporter.causes) != 1 {
		t.Fatalf("reported %d policy errors, want 1", len(reporter.causes))
	}

	if got := rendered(t, cfg.metrics); !strings.Contains(got, `g0efilter_policy_reloads_total{result="failure"} 1`) {
		t.Errorf("the failed reload was not counted:\n%s", got)
	}
}

// Reporting is optional: an agent outside Kubernetes has no recorder.
func TestApplyPolicyChangeWithoutAReporter(t *testing.T) {
	t.Parallel()

	cfg := config{
		policyPath: policyFile(t, "allowlist:\n  domains: not-a-list\n"),
		metrics:    metrics.New(),
	}

	got := applyPolicyChange(context.Background(), cfg, discardLogger(), "old-hash", "new-hash", nil)
	if got != "old-hash" {
		t.Errorf("returned %q, want old-hash", got)
	}
}

// SIGHUP must reload the file as it stands, not compare hashes: an operator asking
// for a reload has usually just fixed the file the agent already rejected.
func TestForceReloadReportsAnUnreadablePolicy(t *testing.T) {
	t.Parallel()

	reporter := &recordedError{causes: nil}

	cfg := config{
		policyPath:   filepath.Join(t.TempDir(), "absent.yaml"),
		metrics:      metrics.New(),
		policyErrors: reporter,
	}

	got := forceReload(context.Background(), cfg, discardLogger(), "old-hash", nil)
	if got != "old-hash" {
		t.Errorf("returned %q, want old-hash", got)
	}

	if got := rendered(t, cfg.metrics); !strings.Contains(got, `g0efilter_policy_reloads_total{result="failure"} 1`) {
		t.Errorf("an unreadable policy was not counted as a failed reload:\n%s", got)
	}
}
