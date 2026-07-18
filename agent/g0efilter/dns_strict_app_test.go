//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"testing"

	"github.com/g0lab/g0efilter/agent/filter"
)

//nolint:exhaustruct
func TestNormalizeModeAcceptsDNSStrict(t *testing.T) {
	t.Parallel()

	cfg := normalizeMode(config{mode: "dns-strict", defaultAction: "deny"}, discardLogger())
	if cfg.mode != "dns-strict" {
		t.Errorf("mode = %q, want dns-strict", cfg.mode)
	}
}

func TestIsDNSMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want bool
	}{
		{"dns", true},
		{"dns-strict", true},
		{"https", false},
	}

	for _, tt := range tests {
		if got := isDNSMode(tt.mode); got != tt.want {
			t.Errorf("isDNSMode(%q) = %v, want %v", tt.mode, got, tt.want)
		}
	}
}

//nolint:exhaustruct
func TestStrictResolvedHookDegradesWhenPermissive(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	if hook := strictResolvedHook(ctx, filter.Options{DefaultAllow: true}, discardLogger()); hook != nil {
		t.Error("default-allow must disable the strict hook")
	}

	if hook := strictResolvedHook(ctx, filter.Options{LearningMode: true}, discardLogger()); hook != nil {
		t.Error("learning mode must disable the strict hook")
	}

	if hook := strictResolvedHook(ctx, filter.Options{}, discardLogger()); hook == nil {
		t.Error("default-deny non-learning must enable the strict hook")
	}
}
