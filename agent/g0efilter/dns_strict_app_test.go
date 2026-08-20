//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"testing"

	"github.com/g0lab/g0efilter/agent/filter"
	"github.com/g0lab/g0efilter/agent/policy"
	"github.com/g0lab/g0efilter/shared/actions"
)

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

func TestCheckDomainConstraints(t *testing.T) {
	t.Parallel()

	constrained := &policy.Policy{AllowDomainRules: []policy.DomainRule{
		{Pattern: "example.com", Proto: "tcp", Port: 443},
	}}
	plain := &policy.Policy{AllowDomainRules: []policy.DomainRule{{Pattern: "example.com"}}}

	tests := []struct {
		name         string
		pol          *policy.Policy
		cfg          config
		defaultAllow bool
		wantErr      bool
	}{
		{"dns-strict enforces", constrained, config{mode: actions.ModeDNSStrict}, false, false},
		{"https cannot enforce", constrained, config{mode: actions.ModeHTTPS}, false, true},
		{"dns cannot enforce", constrained, config{mode: actions.ModeDNS}, false, true},
		{"default-allow degrades", constrained, config{mode: actions.ModeDNSStrict}, true, true},
		{"learning degrades", constrained, config{mode: actions.ModeDNSStrict, learningMode: true}, false, true},
		{"unconstrained is fine anywhere", plain, config{mode: actions.ModeHTTPS}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkDomainConstraints(tt.pol, tt.cfg, tt.defaultAllow)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDomainConstraints = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
