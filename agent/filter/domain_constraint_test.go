//nolint:testpackage // exercises unexported matching internals
package filter

import (
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

func TestConstraintsForMatching(t *testing.T) {
	t.Parallel()

	rules := []policy.DomainRule{
		{Pattern: "example.com", Proto: "tcp", Port: 443},
		{Pattern: "*.cdn.net", Proto: "udp", Port: 53},
		{Pattern: "open.example.org"},
	}

	tests := []struct {
		name string
		host string
		want []policy.DomainRule
	}{
		{"exact constrained", "example.com", []policy.DomainRule{rules[0]}},
		{"case insensitive", "EXAMPLE.COM", []policy.DomainRule{rules[0]}},
		{"wildcard constrained", "edge.cdn.net", []policy.DomainRule{rules[1]}},
		{"unconstrained entry", "open.example.org", nil},
		{"no match", "other.test", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := constraintsFor(tt.host, rules)
			if len(got) != len(tt.want) {
				t.Fatalf("constraintsFor(%q) = %+v, want %+v", tt.host, got, tt.want)
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("constraintsFor(%q)[%d] = %+v, want %+v", tt.host, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestConstraintsForMultipleEntries(t *testing.T) {
	t.Parallel()

	rules := []policy.DomainRule{
		{Pattern: "dual.example", Proto: "tcp", Port: 443},
		{Pattern: "dual.example", Proto: "udp", Port: 443},
	}

	got := constraintsFor("dual.example", rules)
	if len(got) != 2 {
		t.Fatalf("constraintsFor = %+v, want both constraints", got)
	}
}

func TestConstraintsForUnconstrainedWins(t *testing.T) {
	t.Parallel()

	rules := []policy.DomainRule{
		{Pattern: "shared.example", Proto: "tcp", Port: 443},
		{Pattern: "*.example", Proto: "", Port: 0},
	}

	if got := constraintsFor("shared.example", rules); got != nil {
		t.Errorf("constraintsFor = %+v, want nil (unconstrained)", got)
	}
}
