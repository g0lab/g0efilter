//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

func scriptLines(script string) []string {
	return strings.Split(strings.TrimSpace(script), "\n")
}

//nolint:exhaustruct
func TestBuildResolvedScriptDestroysBeforeAdding(t *testing.T) {
	t.Parallel()

	script, errs := buildResolvedScript(
		[]string{"g0efilter"},
		[]string{"140.82.112.3"},
		300*time.Second,
		[]policy.DomainRule{{}},
	)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	lines := scriptLines(script)

	want := []string{
		"destroy element ip g0efilter_v4 resolved_allow_v4 { 140.82.112.3 }",
		"add element ip g0efilter_v4 resolved_allow_v4 { 140.82.112.3 timeout 300s }",
	}

	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), script)
	}

	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}
}

//nolint:exhaustruct
func TestBuildResolvedScriptBatchesEveryElementIntoOneTransaction(t *testing.T) {
	t.Parallel()

	ips := []string{"1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"}
	rules := []policy.DomainRule{
		{Pattern: "example.com", Proto: "tcp", Port: 443},
		{Pattern: "example.com", Proto: "udp", Port: 53},
	}

	script, errs := buildResolvedScript([]string{"g0efilter"}, ips, time.Minute, rules)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	wantLines := len(ips) * len(rules) * 2
	if got := len(scriptLines(script)); got != wantLines {
		t.Errorf("got %d lines, want %d:\n%s", got, wantLines, script)
	}

	if !strings.Contains(script, "resolved_allow_v6_port { 2606:4700:4700::1111 . tcp . 443") {
		t.Errorf("IPv6 constrained element missing:\n%s", script)
	}

	if !strings.Contains(script, "resolved_allow_v4_port { 8.8.8.8 . udp . 53") {
		t.Errorf("IPv4 constrained element missing:\n%s", script)
	}
}

//nolint:exhaustruct
func TestBuildResolvedScriptCoversEveryTable(t *testing.T) {
	t.Parallel()

	script, errs := buildResolvedScript(
		[]string{"g0efilter", "g0efilter_bridge"},
		[]string{"1.1.1.1"},
		time.Minute,
		[]policy.DomainRule{{}},
	)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	for _, table := range []string{"g0efilter_v4", "g0efilter_bridge_v4"} {
		if !strings.Contains(script, "add element ip "+table+" ") {
			t.Errorf("table %s missing from the batch:\n%s", table, script)
		}
	}

	if got := len(scriptLines(script)); got != 4 {
		t.Errorf("got %d lines, want 4 (destroy+add per table):\n%s", got, script)
	}
}

//nolint:exhaustruct
func TestBuildResolvedScriptRejectsBadElementsWithoutDroppingTheRest(t *testing.T) {
	t.Parallel()

	script, errs := buildResolvedScript(
		[]string{"g0efilter"},
		[]string{"1.1.1.1", "not-an-ip", "1.2.3.4; drop table", "8.8.8.8"},
		time.Minute,
		[]policy.DomainRule{{}},
	)

	if len(errs) != 2 {
		t.Errorf("got %d errors, want 2 (one per bad address): %v", len(errs), errs)
	}

	if strings.Contains(script, "drop table") || strings.Contains(script, "not-an-ip") {
		t.Fatalf("an invalid address reached the nft script:\n%s", script)
	}

	for _, good := range []string{"1.1.1.1", "8.8.8.8"} {
		if !strings.Contains(script, good) {
			t.Errorf("valid address %s was dropped alongside the invalid ones:\n%s", good, script)
		}
	}
}

//nolint:exhaustruct
func TestBuildResolvedScriptRejectsBadConstraints(t *testing.T) {
	t.Parallel()

	script, errs := buildResolvedScript(
		[]string{"g0efilter"},
		[]string{"1.1.1.1"},
		time.Minute,
		[]policy.DomainRule{{Pattern: "example.com", Proto: "tcp; drop", Port: 443}},
	)

	if len(errs) != 1 {
		t.Errorf("got %d errors, want 1: %v", len(errs), errs)
	}

	if script != "" {
		t.Errorf("an invalid constraint produced a script:\n%s", script)
	}
}

func TestBuildResolvedScriptIsEmptyForNoAddresses(t *testing.T) {
	t.Parallel()

	script, errs := buildResolvedScript([]string{"g0efilter"}, nil, time.Minute, nil)
	if script != "" || len(errs) != 0 {
		t.Errorf("got script %q errs %v, want both empty", script, errs)
	}
}

func TestSupportsDestroyElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    bool
	}{
		{"v1.1.5 (Commodore Bullmoose #6)", true},
		{"v1.0.9 (Spark In The Dark)", true},
		{"v1.0.8", true},
		{"v1.0.7 (Scotch Bonnet)", false},
		{"v1.0.0", false},
		{"v0.9.9", false},
		{"v2.0.0", true},
		{"1.0.9", true},
		{"", false},
		{"v1.0", false},
		{"nonsense", false},
		{"v1.x.9", false},
	}

	for _, tt := range tests {
		if got := supportsDestroyElement(tt.version); got != tt.want {
			t.Errorf("supportsDestroyElement(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestResolvedTablePrefixes(t *testing.T) {
	t.Setenv("BRIDGE_INTERFACES", "")

	if got := resolvedTablePrefixes(); len(got) != 1 || got[0] != "g0efilter" {
		t.Errorf("got %v, want just the main table", got)
	}

	t.Setenv("BRIDGE_INTERFACES", "br0")

	got := resolvedTablePrefixes()
	if len(got) != 2 || got[1] != "g0efilter_bridge" {
		t.Errorf("got %v, want the bridge table included", got)
	}
}
