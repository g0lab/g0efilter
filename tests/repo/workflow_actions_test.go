package repo_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var workflowUses = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var containerDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

func actionIsPinned(action string) bool {
	if strings.HasPrefix(action, "./") {
		return true
	}

	if strings.HasPrefix(action, "docker://") {
		return containerDigest.MatchString(action)
	}

	separator := strings.LastIndexByte(action, '@')

	return separator >= 0 && commitSHA.MatchString(action[separator+1:])
}

func TestWorkflowActionsArePinnedToCommits(t *testing.T) {
	t.Parallel()

	for _, name := range trackedFiles(t) {
		if !strings.HasPrefix(name, ".github/") && name != "action.yml" {
			continue
		}

		extension := filepath.Ext(name)
		if extension != ".yml" && extension != ".yaml" {
			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		for _, match := range workflowUses.FindAllStringSubmatch(string(content), -1) {
			action := match[1]
			if !actionIsPinned(action) {
				t.Errorf("%s uses %s; pin external actions to a full commit SHA", name, action)
			}
		}
	}
}

func TestWorkflowActionPinPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"commit", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", true},
		{"tag", "actions/checkout@v7", false},
		{"local", "./.github/actions/local", true},
		{"container tag", "docker://alpine:3.24", false},
		{"container digest", "docker://alpine@sha256:" + strings.Repeat("a", 64), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := actionIsPinned(tc.action); got != tc.want {
				t.Errorf("pin validation = %t, want %t", got, tc.want)
			}
		})
	}
}
