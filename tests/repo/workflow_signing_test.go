package repo_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var gitCommit = regexp.MustCompile(`\bgit(?:\s+-[cC]\s+\S+)*\s+commit\b`)

// Runners hold no signing key, so a local commit is unsigned and fails the signed-commits rule.
func TestWorkflowsCommitThroughGitHub(t *testing.T) {
	t.Parallel()

	for _, name := range workflowFiles(t) {
		content, err := os.ReadFile(name) //nolint:gosec // paths come from the fixed workflow glob
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		if gitCommit.Match(content) {
			t.Errorf("%s runs git commit; use .github/scripts/signed-commit.sh so GitHub signs it",
				filepath.Base(name))
		}
	}
}

func TestGitCommitPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		want bool
	}{
		{`git commit -m "chore: prepare release"`, true},
		{`git -C "$pages_dir" commit -m "Release"`, true},
		{`git -c user.name=bot commit --allow-empty -m x`, true},
		{`git rev-parse "$TARGET^{commit}"`, false},
		{`.github/scripts/signed-commit.sh "$BRANCH" "chore: prepare release"`, false},
	}

	for _, tc := range tests {
		if got := gitCommit.MatchString(tc.line); got != tc.want {
			t.Errorf("match %q = %t, want %t", tc.line, got, tc.want)
		}
	}
}
