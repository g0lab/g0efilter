package repo_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v4"
)

// gatedWorkflows fan every job into a single `result` job, so branch protection needs one
// required check instead of one per job.
func gatedWorkflows() []string {
	return []string{
		".github/workflows/action-test.yaml",
		".github/workflows/test.yaml",
	}
}

type workflow struct {
	Jobs map[string]struct {
		Name  string    `yaml:"name"`
		Needs needsList `yaml:"needs"`
		If    string    `yaml:"if"`
	} `yaml:"jobs"`
}

// needs takes either a single job or a list of them.
type needsList []string

func (n *needsList) UnmarshalYAML(node *yaml.Node) error {
	var single string

	err := node.Decode(&single)
	if err == nil {
		*n = needsList{single}

		return nil
	}

	var many []string

	err = node.Decode(&many)
	if err != nil {
		return fmt.Errorf("decode needs: %w", err)
	}

	*n = many

	return nil
}

// A job missing from the result job's needs would fail without blocking the merge, which
// is the whole failure mode the aggregate check exists to prevent.
func TestGatedWorkflowsFanEveryJobIntoTheResultJob(t *testing.T) {
	t.Parallel()

	for _, name := range gatedWorkflows() {
		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		var parsed workflow

		err = yaml.Unmarshal(content, &parsed)
		if err != nil {
			t.Errorf("parse %s: %v", name, err)

			continue
		}

		result, ok := parsed.Jobs["result"]
		if !ok {
			t.Errorf("%s has no result job to act as the required check", name)

			continue
		}

		// Without always() the check is skipped when an upstream job fails, and a skipped
		// required check counts as a pass.
		if result.If != "always()" {
			t.Errorf("%s result job must be if: always(), got %q", name, result.If)
		}

		needed := make(map[string]bool, len(result.Needs))
		for _, job := range result.Needs {
			needed[job] = true
		}

		for id := range parsed.Jobs {
			if id == "result" || needed[id] {
				continue
			}

			t.Errorf("%s job %q is not in the result job's needs, so it cannot block a merge", name, id)
		}
	}
}
