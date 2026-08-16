package repo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func TestEveryWorkflowJobFiltersEgress(t *testing.T) {
	t.Parallel()

	type step struct {
		Uses string `yaml:"uses"`
	}

	type job struct {
		Steps []step `yaml:"steps"`
	}

	type workflow struct {
		Jobs map[string]job `yaml:"jobs"`
	}

	for _, name := range workflowFiles(t) {
		content, err := os.ReadFile(name) //nolint:gosec // paths come from the fixed workflow glob
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

		for id, job := range parsed.Jobs {
			filtered := false

			for _, step := range job.Steps {
				if strings.HasPrefix(step.Uses, "g0lab/g0efilter@") || step.Uses == "./" {
					filtered = true

					break
				}
			}

			if !filtered {
				t.Errorf("%s job %q does not run g0efilter", filepath.Base(name), id)
			}
		}
	}
}
