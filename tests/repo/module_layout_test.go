package repo_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoWorkspaceContainsEveryModule(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	workspace := readFile(t, filepath.Join(root, "go.work"))
	modules := []string{"agent", "controller", "dashboard", "shared", "tests", "tests/e2e"}

	_, err := os.Stat(filepath.Join(root, "go.mod"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root go.mod must not exist after the component module split: %v", err)
	}

	for _, module := range modules {
		if !strings.Contains(workspace, "\t./"+module+"\n") {
			t.Errorf("go.work does not include ./%s", module)
		}

		moduleFile := readFile(t, filepath.Join(root, module, "go.mod"))
		if !strings.Contains(moduleFile, "\ngo 1.26.4\n") {
			t.Errorf("%s/go.mod does not use Go 1.26.4", module)
		}
	}
}

func TestComponentModulesUseSharedModule(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	for _, module := range []string{"agent", "dashboard"} {
		moduleFile := readFile(t, filepath.Join(root, module, "go.mod"))
		if !strings.Contains(moduleFile, "github.com/g0lab/g0efilter/shared v0.0.0") {
			t.Errorf("%s/go.mod does not require the shared module", module)
		}

		if !strings.Contains(moduleFile, "replace github.com/g0lab/g0efilter/shared => ../shared") {
			t.Errorf("%s/go.mod does not resolve the sibling shared module", module)
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()

	content, err := os.ReadFile(name) //nolint:gosec // fixed repository paths supplied by tests
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(content)
}
