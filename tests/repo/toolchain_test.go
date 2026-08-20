package repo_test

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

var (
	workflowGoPattern = regexp.MustCompile(`(?m)^\s*go-version:\s*'?([^'\s]+)'?\s*$`)
	builderPattern    = regexp.MustCompile(`(?m)^FROM golang:([^-\s]+)-`)
	builderTagPattern = regexp.MustCompile(`(?m)^FROM golang:(\S+)`)
	exactPatch        = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

func workflowFiles(t *testing.T) []string {
	t.Helper()

	// Both extensions, so a stale pin in a .yml workflow cannot hide from the glob.
	files := globAll(t, filepath.Join("..", "..", ".github", "workflows"), "*.yaml", "*.yml")

	if len(files) == 0 {
		t.Fatal("no workflows found; the glob no longer matches")
	}

	return files
}

func globAll(t *testing.T, dir string, patterns ...string) []string {
	t.Helper()

	sets := make([][]string, 0, len(patterns))

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}

		sets = append(sets, matches)
	}

	return slices.Concat(sets...)
}

// builderFiles returns every Containerfile that pins a golang builder image.
func builderFiles(t *testing.T) []string {
	t.Helper()

	root := filepath.Join("..", "..")

	return slices.Concat(
		globAll(t, filepath.Join(root, "tests", "e2e"), "Containerfile*"),
		globAll(t, filepath.Join(root, "examples", "build"), "Containerfile*"),
	)
}

// workflowGoVersions maps each workflow that pins a Go version to that version.
func workflowGoVersions(t *testing.T) map[string]string {
	t.Helper()

	pins := make(map[string]string)

	for _, workflow := range workflowFiles(t) {
		match := workflowGoPattern.FindStringSubmatch(readFile(t, workflow))
		if match == nil {
			continue
		}

		pins[filepath.Base(workflow)] = match[1]
	}

	if len(pins) == 0 {
		t.Fatal("no workflow pins a Go version; releases would build with whatever the runner ships")
	}

	return pins
}

// releaseGoVersion is the toolchain the release is built with. Modules keep a
// lower go directive on purpose, so the binary still builds with an older Go.
func releaseGoVersion(t *testing.T) string {
	t.Helper()

	pins := workflowGoVersions(t)

	version, ok := pins["release.yaml"]
	if !ok {
		t.Fatal("release.yaml does not pin a Go version")
	}

	return version
}

// A floating minor makes the release toolchain whatever the runner resolves on
// the day, so the same tag rebuilt later is not the same build.
func TestWorkflowGoVersionsArePinnedToAPatch(t *testing.T) {
	t.Parallel()

	for workflow, version := range workflowGoVersions(t) {
		if !exactPatch.MatchString(version) {
			t.Errorf("%s pins Go %q, want an exact patch such as 1.26.6", workflow, version)
		}
	}
}

func TestWorkflowGoVersionsAgree(t *testing.T) {
	t.Parallel()

	pins := workflowGoVersions(t)
	want := releaseGoVersion(t)

	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if pins[name] != want {
			t.Errorf("%s pins Go %s, want %s to match release.yaml", name, pins[name], want)
		}
	}
}

// Renovate matches the customManager that owns the setup-go pins by file pattern, so
// a workflow it does not match silently keeps a stale Go version through a bump.
func TestRenovateCoversEveryWorkflowGoPin(t *testing.T) {
	t.Parallel()

	patterns := renovateGoPatterns(t)

	for workflow := range workflowGoVersions(t) {
		path := ".github/workflows/" + workflow

		matched := slices.ContainsFunc(patterns, func(p *regexp.Regexp) bool {
			return p.MatchString(path)
		})

		if !matched {
			t.Errorf("%s pins a Go version but no Renovate managerFilePatterns entry matches it", path)
		}
	}
}

func renovateGoPatterns(t *testing.T) []*regexp.Regexp {
	t.Helper()

	var config struct {
		CustomManagers []struct {
			DatasourceTemplate  string   `json:"datasourceTemplate"`
			ManagerFilePatterns []string `json:"managerFilePatterns"`
		} `json:"customManagers"`
	}

	file := readFile(t, filepath.Join("..", "..", ".github", "renovate.json"))

	err := json.Unmarshal([]byte(file), &config)
	if err != nil {
		t.Fatalf("parse renovate.json: %v", err)
	}

	patterns := make([]*regexp.Regexp, 0, len(config.CustomManagers))

	for _, manager := range config.CustomManagers {
		if manager.DatasourceTemplate != "golang-version" {
			continue
		}

		for _, pattern := range manager.ManagerFilePatterns {
			patterns = append(patterns, compileRenovatePattern(t, pattern))
		}
	}

	if len(patterns) == 0 {
		t.Fatal("no Renovate customManager resolves the Go toolchain version")
	}

	return patterns
}

// Renovate reads a pattern wrapped in slashes as a regex; anything else is a glob
// this test cannot reason about.
func compileRenovatePattern(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()

	if !strings.HasPrefix(pattern, "/") || !strings.HasSuffix(pattern, "/") {
		t.Fatalf("managerFilePatterns entry %q is a glob, not a regex", pattern)
	}

	compiled, err := regexp.Compile(strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/"))
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}

	return compiled
}

// The builder images are the only Go pin outside the workflows, so a bump that
// misses them has to fail here rather than in a scan of a built image.
func TestBuilderImagesMatchTheReleaseToolchain(t *testing.T) {
	t.Parallel()

	want := releaseGoVersion(t)
	builders := builderFiles(t)

	found := 0

	for _, builder := range builders {
		match := builderPattern.FindStringSubmatch(readFile(t, builder))
		if match == nil {
			continue
		}

		found++

		if match[1] != want {
			t.Errorf("%s builds with golang:%s, want golang:%s", filepath.Base(builder), match[1], want)
		}
	}

	if found == 0 {
		t.Error("no Containerfile pins a golang builder image; the pattern no longer matches")
	}
}

// The go directive stays below the release toolchain so the modules still build
// with an older Go; it must never be raised past it by accident.
func TestModuleGoDirectivesDoNotExceedTheReleaseToolchain(t *testing.T) {
	t.Parallel()

	want := releaseGoVersion(t)
	root := filepath.Join("..", "..")
	directive := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`)

	for _, module := range []string{"agent", "controller", "dashboard", "shared", "tests", "tests/e2e"} {
		match := directive.FindStringSubmatch(readFile(t, filepath.Join(root, module, "go.mod")))
		if match == nil {
			t.Errorf("%s/go.mod has no go directive", module)

			continue
		}

		if compareVersions(match[1], want) > 0 {
			t.Errorf("%s/go.mod requires Go %s, which the release toolchain %s cannot build",
				module, match[1], want)
		}
	}
}

func compareVersions(a, b string) int {
	aParts := regexp.MustCompile(`\.`).Split(a, -1)
	bParts := regexp.MustCompile(`\.`).Split(b, -1)

	for i := range min(len(aParts), len(bParts)) {
		if aParts[i] == bParts[i] {
			continue
		}

		if len(aParts[i]) != len(bParts[i]) {
			return len(aParts[i]) - len(bParts[i])
		}

		if aParts[i] < bParts[i] {
			return -1
		}

		return 1
	}

	return len(aParts) - len(bParts)
}

// Renovate's docker versioning only offers updates that keep the same tag
// suffix, so an alpine bump is manual and can leave one builder behind.
func TestBuilderImagesUseTheSameTag(t *testing.T) {
	t.Parallel()

	builders := builderFiles(t)

	tags := make(map[string]string)

	for _, builder := range builders {
		match := builderTagPattern.FindStringSubmatch(readFile(t, builder))
		if match == nil {
			continue
		}

		tags[builder] = match[1]
	}

	if len(tags) < 2 {
		t.Fatalf("expected at least two golang builders, found %d", len(tags))
	}

	names := make([]string, 0, len(tags))
	for name := range tags {
		names = append(names, name)
	}

	sort.Strings(names)

	want := tags[names[0]]
	for _, name := range names[1:] {
		if tags[name] != want {
			t.Errorf("%s builds with golang:%s but %s uses golang:%s", name, tags[name], names[0], want)
		}
	}
}
