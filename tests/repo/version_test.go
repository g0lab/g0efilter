package repo_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

// The version is pinned in manifests, docs and Go source. A release that updates
// some and not others ships a chart that installs a different agent than its
// controller, so every pin is checked against VERSION.
var taggedPins = []*regexp.Regexp{ //nolint:gochecknoglobals // the pin list is the test's data
	// docker.io/g0lab/g0efilter:v0.8.0, and the dashboard and controller images.
	regexp.MustCompile(`g0lab/g0efilter[a-z-]*:v([0-9]+\.[0-9]+\.[0-9]+[^\s'"]*)`),
	// github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
	regexp.MustCompile(`\?ref=v([0-9]+\.[0-9]+\.[0-9]+[^\s'"]*)`),
	// raw.githubusercontent.com/g0lab/g0efilter/v0.8.0/deploy/crds/...
	regexp.MustCompile(`g0lab/g0efilter/v([0-9]+\.[0-9]+\.[0-9]+[^/\s'"]*)/deploy/`),
	// Kustomize newTag and the Helm image tag.
	regexp.MustCompile(`newTag:\s*'?v([0-9]+\.[0-9]+\.[0-9]+[^\s'"]*)`),
	regexp.MustCompile(`(?m)^\s*tag:\s*'?v([0-9]+\.[0-9]+\.[0-9]+[^\s'"]*)`),
}

// versionScanned are the trees whose pins must match VERSION. Everything else may
// mention an older release legitimately, for example a changelog.
var versionScanned = []string{ //nolint:gochecknoglobals // the scan list is the test's data
	"deploy/", "docs/", "examples/", "controller/", "README.md",
}

func declaredVersion(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}

	version := strings.TrimSpace(string(raw))
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		t.Fatalf("VERSION is %q, want plain SemVer such as 1.2.3", version)
	}

	return version
}

func scanned(name string) bool {
	for _, prefix := range versionScanned {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

func TestPinnedVersionsMatchVERSION(t *testing.T) {
	t.Parallel()

	want := declaredVersion(t)

	for _, name := range trackedFiles(t) {
		if !scanned(name) || strings.HasSuffix(name, "_test.go") {
			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		for _, pin := range taggedPins {
			for _, match := range pin.FindAllStringSubmatch(string(content), -1) {
				if match[1] != want {
					t.Errorf("%s pins %s, but VERSION is %s\nrun scripts/set-version.sh %s",
						name, match[1], want, want)
				}
			}
		}
	}
}

// appVersion is checked only for our own chart: an example chart's appVersion is
// the demo application's version and has nothing to do with the release. Helm wants
// plain SemVer here, so a v prefix is rejected rather than tolerated.
func TestChartAppVersionMatchesVERSION(t *testing.T) {
	t.Parallel()

	want := declaredVersion(t)

	charts, err := filepath.Glob(filepath.Join("..", "..", "deploy", "helm", "*", "Chart.yaml"))
	if err != nil || len(charts) == 0 {
		t.Fatalf("find charts: %v", err)
	}

	for _, chart := range charts {
		content, err := os.ReadFile(chart) //nolint:gosec // repository chart paths
		if err != nil {
			t.Errorf("read %s: %v", chart, err)

			continue
		}

		appVersion := regexp.MustCompile(`(?m)^appVersion:\s*'?"?(\S+?)"?'?$`).FindStringSubmatch(string(content))
		if appVersion == nil {
			t.Errorf("%s declares no appVersion", chart)
		} else if appVersion[1] != want {
			t.Errorf("%s appVersion is %q, but VERSION is %q\nrun scripts/set-version.sh %s",
				chart, appVersion[1], want, want)
		}

		chartVersion := regexp.MustCompile(`(?m)^version:\s*'?"?(\S+?)"?'?$`).FindStringSubmatch(string(content))
		if chartVersion == nil {
			t.Errorf("%s declares no version", chart)
		} else if chartVersion[1] != want {
			t.Errorf("%s chart version is %q, but VERSION is %q\nrun scripts/set-version.sh %s",
				chart, chartVersion[1], want, want)
		}
	}
}

func TestG0efilterChartDependenciesMatchVERSION(t *testing.T) {
	t.Parallel()

	want := declaredVersion(t)

	for _, name := range trackedFiles(t) {
		if filepath.Base(name) != "Chart.yaml" {
			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		var chart struct {
			Dependencies []struct {
				Name       string `yaml:"name"`
				Version    string `yaml:"version"`
				Repository string `yaml:"repository"`
			} `yaml:"dependencies"`
		}

		err = yaml.Unmarshal(content, &chart)
		if err != nil {
			t.Errorf("parse %s: %v", name, err)

			continue
		}

		for _, dependency := range chart.Dependencies {
			if dependency.Name == "g0efilter" && dependency.Version != want {
				t.Errorf("%s requires g0efilter %s, but VERSION is %s\nrun scripts/set-version.sh %s",
					name, dependency.Version, want, want)
			}
		}
	}
}

// A pin that no expression matches would drift unnoticed, so the set of files
// carrying one is asserted rather than discovered.
func TestEveryExpectedFileCarriesAVersionPin(t *testing.T) {
	t.Parallel()

	want := declaredVersion(t)

	required := []string{
		"deploy/kustomize/sidecar/kustomization.yaml",
		"deploy/kustomize/audit/kustomization.yaml",
		"deploy/kustomize/process-info/kustomization.yaml",
		"deploy/helm/g0efilter/values.yaml",
		"deploy/helm/g0efilter/Chart.yaml",
		"deploy/helm/g0efilter-controller/values.yaml",
		"deploy/helm/g0efilter-controller/Chart.yaml",
		"deploy/helm/g0efilter-dashboard/values.yaml",
		"deploy/helm/g0efilter-dashboard/Chart.yaml",
		"deploy/controller/deployment.yaml",
		"controller/internal/webhook/sidecar.go",
	}

	for _, name := range required {
		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		if !strings.Contains(string(content), want) {
			t.Errorf("%s carries no %s pin; either it lost one or set-version.sh no longer covers it",
				name, want)
		}
	}
}
