package harness

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helmTimeout = 5 * time.Minute

// HelmDependencyUpdate resolves the local library-chart dependency, so the install
// exercises the chart in the working tree rather than a stale packaged copy.
func (c *K3sCluster) HelmDependencyUpdate(t *testing.T, chart string) string {
	t.Helper()

	chartFile := filepath.Join(chart, "Chart.yaml")

	content, err := os.ReadFile(chartFile) //nolint:gosec // a repository test fixture
	if err != nil {
		t.Fatalf("read %s: %v", chartFile, err)
	}

	const publishedRepository = "repository: oci://ghcr.io/g0lab/helm"
	if !strings.Contains(string(content), publishedRepository) {
		c.helm(t, "dependency", "update", chart)

		return chart
	}

	temporaryChart := filepath.Join(t.TempDir(), "chart")

	absoluteChart, err := filepath.Abs(chart)
	if err != nil {
		t.Fatalf("resolve %s: %v", chart, err)
	}

	err = os.CopyFS(temporaryChart, os.DirFS(absoluteChart))
	if err != nil {
		t.Fatalf("copy %s: %v", chart, err)
	}

	err = os.RemoveAll(filepath.Join(temporaryChart, "charts"))
	if err != nil {
		t.Fatalf("remove packaged dependencies: %v", err)
	}

	err = os.Remove(filepath.Join(temporaryChart, "Chart.lock"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove dependency lock: %v", err)
	}

	libraryChart, err := filepath.Abs(RepoPath("deploy", "helm", "g0efilter"))
	if err != nil {
		t.Fatalf("resolve local library chart: %v", err)
	}

	content = []byte(strings.Replace(string(content), publishedRepository,
		"repository: file://"+filepath.ToSlash(libraryChart), 1))

	err = os.WriteFile(filepath.Join(temporaryChart, "Chart.yaml"), content, 0o600) //nolint:gosec // t.TempDir target
	if err != nil {
		t.Fatalf("write temporary Chart.yaml: %v", err)
	}

	c.helm(t, "dependency", "update", temporaryChart)

	return temporaryChart
}

// HelmInstall installs a chart and waits for its workloads to become ready.
func (c *K3sCluster) HelmInstall(t *testing.T, namespace, release, chart string, args ...string) {
	t.Helper()

	install := []string{
		"install", release, chart,
		"--namespace", namespace,
		"--create-namespace",
		"--wait",
		"--timeout", readinessTimeout.String(),
	}

	out, err := c.tryHelm(append(install, args...)...)
	if err != nil {
		t.Fatalf("helm install %s: %v\n%s\n%s", release, err, out, c.describePods(namespace))
	}
}

// HelmUninstall removes a release. It tolerates an already-removed release so it can
// serve both as an assertion and as a cleanup hook.
func (c *K3sCluster) HelmUninstall(t *testing.T, namespace, release string) {
	t.Helper()

	out, err := c.tryHelm("uninstall", release, "--namespace", namespace, "--wait", "--ignore-not-found")
	if err != nil {
		t.Errorf("helm uninstall %s: %v\n%s", release, err, out)
	}
}

func (c *K3sCluster) helm(t *testing.T, args ...string) string {
	t.Helper()

	out, err := c.tryHelm(args...)
	if err != nil {
		t.Fatalf("helm %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return out
}

func (c *K3sCluster) tryHelm(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), helmTimeout)
	defer cancel()

	//nolint:gosec // literal arguments supplied by the tests
	cmd := exec.CommandContext(ctx, "helm", args...)

	cmd.Env = append(os.Environ(), "KUBECONFIG="+c.kubeconfig)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}
