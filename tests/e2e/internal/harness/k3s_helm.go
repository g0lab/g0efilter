package harness

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const helmTimeout = 5 * time.Minute

// HelmDependencyUpdate resolves the local library-chart dependency, so the install
// exercises the chart in the working tree rather than a stale packaged copy.
func (c *K3sCluster) HelmDependencyUpdate(t *testing.T, chart string) {
	t.Helper()

	c.helm(t, "dependency", "update", chart)
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
