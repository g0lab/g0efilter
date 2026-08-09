package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

const helmNamespace = "helm-demo"

// helmInstalledRelease installs the example chart against the cluster. `helm template`
// proves the chart renders; only an install proves the API server accepts what it
// renders and that the resulting pod runs.
func helmInstalledRelease(t *testing.T, cluster *harness.K3sCluster) string {
	t.Helper()

	cluster.ApplyManifest(t, strings.TrimSpace(`
apiVersion: v1
kind: Namespace
metadata:
  name: `+helmNamespace+`
  labels:
    pod-security.kubernetes.io/enforce: privileged
	`))

	chart := harness.RepoPath("examples", "helm", "demo")
	chart = cluster.HelmDependencyUpdate(t, chart)

	cluster.HelmInstall(t, helmNamespace, "demo", chart,
		"--set", "g0efilter.image.repository=g0efilter",
		"--set", "g0efilter.image.tag=e2e",
		"--set", "g0efilter.metrics.enabled=true",
		"--set", fmt.Sprintf("policy.ips={%s,%s}", clusterDNS, kubernetesAPI),
	)

	t.Cleanup(func() { cluster.HelmUninstall(t, helmNamespace, "demo") })

	pod := cluster.WaitForPodReady(t, helmNamespace, "app.kubernetes.io/name=demo")
	cluster.WaitForPodLog(t, helmNamespace, pod, "g0efilter", "startup.ready")

	return pod
}

func helmSidecarIsFirst(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	names := cluster.Get(t, helmNamespace, "pod", pod, "{.spec.initContainers[*].name}")
	if !strings.HasPrefix(names, "g0efilter") {
		t.Errorf("init containers are %q; the chart must place g0efilter first", names)
	}
}

func helmFiltersEgress(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	out, ok := cluster.Exec(t, helmNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://example.com")
	if !ok {
		t.Errorf("the chart's allowed destination was blocked: %s\n%s", out,
			cluster.PodLogs(t, helmNamespace, pod, "g0efilter"))
	}

	out, ok = cluster.Exec(t, helmNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if ok {
		t.Errorf("a destination outside the chart's policy was allowed: %s", out)
	}
}

// The chart's metrics wiring is otherwise only rendered, never served.
func helmServesMetrics(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	annotations := cluster.Get(t, helmNamespace, "pod", pod,
		"{.metadata.annotations['prometheus\\.io/port']}")
	if annotations != "9095" {
		t.Errorf("scrape port annotation = %q, want 9095", annotations)
	}

	out, ok := cluster.Exec(t, helmNamespace, pod, "app",
		"curl", "-fsS", "--max-time", "10", "http://127.0.0.1:9095/metrics")
	if !ok {
		t.Fatalf("the metrics endpoint was not reachable: %s", out)
	}

	// The filtering subtest ran first, so a denial must already be counted.
	for _, want := range []string{
		"g0efilter_connections_total",
		`g0efilter_denials_total{component="https",reason="not-allowlisted"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output has no %s:\n%s", want, out)
		}
	}
}

// Uninstalling has to take the RBAC and policy with it; a Role left behind keeps API
// access the workload no longer has any reason to hold.
func helmUninstallRemovesEverything(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.HelmUninstall(t, helmNamespace, "demo")

	for _, object := range [][2]string{
		{"deployment", "demo"},
		{"configmap", "g0efilter-policy"},
		{"role", "demo-g0efilter-events"},
		{"rolebinding", "demo-g0efilter-events"},
	} {
		cluster.WaitForAbsent(t, helmNamespace, object[0], object[1])
	}
}
