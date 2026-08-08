package e2e_test

import (
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

// TestPhase18Kubernetes runs the control plane in a real cluster: it applies the
// CRDs, starts the controller from a locally built image, creates an EgressPolicy and
// checks the controller renders it into the ConfigMap a sidecar would mount.
//
// The fake client and envtest cover reconcile logic and CRD validation; only a real
// cluster covers the deployment, its RBAC and the manager actually running.
func TestPhase18Kubernetes(t *testing.T) {
	t.Parallel()

	if !harness.K8sEnabled() {
		t.Skip("set E2E_K8S=true to run the Kubernetes phase (starts a k3s cluster)")
	}

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("kubernetes phase runs once, in the https lane (got %s)", mode)
	}

	cluster := harness.StartK3s(t)

	cluster.Apply(t, "--server-side", "-f", harness.RepoPath("deploy", "crds"))
	cluster.WaitForCRDs(t, "egresspolicies.g0efilter.io", "clusteregresspolicies.g0efilter.io")

	cluster.ApplyKustomize(t, harness.RepoPath("tests", "e2e", "testdata", "controller"))
	cluster.WaitForDeployment(t, "g0efilter-system", "g0efilter-controller")

	t.Run("RendersAPolicyIntoAConfigMap", func(t *testing.T) { k8sRendersPolicy(t, cluster) })
	t.Run("MergesAClusterPolicy", func(t *testing.T) { k8sMergesClusterPolicy(t, cluster) })
	t.Run("DeletingAPolicyRemovesItsConfigMap", func(t *testing.T) { k8sGarbageCollects(t, cluster) })
}

func k8sRendersPolicy(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, `
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a
---
apiVersion: g0efilter.io/v1alpha1
kind: EgressPolicy
metadata:
  name: web
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - name: apis
      to:
        - domainNames: ['api.example.com', '*.cdn.example.com']
    - name: dns
      to:
        - networks: ['10.43.0.10']
      ports:
        - protocol: UDP
          port: 53
`)

	document := cluster.WaitForConfigMapKey(t, "tenant-a", "g0efilter-web", "policy.yaml")

	for _, want := range []string{
		"api.example.com",
		"*.cdn.example.com",
		"udp/10.43.0.10:53",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("rendered policy missing %q:\n%s", want, document)
		}
	}

	// The status is how an operator finds the ConfigMap to mount.
	name := cluster.Get(t, "tenant-a", "egresspolicy", "web", "{.status.configMapName}")
	if name != "g0efilter-web" {
		t.Errorf("status.configMapName = %q, want g0efilter-web", name)
	}

	ready := cluster.Get(t, "tenant-a", "egresspolicy", "web",
		`{.status.conditions[?(@.type=="Ready")].status}`)
	if ready != "True" {
		t.Errorf("Ready condition = %q, want True", ready)
	}
}

func k8sMergesClusterPolicy(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, `
apiVersion: g0efilter.io/v1alpha1
kind: ClusterEgressPolicy
metadata:
  name: baseline-dns
spec:
  egress:
    - name: cluster-dns
      to:
        - networks: ['10.43.0.53']
`)

	// The controller watches cluster policies, so the namespaced policy is
	// re-reconciled without touching it.
	cluster.WaitForConfigMapContains(t, "tenant-a", "g0efilter-web", "policy.yaml", "10.43.0.53")
}

func k8sGarbageCollects(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, `
apiVersion: g0efilter.io/v1alpha1
kind: EgressPolicy
metadata:
  name: temporary
  namespace: tenant-a
spec:
  egress:
    - name: apis
      to:
        - domainNames: ['temporary.example.com']
`)

	cluster.WaitForConfigMapKey(t, "tenant-a", "g0efilter-temporary", "policy.yaml")

	cluster.Kubectl(t, "delete", "-n", "tenant-a", "egresspolicy", "temporary")

	// The owner reference is what removes the ConfigMap; only a real cluster runs the
	// garbage collector that acts on it.
	cluster.WaitForAbsent(t, "tenant-a", "configmap", "g0efilter-temporary")
}
