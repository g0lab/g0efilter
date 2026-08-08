package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

const webhookNamespace = "injected"

// The webhook is the only path where the sidecar is added by the cluster rather
// than by a manifest, so it is the only one that exercises the generated
// certificate, the published caBundle and admission itself.
func webhookInjectsIntoAPlainDeployment(t *testing.T, cluster *harness.K3sCluster) string {
	t.Helper()

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    pod-security.kubernetes.io/enforce: privileged
    g0efilter.io/inject: enabled
---
apiVersion: g0efilter.io/v1alpha1
kind: EgressPolicy
metadata:
  name: web
  namespace: %[1]s
spec:
  podSelector:
    matchLabels:
      app: web
  sidecar:
    image: %[4]s
  egress:
    - name: cluster-dns
      to:
        - networks: ['%[2]s']
    - name: allowed-site
      to:
        - domainNames: ['example.com']
`, webhookNamespace, clusterDNS, kubernetesAPI, harness.AgentImage))

	cluster.WaitForConfigMapContains(t, webhookNamespace, "g0efilter-web", "policy.yaml", "example.com")
	cluster.Kubectl(t, "wait", "--for=condition=Ready", "-n", webhookNamespace,
		"egresspolicy/web", "--timeout=3m")

	// No sidecar, no policy volume: everything the pod needs is added at admission.
	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: %[1]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: docker.io/alpine/curl:latest
          command: ['sh', '-c', 'sleep infinity']
`, webhookNamespace))

	pod := cluster.WaitForPodReady(t, webhookNamespace, "app=web")
	cluster.WaitForPodLog(t, webhookNamespace, pod, "g0efilter", "startup.ready")

	return pod
}

func webhookSidecarIsFirst(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	names := cluster.Get(t, webhookNamespace, "pod", pod, "{.spec.initContainers[*].name}")
	if !strings.HasPrefix(names, "g0efilter") {
		t.Errorf("init containers are %q; the webhook must inject the sidecar first", names)
	}

	from := cluster.Get(t, webhookNamespace, "pod", pod, "{.metadata.annotations.g0efilter\\.io/injected-from}")
	if from != "web" {
		t.Errorf("injected-from = %q, want web", from)
	}
}

func webhookInjectedPodFilters(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	out, ok := cluster.Exec(t, webhookNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://example.com")
	if !ok {
		t.Errorf("an allowed destination was blocked: %s\n%s", out,
			cluster.PodLogs(t, webhookNamespace, pod, "g0efilter"))
	}

	out, ok = cluster.Exec(t, webhookNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if ok {
		t.Errorf("a destination outside the policy was allowed: %s", out)
	}
}

// A pod no policy selects has to be admitted untouched, or the webhook would break
// every unrelated workload in an opted-in namespace.
func webhookLeavesUnselectedPodsAlone(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: unselected
  namespace: %s
  labels:
    app: other
spec:
  containers:
    - name: app
      image: docker.io/alpine/curl:latest
      command: ['sleep', '120']
`, webhookNamespace))

	cluster.WaitForPodReady(t, webhookNamespace, "app=other")

	names := cluster.Get(t, webhookNamespace, "pod", "unselected", "{.spec.initContainers[*].name}")
	if strings.TrimSpace(names) != "" {
		t.Errorf("an unselected pod was injected with %q", names)
	}
}

func webhookHonoursTheOptOut(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: opted-out
  namespace: %s
  labels:
    app: web
  annotations:
    g0efilter.io/inject: 'false'
spec:
  containers:
    - name: app
      image: docker.io/alpine/curl:latest
      command: ['sleep', '120']
`, webhookNamespace))

	cluster.WaitForPodReady(t, webhookNamespace, "app=web,!pod-template-hash")

	names := cluster.Get(t, webhookNamespace, "pod", "opted-out", "{.spec.initContainers[*].name}")
	if strings.TrimSpace(names) != "" {
		t.Errorf("an opted-out pod was injected with %q", names)
	}
}

// The controller issues its own certificate and publishes the CA; without both, the
// API server rejects every admission and pod creation stops.
func webhookPublishesItsCABundle(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	bundle := cluster.Kubectl(t, "get", "mutatingwebhookconfiguration",
		"g0efilter-sidecar-injector", "-o", "jsonpath={.webhooks[0].clientConfig.caBundle}")
	if strings.TrimSpace(bundle) == "" {
		t.Fatal("the controller did not publish a caBundle")
	}

	secret := cluster.Get(t, "g0efilter-system", "secret", "g0efilter-webhook-cert", "{.type}")
	if secret != "kubernetes.io/tls" { //nolint:gosec // a Secret type, not a credential
		t.Errorf("the certificate Secret is %q, want kubernetes.io/tls", secret)
	}
}
