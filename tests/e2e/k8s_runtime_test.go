package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

const runtimeNamespace = "runtime-config"

// The sidecar allows the pod's resolver on port 53, so a policy naming no DNS address still resolves.
func clusterDNSNeedsNoPolicyRule(t *testing.T, cluster *harness.K3sCluster) string {
	t.Helper()

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    pod-security.kubernetes.io/enforce: privileged
    g0efilter.g0lab.com/inject: enabled
---
apiVersion: g0efilter.g0lab.com/v1alpha1
kind: EgressPolicy
metadata:
  name: web
  namespace: %[1]s
spec:
  podSelector:
    matchLabels:
      app: web
  sidecar:
    image: %[2]s
  egress:
    - name: allowed-site
      to:
        - domainNames: ['example.com']
`, runtimeNamespace, harness.AgentImage))

	cluster.WaitForConfigMapContains(t, runtimeNamespace, "g0efilter-web", "policy.yaml", "example.com")
	cluster.Kubectl(t, "wait", "--for=condition=Ready", "-n", runtimeNamespace,
		"egresspolicy/web", "--timeout=3m")

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: %s
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
`, runtimeNamespace))

	pod := cluster.WaitForPodReady(t, runtimeNamespace, "app=web")
	cluster.WaitForPodLog(t, runtimeNamespace, pod, "g0efilter", "startup.ready")

	out, ok := cluster.CurlExternal(t, runtimeNamespace, pod, "app", "https://example.com")
	if !ok {
		t.Errorf("resolution failed with no cluster DNS rule in the policy: %s\n%s", out,
			cluster.PodLogs(t, runtimeNamespace, pod, "g0efilter"))
	}

	return pod
}

// Allowing the resolver is not permission to reach other Services.
func theClusterResolverRuleIsScopedToDNS(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	target := cluster.Get(t, "kube-system", "service", "kube-dns", "{.spec.clusterIP}")
	if strings.TrimSpace(target) == "" {
		t.Skip("cluster DNS Service has no ClusterIP to probe")
	}

	out, ok := cluster.Exec(t, runtimeNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "10", "http://"+target+":9153/metrics")
	if ok {
		t.Errorf("the resolver rule opened a port other than 53: %s", out)
	}
}

// Without the startup probe the application starts as soon as the sidecar process does.
func theSidecarGatesTheApplicationOnItsStartupProbe(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	probe := cluster.Get(t, runtimeNamespace, "pod", pod,
		"{.spec.initContainers[0].startupProbe.exec.command[*]}")
	if !strings.Contains(probe, "healthcheck") {
		t.Errorf("the injected sidecar has no healthcheck startup probe, got %q", probe)
	}

	ready := cluster.Get(t, runtimeNamespace, "pod", pod,
		"{.status.initContainerStatuses[?(@.name=='g0efilter')].ready}")
	if ready != "true" {
		t.Errorf("the sidecar reports ready = %q, want true", ready)
	}
}

// Mode, enforcement and DNS travel in the policy document, so they apply to running pods.
func enforcementReloadsWithoutARestart(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	before := cluster.Get(t, runtimeNamespace, "pod", pod,
		"{.status.initContainerStatuses[?(@.name=='g0efilter')].restartCount}")

	cluster.Kubectl(t, "patch", "-n", runtimeNamespace, "egresspolicy/web", "--type=merge",
		"-p", `{"spec":{"sidecar":{"enforcement":"audit"}}}`)

	cluster.WaitForConfigMapContains(t, runtimeNamespace, "g0efilter-web", "policy.yaml", `"enforcement":"audit"`)
	cluster.WaitForPodLog(t, runtimeNamespace, pod, "g0efilter", "policy.applied")

	// Audit allows what block refused, which is the observable proof it reloaded.
	out, ok := cluster.Exec(t, runtimeNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if !ok {
		t.Errorf("audit did not take effect in the running pod: %s\n%s", out,
			cluster.PodLogs(t, runtimeNamespace, pod, "g0efilter"))
	}

	after := cluster.Get(t, runtimeNamespace, "pod", pod,
		"{.status.initContainerStatuses[?(@.name=='g0efilter')].restartCount}")
	if after != before {
		t.Errorf("the sidecar restarted to apply a reloadable setting: %s then %s", before, after)
	}

	if name := cluster.PodName(t, runtimeNamespace, "app=web"); name != pod {
		t.Errorf("the pod was replaced to apply a reloadable setting: %s then %s", pod, name)
	}
}

// A startup setting cannot reload, so drift must not stop the replacements that would clear it.
func stalePodsStillAdmitTheirReplacements(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.Kubectl(t, "patch", "-n", runtimeNamespace, "egresspolicy/web", "--type=merge",
		"-p", `{"spec":{"sidecar":{"logLevel":"DEBUG"}}}`)

	cluster.WaitForStatusField(t, runtimeNamespace, "egresspolicy", "web", "{.status.outOfDatePods}", "1")

	configured := cluster.Get(t, runtimeNamespace, "egresspolicy", "web",
		`{.status.conditions[?(@.type=="ConfigurationReady")].status}`)
	if configured != "True" {
		t.Fatalf("ConfigurationReady = %q while pods are stale; replacements could not be admitted", configured)
	}

	upToDate := cluster.Get(t, runtimeNamespace, "egresspolicy", "web",
		`{.status.conditions[?(@.type=="PodsUpToDate")].status}`)
	if upToDate != "False" {
		t.Errorf("PodsUpToDate = %q, want False while a pod predates the change", upToDate)
	}

	// The recorder writes through events.k8s.io, which needs its own RBAC rule: without
	// it the drift is reported in status but the operator's Event never arrives.
	message := cluster.WaitForEvent(t, runtimeNamespace, "web", "PodsOutOfDate")
	if !strings.Contains(message, "rollout") {
		t.Errorf("unexpected drift event message: %q", message)
	}

	cluster.Kubectl(t, "rollout", "restart", "-n", runtimeNamespace, "deployment/web")
	cluster.Kubectl(t, "rollout", "status", "-n", runtimeNamespace, "deployment/web", "--timeout=3m")

	cluster.WaitForStatusField(t, runtimeNamespace, "egresspolicy", "web", "{.status.outOfDatePods}", "0")
}

// The validating webhook refuses an edit the sidecar could not enforce.
func theValidatorRefusesAnUnenforceablePolicy(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	out, err := cluster.TryApplyManifest(t, fmt.Sprintf(`
apiVersion: g0efilter.g0lab.com/v1alpha1
kind: EgressPolicy
metadata:
  name: unenforceable
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: none
  sidecar:
    mode: https
  egress:
    - name: domain-port
      to:
        - domainNames: ['api.example.com']
      ports:
        - port: 8443
          protocol: TCP
`, runtimeNamespace))
	if err == nil {
		t.Fatalf("a policy https mode cannot enforce was admitted: %s", out)
	}

	if !strings.Contains(out, "dns-strict") {
		t.Errorf("the denial does not name the mode that would work: %s", out)
	}
}
