package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

const auditNamespace = "audited"

// Cover the documented audit-to-enforcement rollout through the CRD, webhook and
// agent.
func webhookInjectsAuditMode(t *testing.T, cluster *harness.K3sCluster) string {
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
    image: %[3]s
    enforcement: audit
    logLevel: DEBUG
  egress:
    - name: cluster-dns
      to:
        - networks: ['%[2]s']
    - name: allowed-site
      to:
        - domainNames: ['example.com']
`, auditNamespace, clusterDNS, harness.AgentImage))

	cluster.WaitForConfigMapContains(t, auditNamespace, "g0efilter-web", "policy.yaml", "example.com")
	cluster.Kubectl(t, "wait", "--for=condition=Ready", "-n", auditNamespace,
		"egresspolicy/web", "--timeout=3m")

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
`, auditNamespace))

	pod := cluster.WaitForPodReady(t, auditNamespace, "app=web")
	cluster.WaitForPodLog(t, auditNamespace, pod, "g0efilter", "startup.ready")

	return pod
}

func auditModeSetsTheEnvironment(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	jsonPath := "{.spec.initContainers[0].env[?(@.name=='ENFORCE')].value}"

	if got := cluster.Get(t, auditNamespace, "pod", pod, jsonPath); got != "audit" {
		t.Errorf("ENFORCE = %q, want audit", got)
	}
}

// The point of audit mode: a destination no rule allows still reaches the network.
func auditModeAllowsUnmatchedTraffic(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	out, ok := cluster.Exec(t, auditNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if !ok {
		t.Errorf("audit mode blocked a destination outside the policy: %s\n%s", out,
			cluster.PodLogs(t, auditNamespace, pod, "g0efilter"))
	}

	out, ok = cluster.Exec(t, auditNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://example.com")
	if !ok {
		t.Errorf("an allowed destination was blocked: %s", out)
	}
}

// Allowing the traffic is only useful if the operator can still see what would have
// been dropped.
func auditModeLogsTheDecision(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	logs := cluster.PodLogs(t, auditNamespace, pod, "g0efilter")

	if !strings.Contains(logs, "audit") {
		t.Errorf("no audit decision was logged:\n%s", logs)
	}

	if !strings.Contains(logs, "github.com") {
		t.Errorf("the audited destination is not named in the logs:\n%s", logs)
	}
}

// The rollout recreates the pod so the webhook can inject the new posture.
func auditModeSwitchesToBlock(t *testing.T, cluster *harness.K3sCluster, oldPod string) {
	t.Helper()

	cluster.Kubectl(t, "patch", "-n", auditNamespace, "egresspolicy/web", "--type=merge",
		"-p", `{"spec":{"sidecar":{"enforcement":"block"}}}`)

	cluster.Kubectl(t, "wait", "--for=condition=Ready", "-n", auditNamespace,
		"egresspolicy/web", "--timeout=3m")

	// Enforcement is baked into the pod at admission, so it takes a new pod.
	cluster.Kubectl(t, "rollout", "restart", "-n", auditNamespace, "deployment/web")
	cluster.Kubectl(t, "rollout", "status", "-n", auditNamespace, "deployment/web", "--timeout=3m")
	cluster.Kubectl(t, "wait", "--for=delete", "-n", auditNamespace,
		"pod/"+oldPod, "--timeout=3m")

	pod := cluster.WaitForPodReady(t, auditNamespace, "app=web")
	cluster.WaitForPodLog(t, auditNamespace, pod, "g0efilter", "startup.ready")

	jsonPath := "{.spec.initContainers[0].env[?(@.name=='ENFORCE')].value}"
	if got := cluster.Get(t, auditNamespace, "pod", pod, jsonPath); got != "block" {
		t.Fatalf("ENFORCE = %q after the switch, want block", got)
	}

	out, ok := cluster.Exec(t, auditNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if ok {
		t.Errorf("the destination audited earlier is still allowed once enforcing: %s", out)
	}
}
