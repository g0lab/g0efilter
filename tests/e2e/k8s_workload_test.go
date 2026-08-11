package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

// k3s serves cluster DNS on 10.43.0.10 by default. Egress is default-deny, so without
// it every lookup fails and nothing else can be tested.
const clusterDNS = "10.43.0.10"

// The sidecar's own egress is filtered by the policy it enforces, so recording Events
// requires the API server to be allowed. Without it g0efilter blocks its own reports.
const kubernetesAPI = "10.43.0.1"

const filteredNamespace = "filtered"

// TestPhase19KubernetesWorkload filters a real pod: kubelet and containerd rather
// than plain Docker, a policy rendered by the controller, and live external egress.
func TestPhase19KubernetesWorkload(t *testing.T) {
	t.Parallel()

	if !harness.K8sEnabled() {
		t.Skip("set E2E_K8S=true to run the Kubernetes phase (starts a k3s cluster)")
	}

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("kubernetes workload phase runs once, in the https lane (got %s)", mode)
	}

	cluster := harness.StartK3s(t)
	cluster.LoadAgentImage(t, harness.Env("G0EFILTER_IMAGE", "g0efilter:test"))

	cluster.Apply(t, "--server-side", "-f", harness.RepoPath("deploy", "crds"))
	cluster.WaitForCRDs(t, "egresspolicies.g0efilter.g0lab.com", "clusteregresspolicies.g0efilter.g0lab.com")
	// The webhook overlay, so this phase covers injection at admission as well as
	// the render-time paths.
	cluster.ApplyKustomize(t, harness.RepoPath("tests", "e2e", "testdata", "webhook"))
	cluster.WaitForDeployment(t, "g0efilter-system", "g0efilter-controller")

	t.Run("PodSecurityRejectsNetAdminUnderBaseline", func(t *testing.T) { podSecurityRejects(t, cluster) })

	pod := startFilteredWorkload(t, cluster)

	t.Run("SidecarIsTheFirstInitContainer", func(t *testing.T) { sidecarIsFirst(t, cluster, pod) })
	t.Run("FiltersRealEgress", func(t *testing.T) { filtersRealEgress(t, cluster, pod) })
	t.Run("RecordsDenialsAsEvents", func(t *testing.T) { recordsDenialEvents(t, cluster, pod) })
	t.Run("ReloadsWhenThePolicyChanges", func(t *testing.T) { reloadsOnPolicyChange(t, cluster, pod) })

	helmPod := helmInstalledRelease(t, cluster)

	t.Run("HelmChartPlacesTheSidecarFirst", func(t *testing.T) { helmSidecarIsFirst(t, cluster, helmPod) })
	t.Run("HelmChartFiltersEgress", func(t *testing.T) { helmFiltersEgress(t, cluster, helmPod) })
	t.Run("HelmChartServesMetrics", func(t *testing.T) { helmServesMetrics(t, cluster, helmPod) })
	t.Run("HelmUninstallRemovesEverything", func(t *testing.T) { helmUninstallRemovesEverything(t, cluster) })

	t.Run("WebhookPublishesItsCABundle", func(t *testing.T) { webhookPublishesItsCABundle(t, cluster) })

	injected := webhookInjectsIntoAPlainDeployment(t, cluster)

	t.Run("WebhookInjectsTheSidecarFirst", func(t *testing.T) { webhookSidecarIsFirst(t, cluster, injected) })
	t.Run("WebhookInjectedPodFilters", func(t *testing.T) { webhookInjectedPodFilters(t, cluster, injected) })
	t.Run("WebhookLeavesUnselectedPodsAlone", func(t *testing.T) { webhookLeavesUnselectedPodsAlone(t, cluster) })
	t.Run("WebhookHonoursTheOptOut", func(t *testing.T) { webhookHonoursTheOptOut(t, cluster) })

	audited := webhookInjectsAuditMode(t, cluster)

	t.Run("AuditModeSetsTheEnvironment", func(t *testing.T) { auditModeSetsTheEnvironment(t, cluster, audited) })
	t.Run("AuditModeAllowsUnmatchedTraffic", func(t *testing.T) { auditModeAllowsUnmatchedTraffic(t, cluster, audited) })
	t.Run("AuditModeLogsTheDecision", func(t *testing.T) { auditModeLogsTheDecision(t, cluster, audited) })
	t.Run("AuditModeSwitchesToBlock", func(t *testing.T) { auditModeSwitchesToBlock(t, cluster, audited) })
}

// docs/kubernetes.md tells operators a filtered namespace needs Pod Security
// `privileged` because NET_ADMIN is outside baseline. This proves that claim.
func podSecurityRejects(t *testing.T, cluster *harness.K3sCluster) {
	t.Helper()

	cluster.ApplyManifest(t, `
apiVersion: v1
kind: Namespace
metadata:
  name: baseline-ns
  labels:
    pod-security.kubernetes.io/enforce: baseline
`)

	out, err := cluster.TryApplyManifest(t, `
apiVersion: v1
kind: Pod
metadata:
  name: needs-net-admin
  namespace: baseline-ns
spec:
  containers:
    - name: app
      image: `+harness.AgentImage+`
      command: ['sleep', '60']
      securityContext:
        capabilities:
          drop: ['ALL']
          add: ['NET_ADMIN']
`)
	if err == nil {
		t.Fatalf("a baseline namespace accepted NET_ADMIN:\n%s", out)
	}

	if !strings.Contains(out, "violate") || !strings.Contains(out, "capabilities") {
		t.Errorf("rejection was not a Pod Security capabilities violation:\n%s", out)
	}
}

// startFilteredWorkload creates the policy, waits for the controller to render it,
// then runs a pod that mounts the rendered ConfigMap.
func startFilteredWorkload(t *testing.T, cluster *harness.K3sCluster) string {
	t.Helper()

	cluster.ApplyManifest(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: g0efilter-events
  namespace: %[1]s
rules:
  - apiGroups: ['']
    resources: ['events']
    verbs: ['create']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: g0efilter-events
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: g0efilter-events
subjects:
  - kind: ServiceAccount
    name: default
---
apiVersion: g0efilter.g0lab.com/v1alpha1
kind: EgressPolicy
metadata:
  name: web
  namespace: %[1]s
spec:
  egress:
    - name: cluster-dns
      to:
        - networks: ['%[2]s']
    - name: kubernetes-api
      to:
        - networks: ['%[3]s']
    - name: allowed-site
      to:
        - domainNames: ['example.com']
`, filteredNamespace, clusterDNS, kubernetesAPI))

	cluster.WaitForConfigMapContains(t, filteredNamespace, "g0efilter-web", "policy.yaml", "example.com")

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
      automountServiceAccountToken: true
      initContainers:
        - name: g0efilter
          image: %[2]s
          imagePullPolicy: IfNotPresent
          restartPolicy: Always
          env:
            - name: FILTER_MODE
              value: https
            - name: POLICY_PATH
              value: /app/policy/policy.yaml
            - name: LOG_LEVEL
              value: INFO
            - name: KUBE_EVENTS
              value: 'true'
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_UID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            readOnlyRootFilesystem: true
            capabilities:
              drop: ['ALL']
              add: ['NET_ADMIN']
          volumeMounts:
            - name: policy
              mountPath: /app/policy
              readOnly: true
        # Ordered after the sidecar; the component guarantees this position.
        - name: migrate
          image: %[2]s
          command: ['sleep', '1']
          securityContext:
            capabilities:
              drop: ['ALL']
      containers:
        - name: app
          image: docker.io/alpine/curl:latest
          command: ['sh', '-c', 'sleep infinity']
      volumes:
        - name: policy
          configMap:
            name: g0efilter-web
`, filteredNamespace, harness.AgentImage))

	pod := cluster.WaitForPodReady(t, filteredNamespace, "app=web")

	// Filtering is only in force once the ruleset is applied.
	cluster.WaitForPodLog(t, filteredNamespace, pod, "g0efilter", "startup.ready")

	return pod
}

func sidecarIsFirst(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	names := cluster.Get(t, filteredNamespace, "pod", pod, "{.spec.initContainers[*].name}")

	if !strings.HasPrefix(names, "g0efilter") {
		t.Errorf("init containers are %q; g0efilter must be first or the one before it "+
			"has unfiltered egress", names)
	}
}

// The whole point: a real pod, a controller-rendered policy, and live egress.
func filtersRealEgress(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	out, ok := cluster.CurlExternal(t, filteredNamespace, pod, "app", "https://example.com")
	if !ok {
		t.Errorf("an allowed destination was blocked: %s\n%s", out,
			cluster.PodLogs(t, filteredNamespace, pod, "g0efilter"))
	}

	out, ok = cluster.Exec(t, filteredNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "20", "https://github.com")
	if ok {
		t.Errorf("a destination outside the policy was allowed: %s", out)
	}

	cluster.WaitForPodLog(t, filteredNamespace, pod, "g0efilter", "github.com")
}

// Editing the EgressPolicy has to reach the running pod through the controller and
// kubelet's ConfigMap refresh, without a restart.
func reloadsOnPolicyChange(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	cluster.Kubectl(t, "patch", "-n", filteredNamespace, "egresspolicy", "web",
		"--type=json",
		`-p=[{"op":"add","path":"/spec/egress/-","value":{"name":"late","to":[{"domainNames":["github.com"]}]}}]`)

	cluster.WaitForConfigMapContains(t, filteredNamespace, "g0efilter-web", "policy.yaml", "github.com")

	// kubelet refreshes a mounted ConfigMap on its own schedule, so this is the slow
	// part; the sidecar then reloads without restarting.
	cluster.WaitForPodLog(t, filteredNamespace, pod, "g0efilter", "policy.reloaded")

	restarts := cluster.Get(t, filteredNamespace, "pod", pod,
		"{.status.initContainerStatuses[?(@.name=='g0efilter')].restartCount}")
	if strings.TrimSpace(restarts) != "0" {
		t.Errorf("the sidecar restarted (%s restarts) instead of reloading", restarts)
	}
}

// Events are the deny-debugging path an operator actually looks at. This runs before
// the reload subtest, which allows github.com and so removes the denial.
func recordsDenialEvents(t *testing.T, cluster *harness.K3sCluster, pod string) {
	t.Helper()

	logs := cluster.PodLogs(t, filteredNamespace, pod, "g0efilter")
	if !strings.Contains(logs, "kubeevents.enabled") {
		t.Fatalf("the sidecar did not enable Kubernetes Events:\n%s", logs)
	}

	_, _ = cluster.Exec(t, filteredNamespace, pod, "app",
		"curl", "-fsS", "-o", "/dev/null", "--max-time", "10", "https://github.com")

	message := cluster.WaitForEvent(t, filteredNamespace, pod, "EgressBlocked")

	if !strings.Contains(message, "blocked egress") {
		t.Errorf("unexpected event message: %q", message)
	}
}
