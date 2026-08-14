package manifests_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every kind the components patch. A component that misses one silently leaves that
// workload unfiltered.
var workloadKinds = []string{ //nolint:gochecknoglobals // the kind list is the tests' data
	"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
}

// Enforcement is stated on every rendered sidecar, so the posture can be read off a
// pod without knowing what the agent defaults to.
func TestSidecarComponentStatesBlockEnforcement(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds"))))

	for _, kind := range workloadKinds {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			if got := sidecarEnv(t, podSpec(t, docs[kind]))["ENFORCE"]["value"]; got != "block" {
				t.Errorf("ENFORCE = %v, want block", got)
			}
		})
	}
}

func TestAuditComponentCoversEveryWorkloadKind(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-audit"))))

	for _, kind := range workloadKinds {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			doc, ok := docs[kind]
			if !ok {
				t.Fatalf("%s was not rendered", kind)
			}

			pod := podSpec(t, doc)

			assertSidecarFirst(t, pod)
			assertPolicyMount(t, pod)

			env := sidecarEnv(t, pod)
			if got := env["ENFORCE"]["value"]; got != "audit" {
				t.Errorf("ENFORCE = %v, want audit", got)
			}

			// Auditing changes the verdict, not the policy or the data path.
			assertPolicyEnv(t, env)

			if got := env["FILTER_MODE"]["value"]; got != "https" {
				t.Errorf("the audit patch changed FILTER_MODE to %v", got)
			}
		})
	}
}

// Sharing the process namespace lets every container see the others' processes, so
// the injected sidecar must never ask for it.
func TestSidecarComponentSharesNoProcessNamespace(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds"))))
	pod := podSpec(t, docs["Deployment"])

	if _, ok := pod["shareProcessNamespace"]; ok {
		t.Error("the sidecar component shared the process namespace")
	}

	if _, ok := sidecarEnv(t, pod)["PROCESS_INFO"]; ok {
		t.Error("the sidecar component enabled process attribution")
	}
}

func TestHelmEnforcementMatchesTheAuditComponent(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	chart = localHelmChart(t, chart)

	fromHelm := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.enforcement=audit")))

	fromKustomize := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-audit"))))

	helmEnv := sidecarEnv(t, podSpec(t, fromHelm["Deployment"]))
	kzEnv := sidecarEnv(t, podSpec(t, fromKustomize["Deployment"]))

	if normalise(t, helmEnv["ENFORCE"]) != normalise(t, kzEnv["ENFORCE"]) {
		t.Errorf("ENFORCE differs:\nhelm:      %s\nkustomize: %s",
			normalise(t, helmEnv["ENFORCE"]), normalise(t, kzEnv["ENFORCE"]))
	}
}

// The library chart's optional knobs must stay absent until asked for, or the three
// packaging paths would drift apart on a default install.
func TestHelmOptionalSidecarEnvIsAbsentByDefault(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	docs := byKind(t, decodeDocs(t, helmTemplate(t, chart)))
	env := sidecarEnv(t, podSpec(t, docs["Deployment"]))

	for _, name := range []string{
		"TENANT_ID", "KUBE_EVENTS_MAX",
		"DASHBOARD_HOST", "DASHBOARD_API_KEY", "DASHBOARD_QUEUE_SIZE", "DASHBOARD_START_DELAY",
		"ENABLE_REMOTE_UNBLOCK", "UNBLOCK_POLL_INTERVAL",
		"NOTIFICATION_URLS", "NOTIFICATION_BACKOFF_SECONDS", "NOTIFICATION_IGNORE_DOMAINS",
		"DNS_UPSTREAMS", "DNS_HARDENING", "DNS_RATE_QPS", "DNS_RATE_BURST",
		"HTTP_PORT", "HTTPS_PORT", "DNS_PORT",
		"MAX_CONNECTIONS", "CONN_MAX_LIFETIME_MS", "NFLOG_BUFSIZE", "NFLOG_QTHRESH",
	} {
		if _, ok := env[name]; ok {
			t.Errorf("%s is set on a default sidecar", name)
		}
	}
}

// A null numeric value renders nothing; 0 is a real value and has to survive.
func TestHelmRendersZeroValuedNumbers(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	chart = localHelmChart(t, chart)

	docs := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.connections.max=0",
		"--set", "g0efilter.events.enabled=true",
		"--set", "g0efilter.events.maxDenials=0")))

	env := sidecarEnv(t, podSpec(t, docs["Deployment"]))

	if got := env["MAX_CONNECTIONS"]["value"]; got != "0" {
		t.Errorf("MAX_CONNECTIONS = %v, want 0", got)
	}

	if got := env["KUBE_EVENTS_MAX"]["value"]; got != "0" {
		t.Errorf("KUBE_EVENTS_MAX = %v, want 0", got)
	}
}

func TestHelmRendersTheFullSidecarOptionSurface(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	chart = localHelmChart(t, chart)

	docs := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.tenantId=tenant-a",
		"--set", "g0efilter.dashboard.host=http://dash.svc:8081",
		"--set", "g0efilter.dashboard.apiKeySecret.name=dash-key",
		"--set", "g0efilter.dashboard.queueSize=2048",
		"--set", "g0efilter.dashboard.startDelay=10s",
		"--set", "g0efilter.dashboard.remoteUnblock=true",
		"--set", "g0efilter.notifications.ignoreDomains={*.noise.example.com}",
		"--set", "g0efilter.dns.upstreams={10.43.0.10:53}",
		"--set", "g0efilter.dns.hardening=false",
		"--set", "g0efilter.ports.https=15443",
		"--set", "g0efilter.connections.maxLifetimeMs=600000",
		"--set", "g0efilter.nflog.bufSize=128")))

	env := sidecarEnv(t, podSpec(t, docs["Deployment"]))

	for name, want := range map[string]string{
		"TENANT_ID":                   "tenant-a",
		"DASHBOARD_HOST":              "http://dash.svc:8081",
		"DASHBOARD_QUEUE_SIZE":        "2048",
		"DASHBOARD_START_DELAY":       "10s",
		"ENABLE_REMOTE_UNBLOCK":       "true",
		"NOTIFICATION_IGNORE_DOMAINS": "*.noise.example.com",
		"DNS_UPSTREAMS":               "10.43.0.10:53",
		"DNS_HARDENING":               "false",
		"HTTPS_PORT":                  "15443",
		"CONN_MAX_LIFETIME_MS":        "600000",
		"NFLOG_BUFSIZE":               "128",
	} {
		if got := env[name]["value"]; got != want {
			t.Errorf("%s = %v, want %q", name, got, want)
		}
	}

	// The key is referenced, never inlined into the pod spec.
	ref, ok := env["DASHBOARD_API_KEY"]["valueFrom"].(map[string]any)
	if !ok {
		t.Fatalf("DASHBOARD_API_KEY is not read from a Secret: %v", env["DASHBOARD_API_KEY"])
	}

	if got := child(t, ref, "secretKeyRef")["name"]; got != "dash-key" {
		t.Errorf("secret name = %v, want dash-key", got)
	}
}

func TestHelmRejectsMetricsProxyPortConflict(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")
	chart = localHelmChart(t, chart)

	out := runHelmExpectingFailure(t, "template", "release", chart,
		"--set", "g0efilter.metrics.enabled=true",
		"--set", "g0efilter.metrics.port=65443")
	if !strings.Contains(out, "must differ") {
		t.Errorf("error does not explain the port conflict:\n%s", out)
	}
}
