package manifests_test

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var helmTestMu sync.Mutex //nolint:gochecknoglobals // Helm rewrites local chart dependencies

func serialHelm(t *testing.T) {
	t.Helper()
	helmTestMu.Lock()
	t.Cleanup(helmTestMu.Unlock)
}

func updateHelmDependency(t *testing.T, chart string) {
	t.Helper()
	helmTestMu.Lock()
	defer helmTestMu.Unlock()

	run(t, "helm", "dependency", "update", chart)
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

// helmTemplate resolves the local library-chart dependency first, which is what a
// consumer does with `helm dependency update`.
func helmTemplate(t *testing.T, chart string) []byte {
	t.Helper()

	run(t, "helm", "dependency", "update", chart)

	return run(t, "helm", "template", "release", chart)
}

func TestHelmLibraryChartInjectsTheSidecar(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	docs := byKind(t, decodeDocs(t, helmTemplate(t, repoPath("examples", "helm", "demo"))))

	deployment, ok := docs["Deployment"]
	if !ok {
		t.Fatal("the demo chart did not render a Deployment")
	}

	pod := podSpec(t, deployment)

	assertSidecarFirst(t, pod)
	assertSidecarSecurity(t, pod)
	assertPolicyMount(t, pod)
	assertAppUntouched(t, pod)
}

// The library chart and the Kustomize component must produce the same sidecar, or
// the same workload would be filtered differently depending on the packaging.
func TestHelmAndKustomizeAgreeOnTheSidecar(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	fromHelm := byKind(t, decodeDocs(t, helmTemplate(t, repoPath("examples", "helm", "demo"))))
	fromKustomize := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-events"))))

	helmPod := podSpec(t, fromHelm["Deployment"])
	kzPod := podSpec(t, fromKustomize["Deployment"])

	helmSidecar := containerNamed(t, list(t, helmPod, "initContainers"), sidecarName)
	kzSidecar := containerNamed(t, list(t, kzPod, "initContainers"), sidecarName)

	for _, key := range []string{"image", "restartPolicy", "securityContext", "resources", "volumeMounts"} {
		if normalise(t, helmSidecar[key]) != normalise(t, kzSidecar[key]) {
			t.Errorf("sidecar %s differs between Helm and Kustomize:\nhelm:      %s\nkustomize: %s",
				key, normalise(t, helmSidecar[key]), normalise(t, kzSidecar[key]))
		}
	}

	// Compared by name because Kustomize merges env entries while Helm appends.
	helmEnv := sidecarEnv(t, helmPod)
	kzEnv := sidecarEnv(t, kzPod)

	if len(helmEnv) != len(kzEnv) {
		t.Errorf("sidecar env names differ: helm=%d kustomize=%d", len(helmEnv), len(kzEnv))
	}

	for name, kzEntry := range kzEnv {
		helmEntry, ok := helmEnv[name]
		if !ok {
			t.Errorf("the Helm chart does not set %s", name)

			continue
		}

		if normalise(t, helmEntry) != normalise(t, kzEntry) {
			t.Errorf("env %s differs:\nhelm:      %s\nkustomize: %s",
				name, normalise(t, helmEntry), normalise(t, kzEntry))
		}
	}
}

func TestHelmChartsLint(t *testing.T) {
	t.Parallel()

	for _, chart := range []string{
		repoPath("deploy", "helm", "g0efilter"),
		repoPath("examples", "helm", "demo"),
	} {
		t.Run(chart, func(t *testing.T) {
			t.Parallel()
			serialHelm(t)

			run(t, "helm", "dependency", "update", chart)
			run(t, "helm", "lint", chart)
		})
	}
}

// The post-renderer is the only path that needs no cooperation from the chart, so
// it is verified against a chart with no g0efilter support at all.
func TestPostRendererInjectsIntoAnUnmodifiedChart(t *testing.T) {
	t.Parallel()

	chart := filepath.Join("testdata", "unfiltered-chart")
	rendered := run(t, "helm", "template", "third-party", chart)

	before := byKind(t, decodeDocs(t, rendered))

	pod := podSpec(t, before["Deployment"])
	if _, ok := pod["initContainers"]; ok {
		t.Fatal("the fixture chart already has init containers; it must start with none")
	}

	script := requireBinary(t, "bash")

	ctx, cancel := context.WithTimeout(t.Context(), toolTimeout)
	defer cancel()

	//nolint:gosec // bash resolved through LookPath, running a script from this repo
	cmd := exec.CommandContext(ctx, script, repoPath("deploy", "helm", "post-renderer.sh"))
	cmd.Stdin = bytes.NewReader(rendered)

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("post-renderer: %v\n%s", err, stderr.String())
	}

	after := byKind(t, decodeDocs(t, out))

	injected := podSpec(t, after["Deployment"])

	assertSidecarFirst(t, injected)
	assertSidecarSecurity(t, injected)
	assertPolicyMount(t, injected)
	assertAppUntouched(t, injected)
}

// runHelmExpectingFailure returns the output of a Helm command that must fail.
func runHelmExpectingFailure(t *testing.T, args ...string) string {
	t.Helper()

	bin := requireBinary(t, "helm")

	ctx, cancel := context.WithTimeout(t.Context(), toolTimeout)
	defer cancel()

	//nolint:gosec // fixed tool names resolved through LookPath, with literal arguments
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("helm %v unexpectedly succeeded:\n%s", args, out)
	}

	return string(out)
}

// values.schema.json is what turns a silent misconfiguration into a failed render,
// so the cases it must catch are worth asserting.
func TestHelmValuesSchemaRejectsBadValues(t *testing.T) {
	t.Parallel()

	chart := repoPath("examples", "helm", "demo")

	updateHelmDependency(t, chart)

	tests := []struct {
		name    string
		set     string
		wantErr string
	}{
		{name: "unknown filter mode", set: "g0efilter.mode=bogus", wantErr: "'/mode'"},
		{name: "misspelled key", set: "g0efilter.logLevl=DEBUG", wantErr: "additional properties"},
		{name: "root uid", set: "g0efilter.runAsUser=0", wantErr: "'/runAsUser'"},
		{name: "relative policy mount", set: "g0efilter.policy.mountPath=app/policy", wantErr: "'/policy/mountPath'"},
		{name: "non-boolean events flag", set: "g0efilter.events.enabled=maybe", wantErr: "'/events/enabled'"},
		{name: "proxy port collision", set: "g0efilter.ports.http=15000,g0efilter.ports.https=15000", wantErr: "must differ"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serialHelm(t)

			out := runHelmExpectingFailure(t, "template", "release", chart, "--set", tc.set)
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("error did not mention %q:\n%s", tc.wantErr, out)
			}
		})
	}
}

func TestHelmAcceptsFractionalDurations(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")
	run(t, "helm", "dependency", "update", chart)

	run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.dashboard.startDelay=1.5s",
		"--set", "g0efilter.dashboard.unblockPollInterval=0.5m")
}

// The library chart's own values.yaml supplies the defaults through Helm's subchart
// coalescing, so a consumer that sets nothing still gets a working sidecar.
func TestHelmDefaultsComeFromTheLibraryChart(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := filepath.Join("testdata", "minimal-consumer")

	run(t, "helm", "dependency", "update", chart)

	docs := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart)))

	pod := podSpec(t, docs["Deployment"])
	assertSidecarFirst(t, pod)
	assertSidecarSecurity(t, pod)
	assertPolicyMount(t, pod)

	env := sidecarEnv(t, pod)
	if got := env["FILTER_MODE"]["value"]; got != "https" {
		t.Errorf("FILTER_MODE = %v, want the library default https", got)
	}

	// Events are opt-in, so a consumer that says nothing gets no API access.
	if _, ok := env["KUBE_EVENTS"]; ok {
		t.Error("events were enabled without the consumer asking")
	}

	if _, ok := docs["Role"]; ok {
		t.Error("an events Role was rendered without the consumer asking")
	}
}

func TestHelmPolicyCommandUsesTheConfiguredConfigMap(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	run(t, "helm", "dependency", "update", chart)

	docs := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.policy.configMapName=team-policy")))

	env := sidecarEnv(t, podSpec(t, docs["Deployment"]))
	if env["POLICY_CONFIGMAP"]["value"] != "team-policy" {
		t.Errorf("POLICY_CONFIGMAP = %v, want team-policy", env["POLICY_CONFIGMAP"]["value"])
	}

	if _, ok := env["POD_NAMESPACE"]["valueFrom"]; !ok {
		t.Error("POD_NAMESPACE is not populated from the pod metadata")
	}
}
