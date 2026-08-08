package manifests_test

import (
	"path/filepath"
	"testing"
)

// podAnnotations returns the pod template's annotations, which live one level above
// the pod spec.
func podAnnotations(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	spec := child(t, doc, "spec")

	if doc["kind"] == "CronJob" {
		spec = child(t, child(t, spec, "jobTemplate"), "spec")
	}

	template := child(t, spec, "template")

	annotations, ok := child(t, template, "metadata")["annotations"].(map[string]any)
	if !ok {
		t.Fatalf("no pod annotations on %v", doc["kind"])
	}

	return annotations
}

func assertMetricsWiring(t *testing.T, doc map[string]any) {
	t.Helper()

	pod := podSpec(t, doc)

	if got := sidecarEnv(t, pod)["METRICS_ADDR"]["value"]; got != ":9095" {
		t.Errorf("METRICS_ADDR = %v, want :9095", got)
	}

	// The declared port is what makes the sidecar scrapable by name.
	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)

	ports := list(t, sidecar, "ports")
	if len(ports) != 1 {
		t.Fatalf("sidecar declares %d ports, want 1", len(ports))
	}

	port, ok := ports[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected port entry %T", ports[0])
	}

	if port["name"] != "metrics" || port["containerPort"] != 9095 {
		t.Errorf("port = %v, want metrics/9095", port)
	}

	annotations := podAnnotations(t, doc)
	if annotations["prometheus.io/scrape"] != "true" || annotations["prometheus.io/port"] != "9095" {
		t.Errorf("scrape annotations = %v", annotations)
	}
}

func TestMetricsComponentCoversEveryWorkloadKind(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-metrics"))))

	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			doc, ok := docs[kind]
			if !ok {
				t.Fatalf("%s was not rendered", kind)
			}

			assertSidecarFirst(t, podSpec(t, doc))
			assertPolicyMount(t, podSpec(t, doc))
			assertMetricsWiring(t, doc)

			env := sidecarEnv(t, podSpec(t, doc))
			for _, name := range []string{"FILTER_MODE", "POLICY_PATH", "LOG_LEVEL"} {
				if _, ok := env[name]; !ok {
					t.Errorf("the metrics patch dropped %s", name)
				}
			}
		})
	}
}

// Metrics open a port, so they must not appear unless asked for.
func TestSidecarComponentAloneExposesNoPort(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds"))))
	pod := podSpec(t, docs["Deployment"])

	if _, ok := sidecarEnv(t, pod)["METRICS_ADDR"]; ok {
		t.Error("the base component enabled metrics")
	}

	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)
	if _, ok := sidecar["ports"]; ok {
		t.Error("the base component declared a container port")
	}
}

func TestHelmMetricsMatchTheComponent(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	run(t, "helm", "dependency", "update", chart)

	fromHelm := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.metrics.enabled=true")))

	fromKustomize := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-metrics"))))

	helmSidecar := containerNamed(t, list(t, podSpec(t, fromHelm["Deployment"]), "initContainers"), sidecarName)
	kzSidecar := containerNamed(t, list(t, podSpec(t, fromKustomize["Deployment"]), "initContainers"), sidecarName)

	if normalise(t, helmSidecar["ports"]) != normalise(t, kzSidecar["ports"]) {
		t.Errorf("declared ports differ:\nhelm:      %s\nkustomize: %s",
			normalise(t, helmSidecar["ports"]), normalise(t, kzSidecar["ports"]))
	}

	if got := sidecarEnv(t, podSpec(t, fromHelm["Deployment"]))["METRICS_ADDR"]["value"]; got != ":9095" {
		t.Errorf("METRICS_ADDR = %v, want :9095", got)
	}
}
