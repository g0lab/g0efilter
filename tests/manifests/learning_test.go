package manifests_test

import (
	"path/filepath"
	"testing"
)

// policyVolume returns the pod's g0efilter-policy volume.
func policyVolume(t *testing.T, pod map[string]any) map[string]any {
	t.Helper()

	for _, entry := range list(t, pod, "volumes") {
		if volume, ok := entry.(map[string]any); ok && volume["name"] == "g0efilter-policy" {
			return volume
		}
	}

	t.Fatal("no g0efilter-policy volume")

	return nil
}

func policyMount(t *testing.T, pod map[string]any) map[string]any {
	t.Helper()

	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)

	for _, entry := range list(t, sidecar, "volumeMounts") {
		if mount, ok := entry.(map[string]any); ok && mount["mountPath"] == "/app/policy" {
			return mount
		}
	}

	t.Fatal("the sidecar does not mount /app/policy")

	return nil
}

// Learning mode appends to the policy file, so a read-only ConfigMap mount would
// make it silently learn nothing.
func assertLearningWiring(t *testing.T, pod map[string]any) {
	t.Helper()

	if got := sidecarEnv(t, pod)["LEARNING_MODE"]["value"]; got != "true" {
		t.Errorf("LEARNING_MODE = %v, want \"true\"", got)
	}

	volume := policyVolume(t, pod)

	if _, ok := volume["emptyDir"]; !ok {
		t.Errorf("the policy volume is not an emptyDir: %v", volume)
	}

	// Leaving the ConfigMap source alongside emptyDir is rejected by the API server.
	if _, ok := volume["configMap"]; ok {
		t.Errorf("the policy volume still has a configMap source: %v", volume)
	}

	if policyMount(t, pod)["readOnly"] != false {
		t.Errorf("the policy mount is still read-only: %v", policyMount(t, pod))
	}
}

func TestLearningComponentCoversEveryWorkloadKind(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-learning"))))

	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			doc, ok := docs[kind]
			if !ok {
				t.Fatalf("%s was not rendered", kind)
			}

			pod := podSpec(t, doc)

			assertSidecarFirst(t, pod)
			assertSidecarSecurity(t, pod)
			assertLearningWiring(t, pod)

			// The base configuration has to survive the add-on's patch.
			env := sidecarEnv(t, pod)
			for _, name := range []string{"FILTER_MODE", "POLICY_PATH", "LOG_LEVEL"} {
				if _, ok := env[name]; !ok {
					t.Errorf("the learning patch dropped %s", name)
				}
			}
		})
	}
}

// Enforcement is the default; learning must never be on unless asked for.
func TestSidecarComponentAloneEnforces(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds"))))
	pod := podSpec(t, docs["Deployment"])

	if _, ok := sidecarEnv(t, pod)["LEARNING_MODE"]; ok {
		t.Error("the base component enabled learning mode")
	}

	if _, ok := policyVolume(t, pod)["configMap"]; !ok {
		t.Error("the base component did not mount the policy ConfigMap")
	}

	if policyMount(t, pod)["readOnly"] != true {
		t.Error("the base component left the policy mount writable")
	}
}

func TestHelmLearningModeMatchesTheComponent(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("examples", "helm", "demo")

	chart = localHelmChart(t, chart)

	fromHelm := byKind(t, decodeDocs(t, run(t, "helm", "template", "release", chart,
		"--set", "g0efilter.learning.enabled=true")))

	assertLearningWiring(t, podSpec(t, fromHelm["Deployment"]))
}
