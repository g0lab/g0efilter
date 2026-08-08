package manifests_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// sidecarEnv indexes the sidecar's env by name; downward-API entries have no value.
func sidecarEnv(t *testing.T, pod map[string]any) map[string]map[string]any {
	t.Helper()

	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)
	out := make(map[string]map[string]any)

	for _, entry := range list(t, sidecar, "env") {
		if e, ok := entry.(map[string]any); ok {
			if name, ok := e["name"].(string); ok {
				out[name] = e
			}
		}
	}

	return out
}

// The Events add-on must leave the base sidecar configuration intact, which a
// list-replacing patch would silently destroy.
func assertEventsWiring(t *testing.T, pod map[string]any) {
	t.Helper()

	env := sidecarEnv(t, pod)

	if got := env["KUBE_EVENTS"]["value"]; got != "true" {
		t.Errorf("KUBE_EVENTS = %v, want \"true\"", got)
	}

	for _, name := range []string{"POD_NAME", "POD_NAMESPACE", "POD_UID"} {
		entry, ok := env[name]
		if !ok {
			t.Errorf("%s is not exposed via the downward API", name)

			continue
		}

		if _, ok := entry["valueFrom"]; !ok {
			t.Errorf("%s has no valueFrom fieldRef", name)
		}
	}

	for _, name := range []string{"FILTER_MODE", "POLICY_PATH", "LOG_LEVEL"} {
		if _, ok := env[name]; !ok {
			t.Errorf("the events patch dropped %s from the sidecar", name)
		}
	}

	// Without a mounted token the sidecar cannot authenticate to the API server.
	if pod["automountServiceAccountToken"] != true {
		t.Error("automountServiceAccountToken was not enabled")
	}
}

func TestEventsComponentWiresEveryWorkloadKind(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-events"))))

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
			assertPolicyMount(t, pod)
			assertEventsWiring(t, pod)
		})
	}
}

// Creating events in one namespace is the whole permission; anything broader would
// be a needless privilege for a filtering sidecar.
func TestEventsComponentGrantsOnlyEventCreation(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("testdata", "all-kinds-events"))))

	role, ok := docs["Role"]
	if !ok {
		t.Fatal("no Role was rendered")
	}

	rules := list(t, role, "rules")
	if len(rules) != 1 {
		t.Fatalf("Role has %d rules, want 1", len(rules))
	}

	rule, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected rule type %T", rules[0])
	}

	if got := normalise(t, rule["resources"]); got != "- events\n" {
		t.Errorf("resources = %q, want only events", got)
	}

	if got := normalise(t, rule["verbs"]); got != "- create\n" {
		t.Errorf("verbs = %q, want only create", got)
	}

	if _, ok := docs["RoleBinding"]; !ok {
		t.Error("no RoleBinding was rendered")
	}

	// A ClusterRole would grant the permission cluster-wide.
	if _, ok := docs["ClusterRole"]; ok {
		t.Error("the events component rendered a ClusterRole")
	}
}

// The base component must not turn on API access by itself.
func TestSidecarComponentAloneGrantsNoAPIAccess(t *testing.T) {
	t.Parallel()

	raw := string(renderKustomize(t, filepath.Join("testdata", "all-kinds")))

	for _, banned := range []string{"KUBE_EVENTS", "automountServiceAccountToken", "RoleBinding"} {
		if strings.Contains(raw, banned) {
			t.Errorf("the base component rendered %s", banned)
		}
	}
}

func TestHelmEventsRBACIsOptIn(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	docs := byKind(t, decodeDocs(t, helmTemplate(t, repoPath("examples", "helm", "demo"))))

	if _, ok := docs["Role"]; !ok {
		t.Fatal("the demo chart enables events but rendered no Role")
	}

	assertEventsWiring(t, podSpec(t, docs["Deployment"]))
}
