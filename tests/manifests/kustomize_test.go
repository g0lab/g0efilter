// Package manifests_test renders the shipped Kubernetes manifests and asserts the
// sidecar they inject, so a packaging regression fails here rather than in a
// consumer's cluster.
package manifests_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"
)

const (
	sidecarName = "g0efilter"
	toolTimeout = 60 * time.Second
)

// requireBinary skips locally when a tool is missing, but fails in CI: a silent
// skip there would mean the manifests were never checked at all.
func requireBinary(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is required in CI: %v", name, err)
		}

		t.Skipf("%s is not installed", name)
	}

	return path
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()

	bin := requireBinary(t, name)

	ctx, cancel := context.WithTimeout(t.Context(), toolTimeout)
	defer cancel()

	//nolint:gosec // fixed tool names resolved through LookPath, with literal arguments
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			t.Fatalf("%s %v: %v\n%s", name, args, err, exitErr.Stderr)
		}

		t.Fatalf("%s %v: %v", name, args, err)
	}

	return out
}

func renderKustomize(t *testing.T, dir string) []byte {
	t.Helper()

	return run(t, "kubectl", "kustomize", dir)
}

func decodeDocs(t *testing.T, raw []byte) []map[string]any {
	t.Helper()

	var docs []map[string]any

	dec := yaml.NewDecoder(bytes.NewReader(raw))

	for {
		var doc map[string]any

		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("decode rendered yaml: %v", err)
		}

		if doc != nil {
			docs = append(docs, doc)
		}
	}

	return docs
}

// normalise renders a value as canonical YAML so two packagings can be compared.
func normalise(t *testing.T, value any) string {
	t.Helper()

	out, err := yaml.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}

	return string(out)
}

func child(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()

	got, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("expected a map at %q, got %T", key, m[key])
	}

	return got
}

func list(t *testing.T, m map[string]any, key string) []any {
	t.Helper()

	got, ok := m[key].([]any)
	if !ok {
		t.Fatalf("expected a list at %q, got %T", key, m[key])
	}

	return got
}

// podSpec returns a workload's pod spec, which CronJob nests one level deeper.
func podSpec(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	spec := child(t, doc, "spec")

	if doc["kind"] == "CronJob" {
		spec = child(t, child(t, spec, "jobTemplate"), "spec")
	}

	return child(t, child(t, spec, "template"), "spec")
}

func containerNamed(t *testing.T, containers []any, name string) map[string]any {
	t.Helper()

	for _, entry := range containers {
		c, ok := entry.(map[string]any)
		if ok && c["name"] == name {
			return c
		}
	}

	t.Fatalf("no container named %q", name)

	return nil
}

func byKind(t *testing.T, docs []map[string]any) map[string]map[string]any {
	t.Helper()

	out := make(map[string]map[string]any, len(docs))

	for _, doc := range docs {
		kind, ok := doc["kind"].(string)
		if !ok {
			t.Fatalf("document without a kind: %v", doc)
		}

		out[kind] = doc
	}

	return out
}

func TestSidecarComponentCoversEveryWorkloadKind(t *testing.T) {
	t.Parallel()

	raw := renderKustomize(t, filepath.Join("testdata", "all-kinds"))
	docs := byKind(t, decodeDocs(t, raw))

	// Every kind that renders a pod template must be covered.
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
			assertAppUntouched(t, pod)
		})
	}
}

// The sidecar must be the first init container: an init container that runs before
// it would have unfiltered egress.
func assertSidecarFirst(t *testing.T, pod map[string]any) {
	t.Helper()

	inits := list(t, pod, "initContainers")

	first, ok := inits[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected initContainers[0]: %T", inits[0])
	}

	if first["name"] != sidecarName {
		t.Errorf("initContainers[0] is %v, want %s", first["name"], sidecarName)
	}

	// restartPolicy: Always is what makes it a native sidecar rather than a init
	// container that must exit before the app starts.
	if first["restartPolicy"] != "Always" {
		t.Errorf("restartPolicy = %v, want Always", first["restartPolicy"])
	}
}

func assertSidecarSecurity(t *testing.T, pod map[string]any) {
	t.Helper()

	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)
	sc := child(t, sidecar, "securityContext")

	wantFlags := map[string]any{
		"runAsNonRoot":             true,
		"runAsUser":                65534,
		"readOnlyRootFilesystem":   true,
		"allowPrivilegeEscalation": false,
	}

	for key, want := range wantFlags {
		if sc[key] != want {
			t.Errorf("securityContext.%s = %v, want %v", key, sc[key], want)
		}
	}

	assertCapabilities(t, child(t, sc, "capabilities"))
}

// NET_ADMIN is the only capability the image needs now that it carries a file
// capability; SETUID, SETGID and CHOWN existed only for the old privilege drop.
func assertCapabilities(t *testing.T, capabilities map[string]any) {
	t.Helper()

	drop := list(t, capabilities, "drop")
	if len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("capabilities.drop = %v, want [ALL]", drop)
	}

	add := list(t, capabilities, "add")
	if len(add) != 1 || add[0] != "NET_ADMIN" {
		t.Errorf("capabilities.add = %v, want exactly [NET_ADMIN]", add)
	}
}

func assertPolicyMount(t *testing.T, pod map[string]any) {
	t.Helper()

	sidecar := containerNamed(t, list(t, pod, "initContainers"), sidecarName)
	assertPolicyEnv(t, sidecarEnv(t, pod))

	var mounted bool

	for _, entry := range list(t, sidecar, "volumeMounts") {
		mount, ok := entry.(map[string]any)
		if ok && mount["mountPath"] == "/app/policy" {
			mounted = true

			if mount["readOnly"] != true {
				t.Error("the policy mount is not readOnly")
			}
		}
	}

	if !mounted {
		t.Error("the sidecar does not mount /app/policy")
	}

	for _, entry := range list(t, pod, "volumes") {
		volume, ok := entry.(map[string]any)
		if ok && volume["name"] == "g0efilter-policy" {
			// A directory mount is required for live reload: kubelet swaps the
			// symlink, which a single-file subPath mount would never see.
			if child(t, volume, "configMap")["name"] != "g0efilter-policy" {
				t.Error("the policy volume does not reference the g0efilter-policy ConfigMap")
			}

			return
		}
	}

	t.Error("no g0efilter-policy volume was added")
}

func assertPolicyEnv(t *testing.T, env map[string]map[string]any) {
	t.Helper()

	if env["POLICY_CONFIGMAP"]["value"] != "g0efilter-policy" {
		t.Errorf("POLICY_CONFIGMAP = %v", env["POLICY_CONFIGMAP"]["value"])
	}

	if _, ok := env["POD_NAMESPACE"]["valueFrom"]; !ok {
		t.Error("POD_NAMESPACE is not populated from the pod metadata")
	}
}

// Injecting the sidecar must not grant the application container privileges or
// expose the policy to it; whatever else the consumer declared is their business.
func assertAppUntouched(t *testing.T, pod map[string]any) {
	t.Helper()

	app := containerNamed(t, list(t, pod, "containers"), "app")

	if sc, ok := app["securityContext"].(map[string]any); ok {
		if capabilities, ok := sc["capabilities"].(map[string]any); ok {
			if added, ok := capabilities["add"]; ok {
				t.Errorf("the application container gained capabilities: %v", added)
			}
		}
	}

	mounts, ok := app["volumeMounts"].([]any)
	if !ok {
		return
	}

	for _, entry := range mounts {
		if mount, ok := entry.(map[string]any); ok && mount["name"] == "g0efilter-policy" {
			t.Error("the policy was mounted into the application container")
		}
	}
}

// The old privilege-drop knobs must not reappear anywhere in the rendered output.
func TestRenderedManifestsHaveNoPrivilegeDropLeftovers(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{
		filepath.Join("testdata", "all-kinds"),
		filepath.Join("..", "..", "examples", "kubernetes"),
	} {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()

			rendered := string(renderKustomize(t, dir))

			for _, banned := range []string{"SETUID", "SETGID", "CHOWN", "PUID", "PGID", "ALLOW_ROOT_FALLBACK"} {
				if strings.Contains(rendered, banned) {
					t.Errorf("rendered output still references %s", banned)
				}
			}
		})
	}
}

func TestExampleOverlayRenders(t *testing.T) {
	t.Parallel()

	raw := renderKustomize(t, filepath.Join("..", "..", "examples", "kubernetes"))
	docs := decodeDocs(t, raw)

	kinds := byKind(t, docs)

	for _, want := range []string{"Namespace", "ConfigMap", "Deployment"} {
		if _, ok := kinds[want]; !ok {
			t.Errorf("the example overlay does not render a %s", want)
		}
	}

	pod := podSpec(t, kinds["Deployment"])
	assertSidecarFirst(t, pod)
	assertPolicyMount(t, pod)
}
