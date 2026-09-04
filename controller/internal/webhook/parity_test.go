package webhook_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	g0webhook "github.com/g0lab/g0efilter/controller/internal/webhook"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// component is the shape of deploy/kustomize/sidecar/kustomization.yaml that
// matters here: the first patch carries the sidecar for the workload kinds whose
// pod template lives at spec.template.
type component struct {
	Patches []struct {
		Patch string `json:"patch"`
	} `json:"patches"`
}

type workloadPatch struct {
	Spec struct {
		Template struct {
			Spec corev1.PodSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

func kustomizeSidecar(t *testing.T) corev1.Container {
	t.Helper()

	path := filepath.Join("..", "..", "..", "deploy", "kustomize", "sidecar", "kustomization.yaml")

	raw, err := os.ReadFile(path) //nolint:gosec // a fixed repository path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var parsed component

	err = yaml.Unmarshal(raw, &parsed)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	if len(parsed.Patches) == 0 {
		t.Fatalf("%s declares no patches", path)
	}

	var workload workloadPatch

	err = yaml.Unmarshal([]byte(parsed.Patches[0].Patch), &workload)
	if err != nil {
		t.Fatalf("parse the sidecar patch: %v", err)
	}

	containers := workload.Spec.Template.Spec.InitContainers
	if len(containers) != 1 || containers[0].Name != g0webhook.ContainerName {
		t.Fatalf("the component's first patch does not carry the sidecar: %v", containers)
	}

	return containers[0]
}

// The webhook, the Kustomize component and the Helm library chart all add the same
// container. tests/manifests keeps Helm and Kustomize in step; this keeps the
// webhook with them, so the same workload is filtered identically however it was
// deployed.
func TestInjectedSidecarMatchesTheKustomizeComponent(t *testing.T) {
	t.Parallel()

	want := kustomizeSidecar(t)

	injector := newInjector(t, policy("policy", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{
		Image:     want.Image,
		Mode:      "",
		LogLevel:  "",
		Events:    false,
		Metrics:   v1alpha1.MetricsSpec{Enabled: false, Port: 0, Annotations: false},
		Resources: corev1.ResourceRequirements{Limits: nil, Requests: nil, Claims: nil},
	}))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	got := patched.Spec.InitContainers[0]

	assertSecurityContextMatches(t, got, want)
	assertEnvMatches(t, got, want)
	assertMountMatches(t, got, want)

	if !equalResources(got.Resources, want.Resources) {
		t.Errorf("resources differ:\nwebhook:   %v\nkustomize: %v", got.Resources, want.Resources)
	}

	if got.RestartPolicy == nil || want.RestartPolicy == nil || *got.RestartPolicy != *want.RestartPolicy {
		t.Errorf("restartPolicy differs: webhook=%v kustomize=%v", got.RestartPolicy, want.RestartPolicy)
	}
}

func assertSecurityContextMatches(t *testing.T, got, want corev1.Container) {
	t.Helper()

	if got.SecurityContext == nil || want.SecurityContext == nil {
		t.Fatal("one of the sidecars has no securityContext")
	}

	gotJSON, err := yaml.Marshal(got.SecurityContext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	wantJSON, err := yaml.Marshal(want.SecurityContext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(gotJSON) != string(wantJSON) {
		t.Errorf("securityContext differs:\nwebhook:\n%s\nkustomize:\n%s", gotJSON, wantJSON)
	}
}

func assertEnvMatches(t *testing.T, got, want corev1.Container) {
	t.Helper()

	gotEnv := envOf(got)
	wantEnv := envOf(want)

	if len(gotEnv) != len(wantEnv) {
		t.Errorf("env differs: webhook=%v kustomize=%v", gotEnv, wantEnv)

		return
	}

	for name, value := range wantEnv {
		if gotEnv[name] != value {
			t.Errorf("%s = %q, kustomize sets %q", name, gotEnv[name], value)
		}
	}
}

func assertMountMatches(t *testing.T, got, want corev1.Container) {
	t.Helper()

	if len(got.VolumeMounts) != 1 || len(want.VolumeMounts) != 1 {
		t.Fatalf("volume mounts: webhook=%v kustomize=%v", got.VolumeMounts, want.VolumeMounts)
	}

	if !reflect.DeepEqual(got.VolumeMounts[0], want.VolumeMounts[0]) {
		t.Errorf("volume mount differs:\nwebhook:   %v\nkustomize: %v", got.VolumeMounts[0], want.VolumeMounts[0])
	}
}

func equalResources(got, want corev1.ResourceRequirements) bool {
	if len(got.Requests) != len(want.Requests) || len(got.Limits) != len(want.Limits) {
		return false
	}

	for name, quantity := range want.Requests {
		if !quantity.Equal(got.Requests[name]) {
			return false
		}
	}

	for name, quantity := range want.Limits {
		if !quantity.Equal(got.Limits[name]) {
			return false
		}
	}

	return true
}

// The default image the webhook injects must be the tag the Kustomize component and
// the Helm chart pin, or the same policy would run different agents.
func TestDefaultSidecarImageMatchesThePackaging(t *testing.T) {
	t.Parallel()

	want := kustomizeSidecar(t)

	path := filepath.Join("..", "..", "..", "deploy", "kustomize", "sidecar", "kustomization.yaml")

	raw, err := os.ReadFile(path) //nolint:gosec // a fixed repository path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var images struct {
		Images []struct {
			Name   string `json:"name"`
			NewTag string `json:"newTag"`
		} `json:"images"`
	}

	err = yaml.Unmarshal(raw, &images)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	if len(images.Images) != 1 {
		t.Fatalf("the component pins %d images, want 1", len(images.Images))
	}

	pinned := images.Images[0].Name + ":" + images.Images[0].NewTag

	if want.Image != images.Images[0].Name {
		t.Errorf("the patch names %q but the component pins %q", want.Image, images.Images[0].Name)
	}

	if g0webhook.DefaultImage != pinned {
		t.Errorf("the webhook injects %q, the component renders %q", g0webhook.DefaultImage, pinned)
	}
}
