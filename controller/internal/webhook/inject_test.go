package webhook_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
	g0webhook "github.com/g0lab/g0efilter/controller/internal/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	testImage = "docker.io/g0lab/g0efilter:test"
	testNS    = "tenant"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()

	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("core scheme: %v", err)
	}

	err = v1alpha1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("g0efilter scheme: %v", err)
	}

	return scheme
}

func newInjector(t *testing.T, objects ...client.Object) *g0webhook.Injector {
	t.Helper()

	scheme := testScheme(t)
	withDependencies := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}}, //nolint:exhaustruct // metadata only
	}

	for _, object := range objects {
		withDependencies = append(withDependencies, object)

		policy, ok := object.(*v1alpha1.EgressPolicy)
		if !ok || policy.Status.ConfigMapName == "" {
			continue
		}

		document, err := render.RulesForMode(policy.Spec.Sidecar.Mode, policy.Spec.Egress)
		if err != nil {
			t.Fatalf("render test policy: %v", err)
		}

		withDependencies = append(withDependencies, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: policy.Status.ConfigMapName, Namespace: policy.Namespace},
			Data:       map[string]string{"policy.yaml": document.Document()},
		})
	}

	return &g0webhook.Injector{
		Client:   fake.NewClientBuilder().WithScheme(scheme).WithObjects(withDependencies...).Build(),
		Decoder:  admission.NewDecoder(scheme),
		Defaults: g0webhook.Defaults{Image: testImage},
	}
}

func policy(name string, selector map[string]string, sidecar v1alpha1.SidecarSpec) *v1alpha1.EgressPolicy {
	//nolint:exhaustruct // only the fields under test
	return &v1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS, Generation: 1},
		Spec: v1alpha1.EgressPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selector, MatchExpressions: nil},
			Egress:      nil,
			Sidecar:     sidecar,
		},
		Status: v1alpha1.EgressPolicyStatus{
			ObservedGeneration: 1,
			ConfigMapName:      "g0efilter-" + name,
			Conditions: []metav1.Condition{{ //nolint:exhaustruct // readiness fields only
				Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1,
			}},
		},
	}
}

func pod(labels, annotations map[string]string) *corev1.Pod {
	//nolint:exhaustruct // only the fields under test
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: testNS, Labels: labels, Annotations: annotations},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app:1"}}, //nolint:exhaustruct // name and image only
		},
	}
}

// admit runs the handler and returns the response plus the pod after patching.
func admit(t *testing.T, injector *g0webhook.Injector, subject *corev1.Pod) (admission.Response, *corev1.Pod) {
	t.Helper()

	raw, err := json.Marshal(subject)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	//nolint:exhaustruct // only the fields the handler reads
	response := injector.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: testNS,
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw, Object: nil},
		},
	})

	if !response.Allowed || len(response.Patches) == 0 {
		return response, nil
	}

	patched := applyPatches(t, raw, response)

	return response, patched
}

func applyPatches(t *testing.T, raw []byte, response admission.Response) *corev1.Pod {
	t.Helper()

	encoded, err := json.Marshal(response.Patches)
	if err != nil {
		t.Fatalf("marshal patches: %v", err)
	}

	patch, err := jsonpatch.DecodePatch(encoded)
	if err != nil {
		t.Fatalf("decode patches: %v", err)
	}

	out, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("apply patches: %v", err)
	}

	result := &corev1.Pod{} //nolint:exhaustruct // decoded into

	err = json.Unmarshal(out, result)
	if err != nil {
		t.Fatalf("unmarshal patched pod: %v", err)
	}

	return result
}

func TestInjectsTheSidecarFirst(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // the defaults are the subject
	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{}))
	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))

	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	if len(patched.Spec.InitContainers) == 0 || patched.Spec.InitContainers[0].Name != g0webhook.ContainerName {
		t.Fatalf("init containers = %v; the sidecar must be first", patched.Spec.InitContainers)
	}

	sidecar := patched.Spec.InitContainers[0]

	if sidecar.Image != testImage {
		t.Errorf("image = %q, want %q", sidecar.Image, testImage)
	}

	if sidecar.RestartPolicy == nil || *sidecar.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Error("the sidecar is not a native sidecar: restartPolicy must be Always")
	}

	if envOf(sidecar)["POLICY_CONFIGMAP"] != "g0efilter-web" {
		t.Errorf("POLICY_CONFIGMAP = %q", envOf(sidecar)["POLICY_CONFIGMAP"])
	}

	if !hasFieldRef(sidecar.Env, "POD_NAMESPACE", "metadata.namespace") {
		t.Error("POD_NAMESPACE is not populated from the pod metadata")
	}

	assertPolicyVolume(t, patched, "g0efilter-web")

	if patched.Annotations[g0webhook.InjectedAnnotation] != "web" {
		t.Errorf("injected-from = %q, want web", patched.Annotations[g0webhook.InjectedAnnotation])
	}
}

func assertPolicyVolume(t *testing.T, patched *corev1.Pod, configMap string) {
	t.Helper()

	for _, volume := range patched.Spec.Volumes {
		if volume.Name != g0webhook.VolumeName {
			continue
		}

		if volume.ConfigMap == nil || volume.ConfigMap.Name != configMap {
			t.Errorf("policy volume = %v, want ConfigMap %s", volume.VolumeSource, configMap)
		}

		return
	}

	t.Errorf("no %s volume on the patched pod", g0webhook.VolumeName)
}

func TestSkipsPodsThatShouldNotBeFiltered(t *testing.T) {
	t.Parallel()

	selector := map[string]string{"app": "web"}

	//nolint:exhaustruct // only the fields under test
	withSidecar := pod(selector, nil)
	withSidecar.Spec.InitContainers = []corev1.Container{{Name: g0webhook.ContainerName, Image: "old"}}

	hostNetwork := pod(selector, nil)
	hostNetwork.Spec.HostNetwork = true

	tests := map[string]*corev1.Pod{
		"opted out":        pod(selector, map[string]string{g0webhook.InjectAnnotation: "false"}),
		"already filtered": withSidecar,
		"host network":     hostNetwork,
		"not selected":     pod(map[string]string{"app": "other"}, nil),
		"no labels at all": pod(nil, nil),
	}

	for name, subject := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			injector := newInjector(t, policy("web", selector, v1alpha1.SidecarSpec{})) //nolint:exhaustruct // defaults
			response, patched := admit(t, injector, subject)

			if !response.Allowed {
				t.Fatalf("the pod was denied: %v", response.Result)
			}

			if patched != nil {
				t.Errorf("the pod was patched: %v", patched.Spec.InitContainers)
			}
		})
	}
}

// A pod selected by two policies would be filtered by whichever the controller
// happened to pick, so admission fails with an actionable message instead.
func TestDeniesWhenSeveralPoliciesSelectThePod(t *testing.T) {
	t.Parallel()

	selector := map[string]string{"app": "web"}

	injector := newInjector(t,
		policy("alpha", selector, v1alpha1.SidecarSpec{}), //nolint:exhaustruct // defaults
		policy("beta", selector, v1alpha1.SidecarSpec{}),  //nolint:exhaustruct // defaults
	)

	response, _ := admit(t, injector, pod(selector, nil))

	if response.Allowed {
		t.Fatal("an ambiguous pod was admitted")
	}

	if message := response.Result.Message; message == "" ||
		!strings.Contains(message, "alpha") || !strings.Contains(message, "beta") ||
		!strings.Contains(message, g0webhook.PolicyAnnotation) {
		t.Errorf("denial does not say how to resolve it: %q", message)
	}
}

func TestPolicyAnnotationChoosesBetweenPolicies(t *testing.T) {
	t.Parallel()

	selector := map[string]string{"app": "web"}

	injector := newInjector(t,
		policy("alpha", selector, v1alpha1.SidecarSpec{}), //nolint:exhaustruct // defaults
		policy("beta", selector, v1alpha1.SidecarSpec{}),  //nolint:exhaustruct // defaults
	)

	_, patched := admit(t, injector, pod(selector, map[string]string{g0webhook.PolicyAnnotation: "beta"}))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	assertPolicyVolume(t, patched, "g0efilter-beta")
}

func TestDeniesWhenTheNamedPolicyDoesNotSelectThePod(t *testing.T) {
	t.Parallel()

	selector := map[string]string{"app": "web"}
	injector := newInjector(t, policy("alpha", selector, v1alpha1.SidecarSpec{})) //nolint:exhaustruct // defaults

	response, _ := admit(t, injector, pod(selector, map[string]string{g0webhook.PolicyAnnotation: "missing"}))
	if response.Allowed {
		t.Fatal("a pod naming an unrelated policy was admitted")
	}
}

func TestDeniesUntilTheSelectedPolicyIsReady(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*v1alpha1.EgressPolicy){
		"not reconciled": func(policy *v1alpha1.EgressPolicy) {
			policy.Status = v1alpha1.EgressPolicyStatus{}
		},
		"stale generation": func(policy *v1alpha1.EgressPolicy) {
			policy.Generation++
		},
		"rejected generation": func(policy *v1alpha1.EgressPolicy) {
			policy.Status.Conditions[0].Status = metav1.ConditionFalse
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
			mutate(selected)

			response, _ := admit(t, newInjector(t, selected), pod(map[string]string{"app": "web"}, nil))
			if response.Allowed {
				t.Fatal("a pod was admitted before its policy was ready")
			}

			if !strings.Contains(response.Result.Message, "not ready") {
				t.Errorf("denial = %q", response.Result.Message)
			}
		})
	}
}

func TestDeniesWhenAClusterPolicyHasNotReachedTheConfigMap(t *testing.T) {
	t.Parallel()

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	//nolint:exhaustruct // selector and status are intentionally empty
	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
		Spec: v1alpha1.ClusterEgressPolicySpec{Egress: []v1alpha1.EgressRule{{
			Name: "dns",
			To:   []v1alpha1.EgressPeer{{Networks: []string{"10.96.0.10"}}}, //nolint:exhaustruct // networks only
		}}},
	}

	response, _ := admit(t, newInjector(t, selected, baseline), pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted with a stale cluster baseline")
	}

	if !strings.Contains(response.Result.Message, "stale") {
		t.Errorf("denial = %q", response.Result.Message)
	}
}

func TestSidecarSpecOverridesTheDefaults(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{
		Image:     "example.com/g0efilter:custom",
		Mode:      "dns-strict",
		LogLevel:  "DEBUG",
		Events:    true,
		Metrics:   v1alpha1.MetricsSpec{Enabled: true, Port: 9110, Annotations: true},
		Resources: corev1.ResourceRequirements{Limits: nil, Requests: nil, Claims: nil},
	}

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, spec))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	sidecar := patched.Spec.InitContainers[0]

	if sidecar.Image != spec.Image {
		t.Errorf("image = %q, want %q", sidecar.Image, spec.Image)
	}

	env := envOf(sidecar)
	for key, want := range map[string]string{
		"FILTER_MODE":  "dns-strict",
		"LOG_LEVEL":    "DEBUG",
		"KUBE_EVENTS":  "true",
		"METRICS_ADDR": ":9110",
	} {
		if env[key] != want {
			t.Errorf("%s = %q, want %q", key, env[key], want)
		}
	}

	// Events are posted with the pod's own token, so it has to be mounted.
	if patched.Spec.AutomountServiceAccountToken == nil || !*patched.Spec.AutomountServiceAccountToken {
		t.Error("events are enabled but the ServiceAccount token is not mounted")
	}

	if patched.Annotations["prometheus.io/port"] != "9110" {
		t.Errorf("scrape annotations = %v", patched.Annotations)
	}

	if len(sidecar.Ports) != 1 || sidecar.Ports[0].ContainerPort != 9110 {
		t.Errorf("ports = %v, want metrics on 9110", sidecar.Ports)
	}
}

func TestProcessInfoRejectsAnExplicitPrivatePIDNamespace(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{ProcessInfo: true} //nolint:exhaustruct // one field under test
	subject := pod(map[string]string{"app": "web"}, nil)
	disabled := false
	subject.Spec.ShareProcessNamespace = &disabled

	response, _ := admit(t, newInjector(t, policy("web", map[string]string{"app": "web"}, spec)), subject)
	if response.Allowed {
		t.Fatal("a pod with an incompatible PID namespace was admitted")
	}

	if !strings.Contains(response.Result.Message, "shareProcessNamespace") {
		t.Errorf("denial = %q", response.Result.Message)
	}
}

func TestProcessInfoPreservesHostPID(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{ProcessInfo: true} //nolint:exhaustruct // one field under test
	subject := pod(map[string]string{"app": "web"}, nil)
	subject.Spec.HostPID = true

	_, patched := admit(t, newInjector(t, policy("web", map[string]string{"app": "web"}, spec)), subject)
	if patched == nil {
		t.Fatal("the hostPID pod was not patched")
	}

	if patched.Spec.ShareProcessNamespace != nil {
		t.Errorf("shareProcessNamespace = %v, want unset", *patched.Spec.ShareProcessNamespace)
	}
}

func envOf(container corev1.Container) map[string]string {
	out := make(map[string]string, len(container.Env))
	for _, entry := range container.Env {
		out[entry.Name] = entry.Value
	}

	return out
}

func hasFieldRef(entries []corev1.EnvVar, name, path string) bool {
	for _, entry := range entries {
		if entry.Name == name && entry.ValueFrom != nil && entry.ValueFrom.FieldRef != nil &&
			entry.ValueFrom.FieldRef.FieldPath == path {
			return true
		}
	}

	return false
}
