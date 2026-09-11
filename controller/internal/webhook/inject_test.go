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
	"k8s.io/apimachinery/pkg/types"
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
	withDependencies := make([]client.Object, 0, 1+len(objects))
	withDependencies = append(withDependencies,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}})

	for _, object := range objects {
		withDependencies = append(withDependencies, object)

		selected, ok := object.(*v1alpha1.EgressPolicy)
		if ok && selected.Status.ConfigMapName != "" {
			withDependencies = append(withDependencies, renderedConfigMap(selected))
		}
	}

	return &g0webhook.Injector{
		Client:   fake.NewClientBuilder().WithScheme(scheme).WithObjects(withDependencies...).Build(),
		Decoder:  admission.NewDecoder(scheme),
		Defaults: g0webhook.Defaults{Image: testImage},
	}
}

// renderedConfigMap stands in for what the reconciler wrote. Its document is
// deliberately not what this build renders: admission must not compare them.
func renderedConfigMap(policy *v1alpha1.EgressPolicy) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Status.ConfigMapName,
			Namespace: policy.Namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(),
				Kind:       "EgressPolicy",
				Name:       policy.Name,
				UID:        policy.UID,
				Controller: new(true),
			}},
		},
		Data: map[string]string{"policy.yaml": "domains: []\nnetworks: []\n"},
	}
}

func policy(name string, selector map[string]string, sidecar v1alpha1.SidecarSpec) *v1alpha1.EgressPolicy {
	noBaselines := emptyRevision()

	return &v1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: testNS, Generation: 1, UID: types.UID(name + "-uid"),
		},
		Spec: v1alpha1.EgressPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selector, MatchExpressions: nil},
			Egress:      nil,
			Sidecar:     sidecar,
		},
		Status: v1alpha1.EgressPolicyStatus{
			ObservedGeneration:      1,
			ConfigMapName:           "g0efilter-" + name,
			ObservedClusterRevision: noBaselines,
			Conditions: []metav1.Condition{{
				Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1,
			}},
		},
	}
}

// emptyRevision is what a current reconciler records where no cluster baseline
// selects the namespace, as distinct from the empty string an older one leaves.
func emptyRevision() string {
	_, revision, err := render.ClusterBaselines(nil, nil)
	if err != nil {
		panic(err)
	}

	return revision
}

func pod(labels, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: testNS, Labels: labels, Annotations: annotations},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app:1"}},
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

	result := &corev1.Pod{}

	err = json.Unmarshal(out, result)
	if err != nil {
		t.Fatalf("unmarshal patched pod: %v", err)
	}

	return result
}

func TestInjectsTheSidecarFirst(t *testing.T) {
	t.Parallel()

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

			injector := newInjector(t, policy("web", selector, v1alpha1.SidecarSpec{}))
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
		policy("alpha", selector, v1alpha1.SidecarSpec{}),
		policy("beta", selector, v1alpha1.SidecarSpec{}),
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
		policy("alpha", selector, v1alpha1.SidecarSpec{}),
		policy("beta", selector, v1alpha1.SidecarSpec{}),
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
	injector := newInjector(t, policy("alpha", selector, v1alpha1.SidecarSpec{}))

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
	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
		Spec: v1alpha1.ClusterEgressPolicySpec{Egress: []v1alpha1.EgressRule{{
			Name: "dns",
			To:   []v1alpha1.EgressPeer{{Networks: []string{"10.96.0.10"}}},
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

// Admission validates the merged result live, so the pair a raced policy edit can
// commit never reaches a pod: the sidecar would be unable to enforce it.
func TestDeniesWhenAClusterBaselineIsUnenforceableInTheSelectedMode(t *testing.T) {
	t.Parallel()

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{Mode: "https"})
	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
		Spec: v1alpha1.ClusterEgressPolicySpec{Egress: []v1alpha1.EgressRule{{
			Name:  "domain-port",
			To:    []v1alpha1.EgressPeer{{DomainNames: []string{"api.example.com"}}},
			Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 8443}},
		}}},
	}

	response, _ := admit(t, newInjector(t, selected, baseline), pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted under a policy its sidecar could not enforce")
	}

	if !strings.Contains(response.Result.Message, "dns-strict") {
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

// Admission must tolerate different renderer versions during a controller rollout.
func TestAdmitsWhenTheRenderedDocumentPredatesTheRunningWebhook(t *testing.T) {
	t.Parallel()

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})

	response, patched := admit(t, newInjector(t, selected), pod(map[string]string{"app": "web"}, nil))
	if !response.Allowed {
		t.Fatalf("a pod was denied over a document a newer webhook renders differently: %s",
			response.Result.Message)
	}

	if patched == nil {
		t.Fatal("the pod was not patched")
	}
}

func clusterBaseline(uid types.UID, generation int64, network string) *v1alpha1.ClusterEgressPolicy {
	return &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline", UID: uid, Generation: generation},
		Spec: v1alpha1.ClusterEgressPolicySpec{Egress: []v1alpha1.EgressRule{{
			Name: "dns",
			To:   []v1alpha1.EgressPeer{{Networks: []string{network}}},
		}}},
	}
}

func baselineRevision(t *testing.T, baselines ...v1alpha1.ClusterEgressPolicy) string {
	t.Helper()

	_, revision, err := render.ClusterBaselines(nil, baselines)
	if err != nil {
		t.Fatalf("ClusterBaselines() = %v", err)
	}

	return revision
}

func TestAdmitsOnceTheRenderedConfigMapCarriesTheClusterBaseline(t *testing.T) {
	t.Parallel()

	baseline := clusterBaseline("baseline-uid", 3, "10.96.0.10")

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	selected.Status.ObservedClusterRevision = baselineRevision(t, *baseline)

	response, _ := admit(t, newInjector(t, selected, baseline), pod(map[string]string{"app": "web"}, nil))
	if !response.Allowed {
		t.Fatalf("a pod was denied under a rendered baseline: %s", response.Result.Message)
	}

	// A baseline edit bumps its generation, so the same ConfigMap is now stale.
	baseline.Generation++

	response, _ = admit(t, newInjector(t, selected, baseline), pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted against a baseline edit that had not been rendered")
	}
}

// A recreated baseline restarts at generation 1, so name and generation alone
// cannot tell it from the one the ConfigMap was rendered from.
func TestDeniesWhenAClusterBaselineWasRecreatedWithDifferentRules(t *testing.T) {
	t.Parallel()

	before := clusterBaseline("first-uid", 1, "10.96.0.10")
	after := clusterBaseline("second-uid", 1, "10.96.0.99")

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	selected.Status.ObservedClusterRevision = baselineRevision(t, *before)

	response, _ := admit(t, newInjector(t, selected, after), pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted against a recreated baseline's unrendered rules")
	}
}

// A reconciler that predates observedClusterRevision records none, and a rollback
// drops it again. Denying then denies every pod for the length of the rollout.
func TestAdmitsWhileTheReconcilerHasNotRecordedARevision(t *testing.T) {
	t.Parallel()

	baseline := clusterBaseline("baseline-uid", 1, "10.96.0.10")

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	selected.Status.ObservedClusterRevision = ""

	response, patched := admit(t, newInjector(t, selected, baseline), pod(map[string]string{"app": "web"}, nil))
	if !response.Allowed {
		t.Fatalf("a pod was denied during a controller rollout: %s", response.Result.Message)
	}

	if patched == nil {
		t.Fatal("the pod was not patched")
	}
}

func TestDeniesWhenTheRenderedConfigMapIsMissing(t *testing.T) {
	t.Parallel()

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	injector := newInjector(t)

	err := injector.Client.Create(context.Background(), selected)
	if err != nil {
		t.Fatalf("create the policy: %v", err)
	}

	response, _ := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted with no ConfigMap to mount")
	}
}

func TestDeniesWhenTheConfigMapIsNotOwnedByThePolicy(t *testing.T) {
	t.Parallel()

	selected := policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{})
	foreign := renderedConfigMap(selected)
	foreign.OwnerReferences = nil

	scheme := testScheme(t)
	injector := &g0webhook.Injector{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}}, selected, foreign).Build(),
		Decoder:  admission.NewDecoder(scheme),
		Defaults: g0webhook.Defaults{Image: testImage},
	}

	response, _ := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if response.Allowed {
		t.Fatal("a pod was admitted against a ConfigMap the controller does not own")
	}
}
