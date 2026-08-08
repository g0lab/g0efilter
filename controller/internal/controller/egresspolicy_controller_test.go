//nolint:testpackage // Need access to internal implementation details
package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testNS = "apps"

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()

	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("add core scheme: %v", err)
	}

	err = v1alpha1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("add g0efilter scheme: %v", err)
	}

	return scheme
}

func namespace(labels map[string]string) *corev1.Namespace {
	//nolint:exhaustruct // only metadata matters
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS, Labels: labels}}
}

func rule(name string, domains []string, networks []string) v1alpha1.EgressRule {
	//nolint:exhaustruct // ports are set by the caller where relevant
	return v1alpha1.EgressRule{
		Name: name,
		To:   []v1alpha1.EgressPeer{{DomainNames: domains, Networks: networks}},
	}
}

func egressPolicy(name string, rules ...v1alpha1.EgressRule) *v1alpha1.EgressPolicy {
	//nolint:exhaustruct // status is filled by the reconciler
	return &v1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS, Generation: 1},
		Spec:       v1alpha1.EgressPolicySpec{Egress: rules},
	}
}

func clusterPolicy(
	name string,
	selector map[string]string,
	rules ...v1alpha1.EgressRule,
) *v1alpha1.ClusterEgressPolicy {
	//nolint:exhaustruct // status is filled by the reconciler
	return &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1},
		Spec: v1alpha1.ClusterEgressPolicySpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: selector}, //nolint:exhaustruct // MatchLabels only
			Egress:            rules,
		},
	}
}

//nolint:ireturn // the fake client is only usable through the client.Client interface
func newReconciler(t *testing.T, objects ...client.Object) (*EgressPolicyReconciler, client.Client) {
	t.Helper()

	scheme := testScheme(t)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&v1alpha1.EgressPolicy{}).
		Build()

	return &EgressPolicyReconciler{Client: fakeClient, Scheme: scheme}, fakeClient
}

func reconcile(t *testing.T, r *EgressPolicyReconciler, name string) {
	t.Helper()

	//nolint:exhaustruct // NamespacedName is the whole request
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNS, Name: name},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func getConfigMap(t *testing.T, c client.Client, name string) *corev1.ConfigMap {
	t.Helper()

	var configMap corev1.ConfigMap

	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, &configMap)
	if err != nil {
		t.Fatalf("get ConfigMap %s: %v", name, err)
	}

	return &configMap
}

//nolint:unparam // a general accessor; every current caller happens to want the same policy
func getPolicy(t *testing.T, c client.Client, name string) *v1alpha1.EgressPolicy {
	t.Helper()

	var policy v1alpha1.EgressPolicy

	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, &policy)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	return &policy
}

func TestReconcileRendersAConfigMap(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
	)

	reconcile(t, r, "web")

	configMap := getConfigMap(t, c, "g0efilter-web")

	document, ok := configMap.Data[PolicyKey]
	if !ok {
		t.Fatalf("ConfigMap has no %s key: %v", PolicyKey, configMap.Data)
	}

	if !strings.Contains(document, "api.example.com") {
		t.Errorf("rendered policy missing the domain:\n%s", document)
	}

	if configMap.Labels[managedByLabel] != managedByValue {
		t.Errorf("labels = %v", configMap.Labels)
	}

	// Without a controller owner reference the ConfigMap outlives its policy.
	if len(configMap.OwnerReferences) != 1 || configMap.OwnerReferences[0].Name != "web" {
		t.Errorf("owner references = %v", configMap.OwnerReferences)
	}

	policy := getPolicy(t, c, "web")
	if policy.Status.ConfigMapName != "g0efilter-web" || policy.Status.ObservedGeneration != 1 {
		t.Errorf("status = %+v", policy.Status)
	}

	if len(policy.Status.Conditions) != 1 || policy.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("conditions = %+v", policy.Status.Conditions)
	}
}

func TestSeveralPoliciesRenderSeparateConfigMaps(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("web", []string{"api.example.com"}, nil)),
		egressPolicy("batch", rule("batch", []string{"warehouse.example.com"}, nil)),
	)

	reconcile(t, r, "web")
	reconcile(t, r, "batch")

	web := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]
	batch := getConfigMap(t, c, "g0efilter-batch").Data[PolicyKey]

	if strings.Contains(web, "warehouse.example.com") || strings.Contains(batch, "api.example.com") {
		t.Errorf("policies leaked into each other:\nweb:\n%s\nbatch:\n%s", web, batch)
	}
}

func TestClusterPolicyRulesAreMergedIn(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(map[string]string{"tier": "prod"}),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
		clusterPolicy("dns", map[string]string{"tier": "prod"}, rule("dns", nil, []string{"10.96.0.10"})),
	)

	reconcile(t, r, "web")

	document := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]

	for _, want := range []string{"api.example.com", "10.96.0.10"} {
		if !strings.Contains(document, want) {
			t.Errorf("rendered policy missing %q:\n%s", want, document)
		}
	}
}

func TestClusterPolicyIsSkippedWhenTheNamespaceDoesNotMatch(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(map[string]string{"tier": "dev"}),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
		clusterPolicy("prod-dns", map[string]string{"tier": "prod"}, rule("dns", nil, []string{"10.96.0.10"})),
	)

	reconcile(t, r, "web")

	document := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]
	if strings.Contains(document, "10.96.0.10") {
		t.Errorf("a non-matching cluster policy was merged in:\n%s", document)
	}
}

// An empty namespaceSelector selects every namespace, which is how a cluster-wide
// baseline is expressed.
func TestClusterPolicyWithNoSelectorAppliesEverywhere(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
		clusterPolicy("baseline", nil, rule("dns", nil, []string{"10.96.0.10"})),
	)

	reconcile(t, r, "web")

	if !strings.Contains(getConfigMap(t, c, "g0efilter-web").Data[PolicyKey], "10.96.0.10") {
		t.Error("a cluster policy with no selector was not applied")
	}
}

// Replacing a working ConfigMap with an empty one because the new spec is invalid
// would open the pod's egress, so the old document has to survive.
func TestInvalidSpecLeavesThePreviousConfigMapIntact(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
	)

	reconcile(t, r, "web")

	before := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]

	policy := getPolicy(t, c, "web")
	policy.Spec.Egress = []v1alpha1.EgressRule{rule("broken", []string{"*"}, nil)}
	policy.Generation = 2

	err := c.Update(context.Background(), policy)
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	reconcile(t, r, "web")

	if got := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]; got != before {
		t.Errorf("an invalid spec rewrote the ConfigMap:\n%s", got)
	}

	updated := getPolicy(t, c, "web")
	if len(updated.Status.Conditions) != 1 || updated.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("conditions = %+v", updated.Status.Conditions)
	}

	if updated.Status.Conditions[0].Reason != reasonInvalidPolicy {
		t.Errorf("reason = %q", updated.Status.Conditions[0].Reason)
	}
}

// Reconciling repeatedly must converge, or every resync would rewrite the ConfigMap
// and reload every filtered pod.
func TestReconcileIsIdempotent(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("apis", []string{"b.example.com", "a.example.com"}, nil)),
	)

	reconcile(t, r, "web")

	first := getConfigMap(t, c, "g0efilter-web")
	firstVersion := first.ResourceVersion
	firstPolicyVersion := getPolicy(t, c, "web").ResourceVersion
	document := first.Data[PolicyKey]

	for range 3 {
		reconcile(t, r, "web")
	}

	after := getConfigMap(t, c, "g0efilter-web")

	if after.Data[PolicyKey] != document {
		t.Errorf("document changed across reconciles:\n%s\n---\n%s", document, after.Data[PolicyKey])
	}

	if after.ResourceVersion != firstVersion {
		t.Errorf("ConfigMap was rewritten unnecessarily: %s -> %s", firstVersion, after.ResourceVersion)
	}

	if got := getPolicy(t, c, "web").ResourceVersion; got != firstPolicyVersion {
		t.Errorf("status was rewritten unnecessarily: %s -> %s", firstPolicyVersion, got)
	}
}

func TestReconcileUpdatesAnExistingConfigMap(t *testing.T) {
	t.Parallel()

	r, c := newReconciler(t,
		namespace(nil),
		egressPolicy("web", rule("apis", []string{"api.example.com"}, nil)),
	)

	reconcile(t, r, "web")

	policy := getPolicy(t, c, "web")
	policy.Spec.Egress = []v1alpha1.EgressRule{rule("apis", []string{"other.example.com"}, nil)}
	policy.Generation = 2

	err := c.Update(context.Background(), policy)
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	reconcile(t, r, "web")

	document := getConfigMap(t, c, "g0efilter-web").Data[PolicyKey]

	if !strings.Contains(document, "other.example.com") {
		t.Errorf("the new destination was not rendered:\n%s", document)
	}

	if strings.Contains(document, "api.example.com") {
		t.Errorf("the removed destination is still allowed:\n%s", document)
	}
}

func TestReconcileCountsSelectedPods(t *testing.T) {
	t.Parallel()

	policy := egressPolicy("web", rule("apis", []string{"api.example.com"}, nil))
	policy.Spec.PodSelector = metav1.LabelSelector{ //nolint:exhaustruct // MatchLabels only
		MatchLabels: map[string]string{"app": "web"},
	}

	//nolint:exhaustruct // only labels and phase matter
	matching := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-1", Namespace: "apps", Labels: map[string]string{"app": "web"},
	}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	//nolint:exhaustruct // only labels and phase matter
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "batch-1", Namespace: "apps", Labels: map[string]string{"app": "batch"},
	}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	//nolint:exhaustruct // a selected pending pod must not be counted as running
	pending := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-pending", Namespace: "apps", Labels: map[string]string{"app": "web"},
	}, Status: corev1.PodStatus{Phase: corev1.PodPending}}

	r, c := newReconciler(t, namespace(nil), policy, matching, other, pending)

	reconcile(t, r, "web")

	if got := getPolicy(t, c, "web").Status.SelectedPods; got != 1 {
		t.Errorf("selectedPods = %d, want 1", got)
	}
}

// A deleted policy is garbage-collected through its owner reference, so reconciling
// one that no longer exists must be a no-op rather than an error.
func TestReconcileIgnoresADeletedPolicy(t *testing.T) {
	t.Parallel()

	r, _ := newReconciler(t, namespace(nil))

	reconcile(t, r, "gone")
}

func TestConfigMapNameFor(t *testing.T) {
	t.Parallel()

	if got := ConfigMapNameFor("web"); got != "g0efilter-web" {
		t.Errorf("ConfigMapNameFor(web) = %q", got)
	}
}

func TestConfigMapNameForLongPolicy(t *testing.T) {
	t.Parallel()

	name := ConfigMapNameFor(strings.Repeat("a", 253))
	if len(name) != maxConfigMapName {
		t.Fatalf("name has %d bytes, want %d: %q", len(name), maxConfigMapName, name)
	}

	other := ConfigMapNameFor(strings.Repeat("a", 252) + "b")
	if other == name {
		t.Error("different long policy names collided")
	}
}

func TestPoliciesInNamespaceEnqueuesOnlyThatNamespace(t *testing.T) {
	t.Parallel()

	other := egressPolicy("other")
	other.Namespace = "elsewhere"

	r, _ := newReconciler(t, egressPolicy("web"), egressPolicy("batch"), other)

	//nolint:exhaustruct // metadata only
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: testNS}}
	requests := r.policiesInNamespace(context.Background(), pod)

	if len(requests) != 2 {
		t.Fatalf("requests = %v, want the two policies in %s", requests, testNS)
	}

	for _, request := range requests {
		if request.Namespace != testNS {
			t.Errorf("enqueued policy from %q", request.Namespace)
		}
	}
}
