package webhook_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
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

func validatorScheme(t *testing.T) *runtime.Scheme {
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

func newValidator(t *testing.T, objects ...client.Object) *g0webhook.Validator {
	t.Helper()

	scheme := validatorScheme(t)

	return &g0webhook.Validator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
}

func validate(t *testing.T, v *g0webhook.Validator, kind string, object client.Object) admission.Response {
	t.Helper()

	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal %s: %v", kind, err)
	}

	return v.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind:      metav1.GroupVersionKind{Group: v1alpha1.GroupVersion.Group, Version: "v1alpha1", Kind: kind},
			Namespace: object.GetNamespace(),
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
}

const validatorNS = "apps"

func testNamespace(labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: validatorNS, Labels: labels}}
}

func policyWithRules(spec v1alpha1.SidecarSpec, rules ...v1alpha1.EgressRule) *v1alpha1.EgressPolicy {
	return &v1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: validatorNS},
		Spec:       v1alpha1.EgressPolicySpec{Sidecar: spec, Egress: rules},
	}
}

func domainRule(name string, domains []string, ports ...v1alpha1.EgressPort) v1alpha1.EgressRule {
	return v1alpha1.EgressRule{
		Name:  name,
		To:    []v1alpha1.EgressPeer{{DomainNames: domains}},
		Ports: ports,
	}
}

func TestValidatorAdmitsAnEnforceablePolicy(t *testing.T) {
	t.Parallel()

	v := newValidator(t, testNamespace(nil))
	policy := policyWithRules(v1alpha1.SidecarSpec{}, domainRule("apis", []string{"api.example.com"}))

	if got := validate(t, v, "EgressPolicy", policy); !got.Allowed {
		t.Errorf("policy denied: %s", got.Result.Message)
	}
}

func TestValidatorRejectsARuleTheModeCannotEnforce(t *testing.T) {
	t.Parallel()

	v := newValidator(t, testNamespace(nil))

	// Domain ports need dns-strict; https would silently widen the rule.
	policy := policyWithRules(v1alpha1.SidecarSpec{Mode: "https"},
		domainRule("apis", []string{"api.example.com"}, v1alpha1.EgressPort{Port: 8443, Protocol: "tcp"}))

	got := validate(t, v, "EgressPolicy", policy)
	if got.Allowed {
		t.Fatal("a rule the mode cannot enforce was admitted")
	}

	if !strings.Contains(got.Result.Message, "dns-strict") {
		t.Errorf("denial message does not name the required mode: %s", got.Result.Message)
	}
}

func TestValidatorRejectsAnUnrenderableDomain(t *testing.T) {
	t.Parallel()

	v := newValidator(t, testNamespace(nil))
	policy := policyWithRules(v1alpha1.SidecarSpec{}, domainRule("bad", []string{"*"}))

	if got := validate(t, v, "EgressPolicy", policy); got.Allowed {
		t.Fatal("a domain matching every destination was admitted")
	}
}

func TestValidatorRejectsAMalformedDNSUpstream(t *testing.T) {
	t.Parallel()

	v := newValidator(t, testNamespace(nil))
	spec := v1alpha1.SidecarSpec{Mode: "dns", DNS: v1alpha1.DNSSpec{Upstreams: []string{"10.96.0.10"}}}
	policy := policyWithRules(spec, domainRule("apis", []string{"api.example.com"}))

	got := validate(t, v, "EgressPolicy", policy)
	if got.Allowed {
		t.Fatal("an upstream without a port was admitted")
	}

	if !strings.Contains(got.Result.Message, "host:port") {
		t.Errorf("denial message does not explain the format: %s", got.Result.Message)
	}
}

// A baseline merges into every namespace it selects, so it is checked against those policies.
func TestValidatorRejectsABaselineThatBreaksAnExistingPolicy(t *testing.T) {
	t.Parallel()

	existing := policyWithRules(v1alpha1.SidecarSpec{Mode: "https"},
		domainRule("apis", []string{"api.example.com"}))

	v := newValidator(t, testNamespace(map[string]string{"tier": "app"}), existing)

	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "base"},
		Spec: v1alpha1.ClusterEgressPolicySpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "app"}},
			Egress: []v1alpha1.EgressRule{
				domainRule("logs", []string{"logs.example.com"}, v1alpha1.EgressPort{Port: 8443, Protocol: "tcp"}),
			},
		},
	}

	got := validate(t, v, "ClusterEgressPolicy", baseline)
	if got.Allowed {
		t.Fatal("a baseline that makes an existing https policy unenforceable was admitted")
	}

	if !strings.Contains(got.Result.Message, "apps/web") {
		t.Errorf("denial message does not name the broken policy: %s", got.Result.Message)
	}
}

func TestValidatorAdmitsABaselineTheSelectedNamespacesCanEnforce(t *testing.T) {
	t.Parallel()

	existing := policyWithRules(v1alpha1.SidecarSpec{Mode: "https"},
		domainRule("apis", []string{"api.example.com"}))

	v := newValidator(t, testNamespace(map[string]string{"tier": "app"}), existing)

	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "base"},
		Spec: v1alpha1.ClusterEgressPolicySpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "app"}},
			Egress:            []v1alpha1.EgressRule{domainRule("logs", []string{"logs.example.com"})},
		},
	}

	if got := validate(t, v, "ClusterEgressPolicy", baseline); !got.Allowed {
		t.Errorf("an enforceable baseline was denied: %s", got.Result.Message)
	}
}

// A policy the baseline does not select cannot be made unenforceable by it, and one
// already-broken policy must not freeze every later baseline edit.
func TestValidatorIgnoresAPolicyTheBaselineDoesNotSelect(t *testing.T) {
	t.Parallel()

	other := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"tier": "legacy"}},
	}
	broken := &v1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: other.Name},
		Spec: v1alpha1.EgressPolicySpec{
			Sidecar: v1alpha1.SidecarSpec{Mode: "https"},
			Egress: []v1alpha1.EgressRule{
				domainRule("apis", []string{"api.example.com"}, v1alpha1.EgressPort{Port: 8443, Protocol: "tcp"}),
			},
		},
	}
	selected := policyWithRules(v1alpha1.SidecarSpec{Mode: "https"}, domainRule("apis", []string{"api.example.com"}))

	v := newValidator(t, testNamespace(map[string]string{"tier": "app"}), other, selected, broken)

	baseline := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "base"},
		Spec: v1alpha1.ClusterEgressPolicySpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "app"}},
			Egress:            []v1alpha1.EgressRule{domainRule("logs", []string{"logs.example.com"})},
		},
	}

	if got := validate(t, v, "ClusterEgressPolicy", baseline); !got.Allowed {
		t.Errorf("an unrelated broken policy blocked a baseline edit: %s", got.Result.Message)
	}
}

// Replacing a baseline must be judged on the new rules, not the committed ones.
func TestValidatorJudgesABaselineUpdateOnItsNewRules(t *testing.T) {
	t.Parallel()

	committed := &v1alpha1.ClusterEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "base"},
		Spec: v1alpha1.ClusterEgressPolicySpec{
			Egress: []v1alpha1.EgressRule{
				domainRule("logs", []string{"logs.example.com"}, v1alpha1.EgressPort{Port: 8443, Protocol: "tcp"}),
			},
		},
	}
	existing := policyWithRules(v1alpha1.SidecarSpec{Mode: "https"},
		domainRule("apis", []string{"api.example.com"}))

	v := newValidator(t, testNamespace(nil), committed, existing)

	relaxed := committed.DeepCopy()
	relaxed.Spec.Egress = []v1alpha1.EgressRule{domainRule("logs", []string{"logs.example.com"})}

	if got := validate(t, v, "ClusterEgressPolicy", relaxed); !got.Allowed {
		t.Errorf("an update that removes the unenforceable port was denied: %s", got.Result.Message)
	}
}

func TestValidateUpstreams(t *testing.T) {
	t.Parallel()

	valid := []string{"10.96.0.10:53", "[fd00::10]:53", "kube-dns.kube-system.svc:5353"}

	err := g0webhook.ValidateUpstreams(valid)
	if err != nil {
		t.Errorf("ValidateUpstreams(%v) = %v, want nil", valid, err)
	}

	for _, upstream := range []string{"10.96.0.10", ":53", "10.96.0.10:0", "10.96.0.10:65536", "10.96.0.10:dns"} {
		err = g0webhook.ValidateUpstreams([]string{upstream})
		if err == nil {
			t.Errorf("ValidateUpstreams([%q]) = nil, want an error", upstream)
		}
	}
}
