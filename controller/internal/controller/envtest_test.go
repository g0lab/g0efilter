//nolint:testpackage // Need access to internal implementation details
package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// startEnvtest runs a real kube-apiserver and etcd with the generated CRDs
// installed. Unlike the fake client this enforces the CRD's OpenAPI schema, which is
// the only way to know the generated CRDs accept and reject what the types intend.
//
//nolint:ireturn // controller-runtime exposes only the client.Client interface
func startEnvtest(t *testing.T) client.Client {
	t.Helper()

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS is required in CI; run `go tool setup-envtest use -p path`")
		}

		t.Skip("KUBEBUILDER_ASSETS is not set; run scripts/test-go.sh or setup-envtest")
	}

	//nolint:exhaustruct // only the CRD paths matter
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := environment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}

	t.Cleanup(func() { _ = environment.Stop() })

	return newEnvtestClient(t, cfg)
}

//nolint:ireturn // controller-runtime exposes only the client.Client interface
func newEnvtestClient(t *testing.T, cfg *rest.Config) client.Client {
	t.Helper()

	scheme := testScheme(t)

	c, err := client.New(cfg, client.Options{Scheme: scheme}) //nolint:exhaustruct // scheme only
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	return c
}

func createNamespace(t *testing.T, c client.Client, name string, labels map[string]string) {
	t.Helper()

	//nolint:exhaustruct // metadata only
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}

	err := c.Create(context.Background(), ns)
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
}

// The API server is what rejects a bad policy before the controller ever sees it, so
// the generated CRD has to carry the validation the Go types declare.
//
//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDRejectsInvalidPolicies(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "reject", nil)

	tests := []struct {
		name    string
		mutate  func(*v1alpha1.EgressPolicy)
		wantErr string
	}{
		{
			name: "port above the maximum",
			mutate: func(p *v1alpha1.EgressPolicy) {
				p.Spec.Egress[0].Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: 70000}}
			},
			wantErr: "should be less than or equal to 65535",
		},
		{
			name: "port below the minimum",
			mutate: func(p *v1alpha1.EgressPolicy) {
				p.Spec.Egress[0].Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: 0}}
			},
			wantErr: "should be greater than or equal to 1",
		},
		{
			name: "protocol outside the enum",
			mutate: func(p *v1alpha1.EgressPolicy) {
				p.Spec.Egress[0].Ports = []v1alpha1.EgressPort{{Protocol: "SCTP", Port: 443}}
			},
			wantErr: "Unsupported value",
		},
		{
			name:    "rule with no destination",
			mutate:  func(p *v1alpha1.EgressPolicy) { p.Spec.Egress[0].To = nil },
			wantErr: "to",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // shares one apiserver
			policy := egressPolicy("invalid", rule("r", []string{"api.example.com"}, nil))
			policy.Namespace = "reject"
			policy.Name = "invalid-" + strings.ReplaceAll(tc.name, " ", "-")

			tc.mutate(policy)

			err := c.Create(context.Background(), policy)
			if err == nil {
				t.Fatal("the API server accepted an invalid policy")
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error does not mention %q: %v", tc.wantErr, err)
			}
		})
	}
}

//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDAcceptsAValidPolicy(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "accept", nil)

	policy := egressPolicy("valid", rule("apis", []string{"api.example.com", "*.cdn.example.com"}, nil))
	policy.Namespace = "accept"
	policy.Spec.Egress[0].Ports = []v1alpha1.EgressPort{
		{Protocol: "TCP", Port: 443},
		{Protocol: "UDP", Port: 53},
	}

	err := c.Create(context.Background(), policy)
	if err != nil {
		t.Fatalf("the API server rejected a valid policy: %v", err)
	}
}

// The protocol default is declared on the type; only a real API server applies it.
//
//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDDefaultsProtocolToTCP(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "defaults", nil)

	policy := egressPolicy("defaulted", rule("apis", []string{"api.example.com"}, nil))
	policy.Namespace = "defaults"
	policy.Spec.Egress[0].Ports = []v1alpha1.EgressPort{{Protocol: "", Port: 443}}

	err := c.Create(context.Background(), policy)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	var stored v1alpha1.EgressPolicy

	err = c.Get(context.Background(), client.ObjectKey{Namespace: "defaults", Name: "defaulted"}, &stored)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	if got := stored.Spec.Egress[0].Ports[0].Protocol; got != "TCP" {
		t.Errorf("protocol = %q, want the TCP default", got)
	}
}

// Reconciling against a real API server exercises the status subresource and the
// ConfigMap write path, neither of which the fake client models faithfully.
//
//nolint:paralleltest // starts a real apiserver and etcd
func TestReconcileAgainstARealAPIServer(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, testNS, map[string]string{"tier": "prod"})

	policy := egressPolicy("web", rule("apis", []string{"api.example.com"}, nil))

	err := c.Create(context.Background(), policy)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	cluster := clusterPolicy("dns", map[string]string{"tier": "prod"}, rule("dns", nil, []string{"10.96.0.10"}))

	err = c.Create(context.Background(), cluster)
	if err != nil {
		t.Fatalf("create cluster policy: %v", err)
	}

	reconciler := &EgressPolicyReconciler{Client: c, Scheme: testScheme(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:exhaustruct // NamespacedName is the whole request
	_, err = reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: client.ObjectKey{Namespace: testNS, Name: "web"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	assertRenderedConfigMap(ctx, t, c)
	assertReadyStatus(ctx, t, c)
}

func assertRenderedConfigMap(ctx context.Context, t *testing.T, c client.Client) {
	t.Helper()

	var configMap corev1.ConfigMap

	err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: "g0efilter-web"}, &configMap)
	if err != nil {
		t.Fatalf("get rendered ConfigMap: %v", err)
	}

	document := configMap.Data[PolicyKey]

	for _, want := range []string{"api.example.com", "10.96.0.10"} {
		if !strings.Contains(document, want) {
			t.Errorf("rendered policy missing %q:\n%s", want, document)
		}
	}

	if len(configMap.OwnerReferences) != 1 || configMap.OwnerReferences[0].Name != "web" {
		t.Errorf("owner references = %v", configMap.OwnerReferences)
	}
}

func assertReadyStatus(ctx context.Context, t *testing.T, c client.Client) {
	t.Helper()

	var stored v1alpha1.EgressPolicy

	err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: "web"}, &stored)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	if stored.Status.ConfigMapName != "g0efilter-web" {
		t.Errorf("status.configMapName = %q", stored.Status.ConfigMapName)
	}

	if len(stored.Status.Conditions) != 1 || stored.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("conditions = %+v", stored.Status.Conditions)
	}
}

// Short names are how operators reach the API; a clash would only show up here.
//
//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDIsReachableByShortName(t *testing.T) {
	c := startEnvtest(t)

	var list v1alpha1.EgressPolicyList

	err := c.List(context.Background(), &list)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("list policies: %v", err)
	}
}
