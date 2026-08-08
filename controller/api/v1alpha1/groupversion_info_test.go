package v1alpha1_test

import (
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToSchemeRegistersAPIObjects(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()

	err := v1alpha1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	objects := []struct {
		object   runtime.Object
		wantKind string
	}{
		{object: &v1alpha1.EgressPolicy{}, wantKind: "EgressPolicy"},
		{object: &v1alpha1.EgressPolicyList{}, wantKind: "EgressPolicyList"},
		{object: &v1alpha1.ClusterEgressPolicy{}, wantKind: "ClusterEgressPolicy"},
		{object: &v1alpha1.ClusterEgressPolicyList{}, wantKind: "ClusterEgressPolicyList"},
	}
	for _, test := range objects {
		gvks, _, err := scheme.ObjectKinds(test.object)
		if err != nil {
			t.Fatalf("ObjectKinds(%T) error = %v", test.object, err)
		}

		want := v1alpha1.GroupVersion.WithKind(test.wantKind)
		if len(gvks) != 1 || gvks[0] != want {
			t.Errorf("ObjectKinds(%T) = %v, want [%s]", test.object, gvks, want)
		}
	}
}
