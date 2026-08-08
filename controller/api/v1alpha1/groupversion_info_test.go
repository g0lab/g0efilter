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

	objects := []runtime.Object{
		&v1alpha1.EgressPolicy{},
		&v1alpha1.EgressPolicyList{},
		&v1alpha1.ClusterEgressPolicy{},
		&v1alpha1.ClusterEgressPolicyList{},
	}
	for _, object := range objects {
		gvks, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("ObjectKinds(%T) error = %v", object, err)
		}

		if len(gvks) != 1 || gvks[0].GroupVersion() != v1alpha1.GroupVersion {
			t.Errorf("ObjectKinds(%T) = %v, want one %s kind", object, gvks, v1alpha1.GroupVersion)
		}
	}
}
