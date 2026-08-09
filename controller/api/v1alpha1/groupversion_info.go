// Package v1alpha1 contains the g0efilter egress policy API.
//
// +kubebuilder:object:generate=true
// +groupName=g0efilter.g0lab.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version this package defines.
var GroupVersion = schema.GroupVersion{ //nolint:gochecknoglobals
	Group:   "g0efilter.g0lab.com",
	Version: "v1alpha1",
}

// SchemeBuilder registers this package's types with a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes) //nolint:gochecknoglobals

// AddToScheme adds this package's types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme //nolint:gochecknoglobals

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		GroupVersion,
		&EgressPolicy{},
		&EgressPolicyList{},
		&ClusterEgressPolicy{},
		&ClusterEgressPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)

	return nil
}
