// Package v1alpha1 contains the g0efilter egress policy API.
//
// +kubebuilder:object:generate=true
// +groupName=g0efilter.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the API group and version this package defines.
var GroupVersion = schema.GroupVersion{Group: "g0efilter.io", Version: "v1alpha1"} //nolint:gochecknoglobals

// SchemeBuilder registers this package's types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion} //nolint:gochecknoglobals

// AddToScheme adds this package's types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme //nolint:gochecknoglobals
