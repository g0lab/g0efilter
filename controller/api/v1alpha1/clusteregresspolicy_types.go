package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterEgressPolicySpec describes egress allowed across namespaces.
//
// Cluster policies are additive: their rules are merged into every EgressPolicy in
// a matching namespace. They cannot remove anything a namespaced policy allows, so a
// platform team uses them for baseline destinations such as cluster DNS rather than
// as a restriction on tenants.
type ClusterEgressPolicySpec struct {
	// NamespaceSelector selects the namespaces this policy is merged into. An empty
	// selector matches every namespace.
	// +optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Egress lists the allowed destinations.
	// +optional
	// +listType=atomic
	Egress []EgressRule `json:"egress,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=g0cep,categories=g0efilter
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterEgressPolicy is a cluster-scoped set of egress rules merged into the
// namespaced policies it selects.
type ClusterEgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterEgressPolicySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterEgressPolicyList is a list of ClusterEgressPolicy.
type ClusterEgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterEgressPolicy `json:"items"`
}
