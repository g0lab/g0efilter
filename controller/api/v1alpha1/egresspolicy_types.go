package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EgressPolicySpec describes the egress a selected set of pods is allowed.
//
// g0efilter is default-deny: traffic that no rule matches is blocked. This is
// deliberately unlike NetworkPolicy, where an empty rule set on an otherwise
// unselected pod allows everything.
type EgressPolicySpec struct {
	// PodSelector selects the pods this policy is rendered for. An empty selector
	// matches every pod in the namespace.
	// +optional
	PodSelector metav1.LabelSelector `json:"podSelector,omitempty"`

	// Egress lists the allowed destinations. An empty list denies all egress.
	// +optional
	// +listType=atomic
	Egress []EgressRule `json:"egress,omitempty"`

	// Sidecar tunes the container the mutating webhook injects. The Kustomize
	// component and Helm library chart carry their own settings and ignore this.
	// +optional
	Sidecar SidecarSpec `json:"sidecar,omitempty"`
}

// SidecarSpec tunes the injected sidecar. The defaults match the Kustomize
// component and the Helm library chart.
type SidecarSpec struct {
	// Image overrides the sidecar image, including the tag.
	// +optional
	Image string `json:"image,omitempty"`

	// Mode is the filtering mode.
	// +kubebuilder:validation:Enum=https;dns;dns-strict
	// +optional
	Mode string `json:"mode,omitempty"`

	// LogLevel is the sidecar's log level.
	// +kubebuilder:validation:Enum=TRACE;DEBUG;INFO;WARN;ERROR
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// Events records denials as Kubernetes Events. The pod's ServiceAccount needs
	// create on events, and this policy must allow the API server: the sidecar's own
	// egress is filtered too.
	// +optional
	Events bool `json:"events,omitempty"`

	// Metrics serves Prometheus metrics from the sidecar.
	// +optional
	Metrics MetricsSpec `json:"metrics,omitempty"`

	// Resources overrides the sidecar's requests and limits.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// MetricsSpec configures the sidecar's Prometheus endpoint.
type MetricsSpec struct {
	// Enabled serves /metrics and declares the port on the container.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Port is the port /metrics is served on.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// Annotations adds prometheus.io/* scrape annotations to the pod.
	// +optional
	Annotations bool `json:"annotations,omitempty"`
}

// EgressRule allows traffic to a set of peers, optionally narrowed to ports.
type EgressRule struct {
	// Name is an optional label for the rule, used in status and events.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`

	// To lists the destinations this rule allows. At least one is required.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	To []EgressPeer `json:"to"`

	// Ports narrows the rule to specific protocols and ports. When empty, every
	// port is allowed to the listed peers.
	// +optional
	// +listType=atomic
	Ports []EgressPort `json:"ports,omitempty"`
}

// EgressPeer is a set of domain or network destinations.
type EgressPeer struct {
	// DomainNames matches by HTTP Host or TLS SNI. Supports an exact name, a
	// leading wildcard such as `*.example.com`, or a `/regex/` pattern.
	// +optional
	// +listType=atomic
	DomainNames []string `json:"domainNames,omitempty"`

	// Networks matches by IP or CIDR, for destinations with no usable domain name.
	// +optional
	// +listType=atomic
	Networks []string `json:"networks,omitempty"`
}

// EgressPort narrows a rule to a protocol and port.
type EgressPort struct {
	// Protocol is TCP or UDP.
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	// +optional
	Protocol string `json:"protocol,omitempty"`

	// Port is the destination port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// EgressPolicyStatus reports what the controller rendered.
type EgressPolicyStatus struct {
	// ObservedGeneration is the spec generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ConfigMapName is the ConfigMap holding the rendered policy. Mount it in the
	// pods this policy selects.
	// +optional
	ConfigMapName string `json:"configMapName,omitempty"`

	// SelectedPods counts the running pods matching PodSelector. It is reported for
	// visibility only; a pod is filtered by the policy it mounts, not by this count.
	// +optional
	SelectedPods int32 `json:"selectedPods,omitempty"`

	// Conditions reports whether the current generation is Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// Short names are cluster-global and ungrouped, so they carry the project prefix
// even though egresspolicies.g0efilter.io is already unique.
// +kubebuilder:resource:shortName=g0ep,categories=g0efilter
// +kubebuilder:printcolumn:name="ConfigMap",type=string,JSONPath=`.status.configMapName`
// +kubebuilder:printcolumn:name="Pods",type=integer,JSONPath=`.status.selectedPods`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EgressPolicy is a namespaced set of allowed egress destinations. Several may
// coexist in a namespace; each renders its own ConfigMap for pods to mount.
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressPolicySpec   `json:"spec,omitempty"`
	Status EgressPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EgressPolicyList is a list of EgressPolicy.
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []EgressPolicy `json:"items"`
}
