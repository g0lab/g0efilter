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
//
// The API server must be allowed when Events are enabled. Dashboard, notification,
// remote-unblock and upstream-DNS connections use marked sockets that bypass the
// packet filter, although DNS modes still apply domain policy to hostname lookups.
// +kubebuilder:validation:XValidation:rule="!has(self.metrics) || !self.metrics.enabled || (has(self.mode) && self.mode in ['dns','dns-strict'] ? (has(self.ports) && has(self.ports.dns) ? self.ports.dns : 65053) != (has(self.metrics.port) && self.metrics.port != 0 ? self.metrics.port : 9095) : ((has(self.ports) && has(self.ports.http) ? self.ports.http : 65080) != (has(self.metrics.port) && self.metrics.port != 0 ? self.metrics.port : 9095) && (has(self.ports) && has(self.ports.https) ? self.ports.https : 65443) != (has(self.metrics.port) && self.metrics.port != 0 ? self.metrics.port : 9095)))",message="metrics port must differ from the active proxy ports"
type SidecarSpec struct {
	// Image overrides the sidecar image, including the tag.
	// +optional
	Image string `json:"image,omitempty"`

	// ImagePullPolicy overrides the sidecar's pull policy.
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Mode is the filtering mode. It selects the data path, not how strictly a
	// verdict is applied: see Enforcement for that.
	// +kubebuilder:validation:Enum=https;dns;dns-strict
	// +optional
	Mode string `json:"mode,omitempty"`

	// Enforcement decides what happens to traffic no rule allows. `block` drops it;
	// `audit` logs it and allows it through.
	// +kubebuilder:validation:Enum=block;audit
	// +optional
	Enforcement string `json:"enforcement,omitempty"`

	// LogLevel is the sidecar's log level.
	// +kubebuilder:validation:Enum=TRACE;DEBUG;INFO;WARN;ERROR
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// ProcessInfo adds the originating pid and process name to flow logs. The webhook
	// enables a shared process namespace unless the pod uses hostPID, and rejects an
	// explicit shareProcessNamespace: false.
	// +optional
	ProcessInfo bool `json:"processInfo,omitempty"`

	// TenantID labels this sidecar's netfilter log events with a tenant identifier.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	TenantID string `json:"tenantId,omitempty"`

	// Events records denials as Kubernetes Events. The pod's ServiceAccount needs
	// create on events, and this policy must allow the API server.
	// +optional
	Events bool `json:"events,omitempty"`

	// EventsMaxDenials caps the distinct denials recorded per pod. 0 records none.
	// +kubebuilder:validation:Minimum=0
	// +optional
	EventsMaxDenials *int32 `json:"eventsMaxDenials,omitempty"`

	// Metrics serves Prometheus metrics from the sidecar.
	// +optional
	Metrics MetricsSpec `json:"metrics,omitempty"`

	// Dashboard ships this sidecar's logs to a g0efilter dashboard.
	// +optional
	Dashboard DashboardSpec `json:"dashboard,omitempty"`

	// Notifications sends blocked-traffic alerts to a Gotify server.
	// +optional
	Notifications NotificationsSpec `json:"notifications,omitempty"`

	// DNS tunes the sidecar's DNS proxy. It only has an effect in `dns` and
	// `dns-strict` mode.
	// +optional
	DNS DNSSpec `json:"dns,omitempty"`

	// Ports moves the sidecar's internal proxy listeners.
	// +optional
	Ports PortsSpec `json:"ports,omitempty"`

	// Connections caps the sidecar's proxied connections.
	// +optional
	Connections ConnectionsSpec `json:"connections,omitempty"`

	// NFLog tunes the netfilter log socket used for denials.
	// +optional
	NFLog NFLogSpec `json:"nflog,omitempty"`

	// RunAsUser is the uid the sidecar runs as. It must not be 0: the image is built
	// to filter unprivileged, carrying NET_ADMIN as a file capability.
	// +kubebuilder:validation:Minimum=1
	// +optional
	RunAsUser *int64 `json:"runAsUser,omitempty"`

	// RunAsGroup is the gid the sidecar runs as.
	// +kubebuilder:validation:Minimum=1
	// +optional
	RunAsGroup *int64 `json:"runAsGroup,omitempty"`

	// Resources overrides the sidecar's requests and limits.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// ExtraEnv sets sidecar environment variables this API does not model yet.
	//
	// It cannot set anything the injector already derives from this spec, and it
	// cannot set the inline allow/deny lists, DEFAULT_ACTION or LEARNING_MODE: each of
	// those makes the sidecar stop enforcing the policy the controller rendered, so a
	// pod would silently pass traffic this EgressPolicy does not allow.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:XValidation:rule="self.all(e, !(e.name in ['ALLOWLIST_IPS','ALLOWLIST_DOMAINS','DENYLIST_IPS','DENYLIST_DOMAINS','DEFAULT_ACTION','LEARNING_MODE','POLICY_PATH','POLICY_CONFIGMAP']))",message="extraEnv must not set ALLOWLIST_*, DENYLIST_*, DEFAULT_ACTION, LEARNING_MODE, POLICY_PATH or POLICY_CONFIGMAP: they would stop the sidecar enforcing this policy"
	// +kubebuilder:validation:XValidation:rule="self.all(e, !(e.name in ['FILTER_MODE','ENFORCE','LOG_LEVEL','PROCESS_INFO','TENANT_ID','KUBE_EVENTS','KUBE_EVENTS_MAX','METRICS_ADDR','DASHBOARD_HOST','DASHBOARD_API_KEY','DASHBOARD_QUEUE_SIZE','DASHBOARD_START_DELAY','ENABLE_REMOTE_UNBLOCK','UNBLOCK_POLL_INTERVAL','NOTIFICATION_HOST','NOTIFICATION_KEY','NOTIFICATION_BACKOFF_SECONDS','NOTIFICATION_IGNORE_DOMAINS','DNS_UPSTREAMS','DNS_HARDENING','DNS_RATE_QPS','DNS_RATE_BURST','HTTP_PORT','HTTPS_PORT','DNS_PORT','MAX_CONNECTIONS','CONN_MAX_LIFETIME_MS','NFLOG_BUFSIZE','NFLOG_QTHRESH','POD_NAME','POD_NAMESPACE','POD_UID']))",message="extraEnv must not set a variable this spec already controls; use the matching field instead"
	ExtraEnv []corev1.EnvVar `json:"extraEnv,omitempty"`
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

// DashboardSpec points the sidecar at a g0efilter dashboard.
type DashboardSpec struct {
	// Host is the dashboard's URL, such as
	// `http://g0efilter-dashboard.g0efilter-system.svc:8080`. Shipping is off while
	// this is empty. DNS modes must allow the hostname so it can be resolved.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Host string `json:"host,omitempty"`

	// APIKeySecretRef reads the dashboard machine API key from a Secret in the pod's
	// own namespace. The controller never reads the Secret; kubelet resolves it, so a
	// missing key surfaces as the pod failing to start.
	// +optional
	APIKeySecretRef *corev1.SecretKeySelector `json:"apiKeySecretRef,omitempty"`

	// QueueSize buffers log entries while shipping. The oldest are dropped when it
	// fills, so the sidecar never blocks the traffic it is filtering.
	// +kubebuilder:validation:Minimum=1
	// +optional
	QueueSize *int32 `json:"queueSize,omitempty"`

	// StartDelay waits before the first shipment, giving the dashboard time to come
	// up alongside the pod.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('0s')",message="startDelay must not be negative"
	// +optional
	StartDelay *metav1.Duration `json:"startDelay,omitempty"`

	// RemoteUnblock polls the dashboard for operator-approved unblock requests.
	// +optional
	RemoteUnblock bool `json:"remoteUnblock,omitempty"`

	// UnblockPollInterval is how often the dashboard is polled for unblock requests.
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="unblockPollInterval must be positive"
	// +optional
	UnblockPollInterval *metav1.Duration `json:"unblockPollInterval,omitempty"`
}

// NotificationsSpec configures Gotify alerts for blocked traffic.
type NotificationsSpec struct {
	// Host is the Gotify server URL. Alerting is off while this is empty. DNS modes
	// must allow the hostname so it can be resolved.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Host string `json:"host,omitempty"`

	// KeySecretRef reads the Gotify application token from a Secret in the pod's own
	// namespace.
	// +optional
	KeySecretRef *corev1.SecretKeySelector `json:"keySecretRef,omitempty"`

	// BackoffSeconds suppresses repeat alerts for the same destination.
	// +kubebuilder:validation:Minimum=1
	// +optional
	BackoffSeconds *int32 `json:"backoffSeconds,omitempty"`

	// IgnoreDomains are destinations that never raise an alert, even when blocked.
	// Wildcards such as `*.telemetry.example.com` are accepted.
	// +optional
	// +listType=atomic
	IgnoreDomains []string `json:"ignoreDomains,omitempty"`
}

// DNSSpec tunes the sidecar's DNS proxy.
type DNSSpec struct {
	// Upstreams are the resolvers the proxy forwards to, as `host:port`. The default
	// is Docker's `127.0.0.11:53`; set this to cluster DNS on Kubernetes.
	// +optional
	// +listType=atomic
	Upstreams []string `json:"upstreams,omitempty"`

	// Hardening applies the anti-exfiltration checks: qname and label length caps,
	// NULL and bulky-TXT answer rejection, and per-source rate limiting. On unless
	// explicitly set to false.
	// +optional
	Hardening *bool `json:"hardening,omitempty"`

	// RateQPS is the hardening rate limiter's sustained queries per second. Every
	// workload behind the redirect shares one source address, so this is a single
	// budget for the whole pod rather than one per client.
	// +kubebuilder:validation:Minimum=1
	// +optional
	RateQPS *int32 `json:"rateQps,omitempty"`

	// RateBurst is the hardening rate limiter's burst allowance.
	// +kubebuilder:validation:Minimum=1
	// +optional
	RateBurst *int32 `json:"rateBurst,omitempty"`
}

// PortsSpec moves the sidecar's internal proxy listeners.
// +kubebuilder:validation:XValidation:rule="!has(self.http) || !has(self.https) || self.http != self.https",message="http and https must differ"
type PortsSpec struct {
	// HTTP is the local transparent HTTP proxy port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	HTTP *int32 `json:"http,omitempty"`

	// HTTPS is the local transparent TLS proxy port, where SNI is read.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	HTTPS *int32 `json:"https,omitempty"`

	// DNS is the local DNS proxy port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	DNS *int32 `json:"dns,omitempty"`
}

// ConnectionsSpec caps the sidecar's proxied connections.
type ConnectionsSpec struct {
	// Max is the concurrent connection ceiling per listener. Excess is held with
	// backpressure rather than refused. 0 is unlimited.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Max *int32 `json:"max,omitempty"`

	// MaxLifetime is a single absolute deadline on a proxied connection, not an idle
	// timeout: a long-lived stream is cut when it expires. 0 disables it.
	// +kubebuilder:validation:XValidation:rule="duration(self) == duration('0s') || duration(self) >= duration('1ms')",message="maxLifetime must be 0 or at least 1ms"
	// +optional
	MaxLifetime *metav1.Duration `json:"maxLifetime,omitempty"`
}

// NFLogSpec tunes the netfilter log socket.
type NFLogSpec struct {
	// BufSize is the netfilter log buffer size.
	// +kubebuilder:validation:Minimum=1
	// +optional
	BufSize *int32 `json:"bufSize,omitempty"`

	// QThresh is the netfilter log queue threshold.
	// +kubebuilder:validation:Minimum=1
	// +optional
	QThresh *int32 `json:"qthresh,omitempty"`
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
// even though egresspolicies.g0efilter.g0lab.com is already unique.
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
