// Package webhook injects the g0efilter sidecar into pods an EgressPolicy selects.
package webhook

import (
	"strconv"
	"strings"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerName is the injected container, and the marker that a pod is done.
const ContainerName = "g0efilter"

// VolumeName is the policy volume the sidecar mounts.
const VolumeName = "g0efilter-policy"

// DefaultImage must track the tag deploy/kustomize/sidecar and the Helm chart pin.
const DefaultImage = "docker.io/g0lab/g0efilter:v0.9.4"

const (
	policyMountPath = "/app/policy"
	policyFileName  = "policy.yaml"

	defaultMode        = "https"
	defaultEnforcement = "block"
	defaultLogLevel    = "INFO"
	defaultUser        = 65534
	defaultMetrics     = 9095
)

// Defaults are inherited when a policy's sidecar block is empty.
type Defaults struct {
	Image string
}

// sidecarSettings is a SidecarSpec with the defaults filled in. The sub-specs are
// carried as-is: their fields are optional all the way down, and an unset one means
// the agent's own default, which the injector leaves out of the container entirely.
type sidecarSettings struct {
	image         string
	pullPolicy    corev1.PullPolicy
	mode          string
	enforcement   string
	logLevel      string
	tenantID      string
	events        bool
	eventsMax     *int32
	metrics       bool
	metricsPort   int32
	annotations   bool
	dashboard     v1alpha1.DashboardSpec
	notifications v1alpha1.NotificationsSpec
	dns           v1alpha1.DNSSpec
	ports         v1alpha1.PortsSpec
	connections   v1alpha1.ConnectionsSpec
	nflog         v1alpha1.NFLogSpec
	runAsUser     int64
	runAsGroup    int64
	resources     corev1.ResourceRequirements
	extraEnv      []corev1.EnvVar
}

func resolve(spec v1alpha1.SidecarSpec, defaults Defaults) sidecarSettings {
	settings := sidecarSettings{
		image:         or(spec.Image, defaults.Image),
		pullPolicy:    orPullPolicy(spec.ImagePullPolicy),
		mode:          or(spec.Mode, defaultMode),
		enforcement:   or(spec.Enforcement, defaultEnforcement),
		logLevel:      or(spec.LogLevel, defaultLogLevel),
		tenantID:      spec.TenantID,
		events:        spec.Events,
		eventsMax:     spec.EventsMaxDenials,
		metrics:       spec.Metrics.Enabled,
		metricsPort:   spec.Metrics.Port,
		annotations:   spec.Metrics.Annotations,
		dashboard:     spec.Dashboard,
		notifications: spec.Notifications,
		dns:           spec.DNS,
		ports:         spec.Ports,
		connections:   spec.Connections,
		nflog:         spec.NFLog,
		runAsUser:     orInt64(spec.RunAsUser, defaultUser),
		runAsGroup:    orInt64(spec.RunAsGroup, defaultUser),
		resources:     spec.Resources,
		extraEnv:      spec.ExtraEnv,
	}

	if settings.metricsPort == 0 {
		settings.metricsPort = defaultMetrics
	}

	if len(settings.resources.Requests) == 0 && len(settings.resources.Limits) == 0 {
		settings.resources = defaultResources()
	}

	return settings
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func orInt64(value *int64, fallback int64) int64 {
	if value == nil {
		return fallback
	}

	return *value
}

func orPullPolicy(value corev1.PullPolicy) corev1.PullPolicy {
	if value == "" {
		return corev1.PullIfNotPresent
	}

	return value
}

func defaultResources() corev1.ResourceRequirements {
	//nolint:exhaustruct // Claims are not used
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("25m"),
			corev1.ResourceMemory: resource.MustParse("32Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
	}
}

// container must stay identical to what the Kustomize component and Helm chart
// render, or the same workload is filtered differently per deployment path.
func container(settings sidecarSettings, configMapName string) corev1.Container {
	user := settings.runAsUser
	group := settings.runAsGroup
	nonRoot := true
	readOnlyRoot := true
	noEscalation := false

	//nolint:exhaustruct // only the fields the sidecar sets
	sidecar := corev1.Container{
		Name:            ContainerName,
		Image:           settings.image,
		ImagePullPolicy: settings.pullPolicy,
		// Native sidecar: nftables is programmed before the app container starts.
		RestartPolicy: restartAlways(),
		Env:           env(settings, configMapName),
		SecurityContext: &corev1.SecurityContext{ //nolint:exhaustruct // only what is set
			RunAsNonRoot:             &nonRoot,
			RunAsUser:                &user,
			RunAsGroup:               &group,
			ReadOnlyRootFilesystem:   &readOnlyRoot,
			AllowPrivilegeEscalation: &noEscalation,
			SeccompProfile:           seccompRuntimeDefault(),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				// Carried as a file capability, so the container never runs as root.
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		},
		VolumeMounts: []corev1.VolumeMount{{ //nolint:exhaustruct // name, path and mode only
			Name:      VolumeName,
			MountPath: policyMountPath,
			ReadOnly:  true,
		}},
		Resources: settings.resources,
	}

	if settings.metrics {
		sidecar.Ports = []corev1.ContainerPort{{ //nolint:exhaustruct // name, port and protocol only
			Name:          "metrics",
			ContainerPort: settings.metricsPort,
			Protocol:      corev1.ProtocolTCP,
		}}
	}

	return sidecar
}

func seccompRuntimeDefault() *corev1.SeccompProfile {
	//nolint:exhaustruct // type only
	return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
}

func restartAlways() *corev1.ContainerRestartPolicy {
	policy := corev1.ContainerRestartPolicyAlways

	return &policy
}

// env renders the sidecar's configuration. ExtraEnv is appended last, but cannot
// collide with anything above it: the CRD rejects the names this function sets.
func env(settings sidecarSettings, configMapName string) []corev1.EnvVar {
	vars := []corev1.EnvVar{
		{Name: "FILTER_MODE", Value: settings.mode, ValueFrom: nil},
		// Always set, so a pod's enforcement posture is visible without knowing the default.
		{Name: "ENFORCE", Value: settings.enforcement, ValueFrom: nil},
		{Name: "POLICY_PATH", Value: policyMountPath + "/" + policyFileName, ValueFrom: nil},
		{Name: "POLICY_CONFIGMAP", Value: configMapName, ValueFrom: nil},
		{Name: "LOG_LEVEL", Value: settings.logLevel, ValueFrom: nil},
		fieldRef("POD_NAMESPACE", "metadata.namespace"),
	}

	vars = appendIf(vars, settings.tenantID != "", plain("TENANT_ID", settings.tenantID))

	vars = append(vars, observabilityEnv(settings)...)
	vars = append(vars, dashboardEnv(settings.dashboard)...)
	vars = append(vars, notificationsEnv(settings.notifications)...)
	vars = append(vars, dnsEnv(settings.dns)...)
	vars = append(vars, listenerEnv(settings.ports)...)
	vars = append(vars, connectionEnv(settings.connections)...)
	vars = append(vars, nflogEnv(settings.nflog)...)

	return append(vars, settings.extraEnv...)
}

func observabilityEnv(settings sidecarSettings) []corev1.EnvVar {
	var vars []corev1.EnvVar

	if settings.metrics {
		vars = append(vars, plain("METRICS_ADDR", ":"+strconv.Itoa(int(settings.metricsPort))))
	}

	if settings.events {
		vars = append(vars,
			plain("KUBE_EVENTS", "true"),
			fieldRef("POD_NAME", "metadata.name"),
			fieldRef("POD_UID", "metadata.uid"),
		)
		vars = appendInt32(vars, "KUBE_EVENTS_MAX", settings.eventsMax)
	}

	return vars
}

func dashboardEnv(spec v1alpha1.DashboardSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	if spec.Host != "" {
		vars = append(vars, plain("DASHBOARD_HOST", spec.Host))
	}

	if spec.APIKeySecretRef != nil {
		vars = append(vars, secretRef("DASHBOARD_API_KEY", spec.APIKeySecretRef))
	}

	vars = appendInt32(vars, "DASHBOARD_QUEUE_SIZE", spec.QueueSize)
	vars = appendDuration(vars, "DASHBOARD_START_DELAY", spec.StartDelay)
	vars = appendIf(vars, spec.RemoteUnblock, plain("ENABLE_REMOTE_UNBLOCK", "true"))
	vars = appendDuration(vars, "UNBLOCK_POLL_INTERVAL", spec.UnblockPollInterval)

	return vars
}

func notificationsEnv(spec v1alpha1.NotificationsSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	if spec.URLsSecretRef != nil {
		vars = append(vars, secretRef("NOTIFICATION_URLS", spec.URLsSecretRef))
	}

	vars = appendInt32(vars, "NOTIFICATION_BACKOFF_SECONDS", spec.BackoffSeconds)

	if len(spec.IgnoreDomains) > 0 {
		vars = append(vars, plain("NOTIFICATION_IGNORE_DOMAINS", strings.Join(spec.IgnoreDomains, ",")))
	}

	return vars
}

func dnsEnv(spec v1alpha1.DNSSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	if len(spec.Upstreams) > 0 {
		vars = append(vars, plain("DNS_UPSTREAMS", strings.Join(spec.Upstreams, ",")))
	}

	if spec.Hardening != nil {
		vars = append(vars, plain("DNS_HARDENING", strconv.FormatBool(*spec.Hardening)))
	}

	vars = appendInt32(vars, "DNS_RATE_QPS", spec.RateQPS)
	vars = appendInt32(vars, "DNS_RATE_BURST", spec.RateBurst)

	return vars
}

func listenerEnv(spec v1alpha1.PortsSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	vars = appendInt32(vars, "HTTP_PORT", spec.HTTP)
	vars = appendInt32(vars, "HTTPS_PORT", spec.HTTPS)
	vars = appendInt32(vars, "DNS_PORT", spec.DNS)

	return vars
}

func connectionEnv(spec v1alpha1.ConnectionsSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	vars = appendInt32(vars, "MAX_CONNECTIONS", spec.Max)

	if spec.MaxLifetime != nil {
		milliseconds := spec.MaxLifetime.Milliseconds()
		vars = append(vars, plain("CONN_MAX_LIFETIME_MS", strconv.FormatInt(milliseconds, 10)))
	}

	return vars
}

func nflogEnv(spec v1alpha1.NFLogSpec) []corev1.EnvVar {
	var vars []corev1.EnvVar

	vars = appendInt32(vars, "NFLOG_BUFSIZE", spec.BufSize)
	vars = appendInt32(vars, "NFLOG_QTHRESH", spec.QThresh)

	return vars
}

func appendIf(vars []corev1.EnvVar, condition bool, entry corev1.EnvVar) []corev1.EnvVar {
	if !condition {
		return vars
	}

	return append(vars, entry)
}

func appendInt32(vars []corev1.EnvVar, name string, value *int32) []corev1.EnvVar {
	if value == nil {
		return vars
	}

	return append(vars, plain(name, strconv.Itoa(int(*value))))
}

func appendDuration(vars []corev1.EnvVar, name string, value *metav1.Duration) []corev1.EnvVar {
	if value == nil {
		return vars
	}

	return append(vars, plain(name, value.Duration.String()))
}

func plain(name, value string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, Value: value, ValueFrom: nil}
}

func fieldRef(name, path string) corev1.EnvVar {
	return corev1.EnvVar{
		Name:  name,
		Value: "",
		ValueFrom: &corev1.EnvVarSource{ //nolint:exhaustruct // field reference only
			FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: path},
		},
	}
}

// secretRef keeps credentials out of the EgressPolicy: kubelet resolves the Secret
// in the pod's namespace, and the controller never needs read access to it.
func secretRef(name string, selector *corev1.SecretKeySelector) corev1.EnvVar {
	return corev1.EnvVar{
		Name:  name,
		Value: "",
		ValueFrom: &corev1.EnvVarSource{ //nolint:exhaustruct // secret reference only
			SecretKeyRef: selector.DeepCopy(),
		},
	}
}

// policyVolume mounts a directory, not a subPath file, so kubelet's refresh
// reaches the sidecar and triggers live reload.
func policyVolume(configMapName string) corev1.Volume {
	return corev1.Volume{
		Name: VolumeName,
		VolumeSource: corev1.VolumeSource{ //nolint:exhaustruct // configMap only
			ConfigMap: &corev1.ConfigMapVolumeSource{ //nolint:exhaustruct // name only
				LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
			},
		},
	}
}

func scrapeAnnotations(settings sidecarSettings) map[string]string {
	if !settings.metrics || !settings.annotations {
		return nil
	}

	return map[string]string{
		"prometheus.io/scrape": "true",
		"prometheus.io/port":   strconv.Itoa(int(settings.metricsPort)),
		"prometheus.io/path":   "/metrics",
	}
}

func configMapFor(policy *v1alpha1.EgressPolicy) string {
	return policy.Status.ConfigMapName
}
