// Package webhook injects the g0efilter sidecar into pods an EgressPolicy selects.
package webhook

import (
	"strconv"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// ContainerName is the injected container, and the marker that a pod is done.
const ContainerName = "g0efilter"

// VolumeName is the policy volume the sidecar mounts.
const VolumeName = "g0efilter-policy"

// DefaultImage must track the tag deploy/kustomize/sidecar and the Helm chart pin.
const DefaultImage = "docker.io/g0lab/g0efilter:v0.8.0"

const (
	policyMountPath = "/app/policy"
	policyFileName  = "policy.yaml"

	defaultMode     = "https"
	defaultLogLevel = "INFO"
	defaultUser     = 65534
	defaultMetrics  = 9095
)

// Defaults are inherited when a policy's sidecar block is empty.
type Defaults struct {
	Image string
}

// sidecarSettings is a SidecarSpec with the defaults filled in.
type sidecarSettings struct {
	image       string
	mode        string
	logLevel    string
	events      bool
	metrics     bool
	metricsPort int32
	annotations bool
	resources   corev1.ResourceRequirements
}

func resolve(spec v1alpha1.SidecarSpec, defaults Defaults) sidecarSettings {
	settings := sidecarSettings{
		image:       or(spec.Image, defaults.Image),
		mode:        or(spec.Mode, defaultMode),
		logLevel:    or(spec.LogLevel, defaultLogLevel),
		events:      spec.Events,
		metrics:     spec.Metrics.Enabled,
		metricsPort: spec.Metrics.Port,
		annotations: spec.Metrics.Annotations,
		resources:   spec.Resources,
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
	user := int64(defaultUser)
	nonRoot := true
	readOnlyRoot := true
	noEscalation := false

	//nolint:exhaustruct // only the fields the sidecar sets
	sidecar := corev1.Container{
		Name:            ContainerName,
		Image:           settings.image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		// Native sidecar: nftables is programmed before the app container starts.
		RestartPolicy: restartAlways(),
		Env:           env(settings, configMapName),
		SecurityContext: &corev1.SecurityContext{ //nolint:exhaustruct // only what is set
			RunAsNonRoot:             &nonRoot,
			RunAsUser:                &user,
			RunAsGroup:               &user,
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

func env(settings sidecarSettings, configMapName string) []corev1.EnvVar {
	vars := []corev1.EnvVar{
		{Name: "FILTER_MODE", Value: settings.mode, ValueFrom: nil},
		{Name: "POLICY_PATH", Value: policyMountPath + "/" + policyFileName, ValueFrom: nil},
		{Name: "POLICY_CONFIGMAP", Value: configMapName, ValueFrom: nil},
		{Name: "LOG_LEVEL", Value: settings.logLevel, ValueFrom: nil},
		fieldRef("POD_NAMESPACE", "metadata.namespace"),
	}

	if settings.metrics {
		vars = append(vars, corev1.EnvVar{
			Name: "METRICS_ADDR", Value: ":" + strconv.Itoa(int(settings.metricsPort)), ValueFrom: nil,
		})
	}

	if settings.events {
		vars = append(vars,
			corev1.EnvVar{Name: "KUBE_EVENTS", Value: "true", ValueFrom: nil},
			fieldRef("POD_NAME", "metadata.name"),
			fieldRef("POD_UID", "metadata.uid"),
		)
	}

	return vars
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
