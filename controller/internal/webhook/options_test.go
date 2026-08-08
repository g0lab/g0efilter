package webhook_test

import (
	"testing"
	"time"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func duration(d time.Duration) *metav1.Duration {
	return &metav1.Duration{Duration: d}
}

func secretKey(name, key string) *corev1.SecretKeySelector {
	//nolint:exhaustruct // name and key only
	return &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: name},
		Key:                  key,
	}
}

// The default sidecar states its enforcement posture rather than relying on the
// agent's default, so a rendered pod can be read for it.
func TestEnforcementDefaultsToBlock(t *testing.T) {
	t.Parallel()

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{}))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	if got := envOf(patched.Spec.InitContainers[0])["ENFORCE"]; got != "block" {
		t.Errorf("ENFORCE = %q, want block", got)
	}
}

func TestEnforcementAudit(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{Enforcement: "audit"} //nolint:exhaustruct // one field under test
	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, spec))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	if got := envOf(patched.Spec.InitContainers[0])["ENFORCE"]; got != "audit" {
		t.Errorf("ENFORCE = %q, want audit", got)
	}
}

// A default sidecar sets only the variables the Kustomize component sets; every
// option added since must stay out of the container until it is asked for.
func TestUnsetOptionsRenderNoEnvironment(t *testing.T) {
	t.Parallel()

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, v1alpha1.SidecarSpec{}))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	env := envOf(patched.Spec.InitContainers[0])

	want := []string{"FILTER_MODE", "ENFORCE", "POLICY_PATH", "POLICY_CONFIGMAP", "LOG_LEVEL", "POD_NAMESPACE"}
	if len(env) != len(want) {
		t.Errorf("a default sidecar sets %d variables, want %d: %v", len(env), len(want), env)
	}

	for _, name := range want {
		if _, ok := env[name]; !ok {
			t.Errorf("%s is not set", name)
		}
	}
}

// everyOption sets every field the injector can render, so a field added without a
// matching env entry shows up as a missing variable below.
func everyOption() v1alpha1.SidecarSpec {
	//nolint:exhaustruct // image, mode and resources are covered elsewhere
	return v1alpha1.SidecarSpec{
		ProcessInfo: true,
		TenantID:    "tenant-a",
		Events:      v1alpha1.EventsSpec{Enabled: true, MaxDenials: new(int32(3))},
		Dashboard: v1alpha1.DashboardSpec{
			Host:                "http://dashboard.g0efilter-system.svc:8081",
			APIKeySecretRef:     secretKey("dashboard-key", "api-key"),
			QueueSize:           new(int32(2048)),
			StartDelay:          duration(10 * time.Second),
			RemoteUnblock:       true,
			UnblockPollInterval: duration(30 * time.Second),
		},
		Notifications: v1alpha1.NotificationsSpec{
			Host:           "https://gotify.example.com",
			KeySecretRef:   secretKey("gotify", "token"),
			BackoffSeconds: new(int32(120)),
			IgnoreDomains:  []string{"*.telemetry.example.com", "noise.example.com"},
		},
		DNS: v1alpha1.DNSSpec{
			Upstreams: []string{"10.43.0.10:53", "1.1.1.1:53"},
			Hardening: new(false),
			RateQPS:   new(int32(25)),
			RateBurst: new(int32(50)),
		},
		Ports:       v1alpha1.PortsSpec{HTTP: new(int32(15080)), HTTPS: new(int32(15443)), DNS: new(int32(15053))},
		Connections: v1alpha1.ConnectionsSpec{Max: new(int32(0)), MaxLifetime: duration(10 * time.Minute)},
		NFLog:       v1alpha1.NFLogSpec{BufSize: new(int32(128)), QThresh: new(int32(64))},
	}
}

func TestTheFullOptionSurfaceRenders(t *testing.T) {
	t.Parallel()

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, everyOption()))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	sidecar := patched.Spec.InitContainers[0]
	env := envOf(sidecar)

	for name, want := range map[string]string{
		"PROCESS_INFO":                 "true",
		"TENANT_ID":                    "tenant-a",
		"KUBE_EVENTS":                  "true",
		"KUBE_EVENTS_MAX":              "3",
		"DASHBOARD_HOST":               "http://dashboard.g0efilter-system.svc:8081",
		"DASHBOARD_QUEUE_SIZE":         "2048",
		"DASHBOARD_START_DELAY":        "10s",
		"ENABLE_REMOTE_UNBLOCK":        "true",
		"UNBLOCK_POLL_INTERVAL":        "30s",
		"NOTIFICATION_HOST":            "https://gotify.example.com",
		"NOTIFICATION_BACKOFF_SECONDS": "120",
		"NOTIFICATION_IGNORE_DOMAINS":  "*.telemetry.example.com,noise.example.com",
		"DNS_UPSTREAMS":                "10.43.0.10:53,1.1.1.1:53",
		"DNS_HARDENING":                "false",
		"DNS_RATE_QPS":                 "25",
		"DNS_RATE_BURST":               "50",
		"HTTP_PORT":                    "15080",
		"HTTPS_PORT":                   "15443",
		"DNS_PORT":                     "15053",
		"MAX_CONNECTIONS":              "0",
		"CONN_MAX_LIFETIME_MS":         "600000",
		"NFLOG_BUFSIZE":                "128",
		"NFLOG_QTHRESH":                "64",
	} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}

	// Process attribution reads /proc, which needs the shared namespace.
	if patched.Spec.ShareProcessNamespace == nil || !*patched.Spec.ShareProcessNamespace {
		t.Error("processInfo is set but the process namespace is not shared")
	}

	assertSecretRef(t, sidecar, "DASHBOARD_API_KEY", "dashboard-key", "api-key")
	assertSecretRef(t, sidecar, "NOTIFICATION_KEY", "gotify", "token")
}

// Credentials must reach the sidecar as a reference, never as a literal: an
// EgressPolicy is readable by anyone with get on the resource.
func assertSecretRef(t *testing.T, container corev1.Container, name, secret, key string) {
	t.Helper()

	for _, entry := range container.Env {
		if entry.Name != name {
			continue
		}

		if entry.Value != "" {
			t.Errorf("%s carries a literal value", name)
		}

		if entry.ValueFrom == nil || entry.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("%s is not read from a Secret", name)
		}

		if entry.ValueFrom.SecretKeyRef.Name != secret || entry.ValueFrom.SecretKeyRef.Key != key {
			t.Errorf("%s reads %s/%s, want %s/%s", name,
				entry.ValueFrom.SecretKeyRef.Name, entry.ValueFrom.SecretKeyRef.Key, secret, key)
		}

		return
	}

	t.Errorf("%s is not set", name)
}

func TestExtraEnvIsAppended(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // one field under test
	spec := v1alpha1.SidecarSpec{
		ExtraEnv: []corev1.EnvVar{{Name: "LOG_FILE", Value: "/dev/stdout", ValueFrom: nil}},
	}

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, spec))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	sidecar := patched.Spec.InitContainers[0]

	if got := envOf(sidecar)["LOG_FILE"]; got != "/dev/stdout" {
		t.Errorf("LOG_FILE = %q", got)
	}

	// Last wins in Kubernetes, so anything the CRD lets through has to come after the
	// derived variables rather than be silently overridden by them.
	if last := sidecar.Env[len(sidecar.Env)-1].Name; last != "LOG_FILE" {
		t.Errorf("extraEnv is not last: %q is", last)
	}
}

func TestRunAsUserAndPullPolicyOverride(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // only the fields under test
	spec := v1alpha1.SidecarSpec{
		ImagePullPolicy: corev1.PullAlways,
		RunAsUser:       new(int64(1001)),
		RunAsGroup:      new(int64(1002)),
	}

	injector := newInjector(t, policy("web", map[string]string{"app": "web"}, spec))

	_, patched := admit(t, injector, pod(map[string]string{"app": "web"}, nil))
	if patched == nil {
		t.Fatal("the pod was not patched")
	}

	sidecar := patched.Spec.InitContainers[0]

	if sidecar.ImagePullPolicy != corev1.PullAlways {
		t.Errorf("imagePullPolicy = %q", sidecar.ImagePullPolicy)
	}

	if sidecar.SecurityContext.RunAsUser == nil || *sidecar.SecurityContext.RunAsUser != 1001 {
		t.Errorf("runAsUser = %v", sidecar.SecurityContext.RunAsUser)
	}

	if sidecar.SecurityContext.RunAsGroup == nil || *sidecar.SecurityContext.RunAsGroup != 1002 {
		t.Errorf("runAsGroup = %v", sidecar.SecurityContext.RunAsGroup)
	}
}
