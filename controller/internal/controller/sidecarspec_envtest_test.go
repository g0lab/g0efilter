//nolint:testpackage // Need access to internal implementation details
package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type sidecarRejection struct {
	name    string
	mutate  func(*v1alpha1.SidecarSpec)
	wantErr string
}

func sidecarRejections() []sidecarRejection {
	rejections := append(basicSidecarRejections(), runtimeSidecarRejections()...)

	return append(rejections, extraEnvRejections()...)
}

func basicSidecarRejections() []sidecarRejection {
	return []sidecarRejection{
		{
			name:    "enforcement outside the enum",
			mutate:  func(s *v1alpha1.SidecarSpec) { s.Enforcement = "warn" },
			wantErr: "Unsupported value",
		},
		{
			name:    "pull policy outside the enum",
			mutate:  func(s *v1alpha1.SidecarSpec) { s.ImagePullPolicy = "Sometimes" },
			wantErr: "Unsupported value",
		},
		{
			name: "http and https on the same port",
			mutate: func(s *v1alpha1.SidecarSpec) {
				port := int32(15443)
				s.Ports = v1alpha1.PortsSpec{HTTP: &port, HTTPS: &port, DNS: nil}
			},
			wantErr: "http and https must differ",
		},
		{
			name: "root as the sidecar user",
			mutate: func(s *v1alpha1.SidecarSpec) {
				root := int64(0)
				s.RunAsUser = &root
			},
			wantErr: "should be greater than or equal to 1",
		},
	}
}

func runtimeSidecarRejections() []sidecarRejection {
	return []sidecarRejection{
		{
			name: "negative dashboard start delay",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.Dashboard.StartDelay = &metav1.Duration{Duration: -time.Second}
			},
			wantErr: "startDelay must not be negative",
		},
		{
			name: "zero unblock poll interval",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.Dashboard.UnblockPollInterval = &metav1.Duration{Duration: 0}
			},
			wantErr: "unblockPollInterval must be positive",
		},
		{
			name: "sub-millisecond connection lifetime",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.Connections.MaxLifetime = &metav1.Duration{Duration: time.Nanosecond}
			},
			wantErr: "maxLifetime must be 0 or at least 1ms",
		},
		{
			name: "metrics port conflicting with https proxy",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.Metrics = v1alpha1.MetricsSpec{Enabled: true, Port: 65443, Annotations: false}
			},
			wantErr: "metrics port must differ from the active proxy ports",
		},
		{
			name: "metrics port conflicting with dns proxy",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.Mode = "dns-strict"
				s.Metrics = v1alpha1.MetricsSpec{Enabled: true, Port: 65053, Annotations: false}
			},
			wantErr: "metrics port must differ from the active proxy ports",
		},
	}
}

func extraEnvRejections() []sidecarRejection {
	return []sidecarRejection{
		{
			name: "extraEnv bypassing the policy file",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.ExtraEnv = []corev1.EnvVar{{Name: "ALLOWLIST_DOMAINS", Value: "evil.example.com", ValueFrom: nil}}
			},
			wantErr: "stop the sidecar enforcing this policy",
		},
		{
			name: "extraEnv turning enforcement off",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.ExtraEnv = []corev1.EnvVar{{Name: "ENFORCE", Value: "audit", ValueFrom: nil}}
			},
			wantErr: "already controls",
		},
		{
			name: "extraEnv relocating the policy file",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.ExtraEnv = []corev1.EnvVar{{Name: "POLICY_PATH", Value: "/tmp/mine.yaml", ValueFrom: nil}}
			},
			wantErr: "stop the sidecar enforcing this policy",
		},
		{
			name: "extraEnv enabling learning mode",
			mutate: func(s *v1alpha1.SidecarSpec) {
				s.ExtraEnv = []corev1.EnvVar{{Name: "LEARNING_MODE", Value: "true", ValueFrom: nil}}
			},
			wantErr: "stop the sidecar enforcing this policy",
		},
	}
}

// The sidecar block's CEL rules and enums are enforced by the API server, not by the
// Go types, so only envtest exercises them.
//
//nolint:paralleltest // shares one apiserver
func TestCRDRejectsInvalidSidecarSpecs(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "sidecar-reject", nil)

	for _, tc := range sidecarRejections() {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // shares one apiserver
			policy := egressPolicy("invalid", rule("r", []string{"api.example.com"}, nil))
			policy.Namespace = "sidecar-reject"
			policy.Name = "sidecar-" + strings.ReplaceAll(tc.name, " ", "-")

			tc.mutate(&policy.Spec.Sidecar)

			err := c.Create(context.Background(), policy)
			if err == nil {
				t.Fatal("the API server accepted an invalid sidecar spec")
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error does not mention %q: %v", tc.wantErr, err)
			}
		})
	}
}

//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDAcceptsTheFullSidecarSpec(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "sidecar-accept", nil)

	policy := egressPolicy("full", rule("apis", []string{"api.example.com"}, nil))
	policy.Namespace = "sidecar-accept"

	maxDenials := int32(3)
	queue := int32(2048)
	hardening := false
	httpPort := int32(15080)
	httpsPort := int32(15443)
	unlimited := int32(0)

	//nolint:exhaustruct // the fields under test
	policy.Spec.Sidecar = v1alpha1.SidecarSpec{
		Mode:        "dns-strict",
		Enforcement: "audit",
		LogLevel:    "DEBUG",
		ProcessInfo: true,
		TenantID:    "tenant-a",
		Events:      v1alpha1.EventsSpec{Enabled: true, MaxDenials: &maxDenials},
		Dashboard: v1alpha1.DashboardSpec{
			Host:          "http://dashboard.g0efilter-system.svc:8081",
			QueueSize:     &queue,
			RemoteUnblock: true,
		},
		Notifications: v1alpha1.NotificationsSpec{
			Host:          "https://gotify.example.com",
			IgnoreDomains: []string{"*.telemetry.example.com"},
		},
		DNS:         v1alpha1.DNSSpec{Upstreams: []string{"10.43.0.10:53"}, Hardening: &hardening},
		Ports:       v1alpha1.PortsSpec{HTTP: &httpPort, HTTPS: &httpsPort},
		Connections: v1alpha1.ConnectionsSpec{Max: &unlimited},
		ExtraEnv:    []corev1.EnvVar{{Name: "LOG_FILE", Value: "/dev/stdout", ValueFrom: nil}},
	}

	err := c.Create(context.Background(), policy)
	if err != nil {
		t.Fatalf("the API server rejected a valid sidecar spec: %v", err)
	}
}

// extraEnv is a map list keyed on name, so the API server rejects a duplicate rather
// than leaving the last-wins outcome to kubelet.
//
//nolint:paralleltest // starts a real apiserver and etcd
func TestCRDRejectsDuplicateExtraEnv(t *testing.T) {
	c := startEnvtest(t)

	createNamespace(t, c, "sidecar-dup", nil)

	policy := egressPolicy("dup", rule("apis", []string{"api.example.com"}, nil))
	policy.Namespace = "sidecar-dup"
	policy.Spec.Sidecar.ExtraEnv = []corev1.EnvVar{
		{Name: "LOG_FILE", Value: "/dev/stdout", ValueFrom: nil},
		{Name: "LOG_FILE", Value: "/tmp/other", ValueFrom: nil},
	}

	err := c.Create(context.Background(), policy)
	if err == nil {
		t.Fatal("the API server accepted a duplicated extraEnv name")
	}

	if !strings.Contains(err.Error(), "Duplicate value") {
		t.Errorf("error does not mention a duplicate: %v", err)
	}
}
