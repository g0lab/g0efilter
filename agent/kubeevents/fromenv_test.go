//nolint:testpackage // Need access to internal implementation details
package kubeevents

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeServiceAccount(t *testing.T, files map[string]string) {
	t.Helper()

	dir := t.TempDir()

	for name, body := range files {
		err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
		if err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	original := serviceAccountDir
	serviceAccountDir = dir

	t.Cleanup(func() { serviceAccountDir = original })
}

func selfSignedCA(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	//nolint:exhaustruct // only the fields a CA certificate needs
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"}, //nolint:exhaustruct // only CN
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	//nolint:exhaustruct // Type and Bytes are the whole PEM block
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func inCluster(t *testing.T) {
	t.Helper()

	t.Setenv("KUBE_EVENTS", "true")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("POD_NAME", "demo-abc123")
	t.Setenv("POD_NAMESPACE", "")
	t.Setenv("POD_UID", "pod-uid-1")
	t.Setenv("KUBE_EVENTS_MAX", "")
}

func completeAccount(t *testing.T) map[string]string {
	t.Helper()

	return map[string]string{"token": "t", "namespace": "apps", "ca.crt": selfSignedCA(t)}
}

//nolint:paralleltest // mutates serviceAccountDir and the environment
func TestNewFromEnvBuildsARecorderInCluster(t *testing.T) {
	inCluster(t)
	fakeServiceAccount(t, map[string]string{
		"token":     "projected-token",
		"namespace": "apps",
		"ca.crt":    selfSignedCA(t),
	})

	rec := NewFromEnv(slog.New(slog.DiscardHandler))
	if rec == nil {
		t.Fatal("no Recorder was built from a complete in-cluster environment")
	}

	if rec.namespace != "apps" || rec.pod != "demo-abc123" || rec.uid != "pod-uid-1" {
		t.Errorf("identity = %s/%s uid=%s", rec.namespace, rec.pod, rec.uid)
	}

	if rec.token != "projected-token" {
		t.Errorf("token = %q", rec.token)
	}

	want := "https://10.96.0.1:443/api/v1/namespaces/apps/events"
	if rec.endpoint != want {
		t.Errorf("endpoint = %q, want %q", rec.endpoint, want)
	}
}

// A half-configured recorder would log a failure for every denial, so anything
// missing has to disable recording outright.
func TestNewFromEnvDisablesOnIncompleteEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		files func(*testing.T) map[string]string
		env   map[string]string
	}{
		{
			name: "no ServiceAccount token",
			files: func(t *testing.T) map[string]string {
				t.Helper()

				return map[string]string{"namespace": "apps"}
			},
		},
		{
			name: "no namespace",
			files: func(t *testing.T) map[string]string {
				t.Helper()

				return map[string]string{"token": "t"}
			},
		},
		{
			name: "unusable cluster CA",
			files: func(t *testing.T) map[string]string {
				t.Helper()

				return map[string]string{"token": "t", "namespace": "apps", "ca.crt": "not a certificate"}
			},
		},
		{
			name:  "no pod name",
			files: completeAccount,
			env:   map[string]string{"POD_NAME": "", "HOSTNAME": ""},
		},
		{
			name:  "not opted in",
			files: completeAccount,
			env:   map[string]string{"KUBE_EVENTS": "false"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inCluster(t)

			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			fakeServiceAccount(t, tc.files(t))

			if rec := NewFromEnv(slog.New(slog.DiscardHandler)); rec != nil {
				t.Error("a Recorder was built from an incomplete environment")
			}
		})
	}
}

func TestPodNamespacePrefersTheDownwardAPI(t *testing.T) {
	fakeServiceAccount(t, map[string]string{"namespace": "from-file"})

	t.Setenv("POD_NAMESPACE", "")

	if got := podNamespace(); got != "from-file" {
		t.Errorf("podNamespace() = %q, want the projected file", got)
	}

	t.Setenv("POD_NAMESPACE", "from-env")

	if got := podNamespace(); got != "from-env" {
		t.Errorf("podNamespace() = %q, want POD_NAMESPACE", got)
	}
}

func TestNewFromEnvHonoursTheEventCap(t *testing.T) {
	inCluster(t)
	t.Setenv("KUBE_EVENTS_MAX", "3")
	fakeServiceAccount(t, completeAccount(t))

	rec := NewFromEnv(slog.New(slog.DiscardHandler))
	if rec == nil {
		t.Fatal("no Recorder built")
	}

	if rec.max != 3 {
		t.Errorf("max = %d, want 3", rec.max)
	}
}

//nolint:paralleltest // mutates serviceAccountDir and the environment
func TestNewClientTrustsOnlyTheClusterCA(t *testing.T) {
	fakeServiceAccount(t, map[string]string{"ca.crt": selfSignedCA(t)})

	client, err := newClient()
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", client.Transport)
	}

	// A nil RootCAs falls back to the system pool, trusting far more than the cluster.
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("the client falls back to the system trust store")
	}

	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("the client permits TLS below 1.2")
	}
}

//nolint:paralleltest // mutates serviceAccountDir and the environment
func TestNewClientRejectsAMissingCA(t *testing.T) {
	fakeServiceAccount(t, map[string]string{})

	_, err := newClient()
	if err == nil {
		t.Fatal("newClient accepted a missing cluster CA")
	}

	if !strings.Contains(err.Error(), "cluster CA") {
		t.Errorf("unclear error: %v", err)
	}
}
