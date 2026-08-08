package certs_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/g0lab/g0efilter/controller/internal/certs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func options(t *testing.T) certs.Options {
	t.Helper()

	//nolint:gosec // object names, not credentials
	return certs.Options{
		Namespace:   "g0efilter-system",
		SecretName:  "g0efilter-webhook-cert",
		ServiceName: "g0efilter-webhook",
		WebhookName: "g0efilter-sidecar-injector",
		Dir:         t.TempDir(),
	}
}

//nolint:ireturn // the fake builder returns the client interface
func newClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()

	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func webhookConfiguration(name string) *admissionv1.MutatingWebhookConfiguration {
	//nolint:exhaustruct // only the fields under test
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:         "sidecar.g0efilter.io",
			ClientConfig: admissionv1.WebhookClientConfig{CABundle: nil}, //nolint:exhaustruct // bundle only
		}},
	}
}

func readCert(t *testing.T, dir string) *x509.Certificate {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, "tls.crt")) //nolint:gosec // a test temporary directory
	if err != nil {
		t.Fatalf("read the certificate: %v", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("the written certificate is not PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}

	return cert
}

func TestEnsureIssuesAndPublishesACertificate(t *testing.T) {
	t.Parallel()

	opts := options(t)
	c := newClient(t, webhookConfiguration(opts.WebhookName))

	err := certs.Ensure(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	cert := readCert(t, opts.Dir)

	// The API server dials the Service by name, so the certificate has to carry it.
	err = cert.VerifyHostname("g0efilter-webhook.g0efilter-system.svc")
	if err != nil {
		t.Errorf("the certificate is not valid for the Service name: %v", err)
	}

	key, err := os.ReadFile(filepath.Join(opts.Dir, "tls.key"))
	if err != nil || len(key) == 0 {
		t.Fatalf("the private key was not written: %v", err)
	}

	var stored corev1.Secret

	err = c.Get(context.Background(), client.ObjectKey{Namespace: opts.Namespace, Name: opts.SecretName}, &stored)
	if err != nil {
		t.Fatalf("the Secret was not created: %v", err)
	}

	// Without the caBundle the API server cannot verify the webhook, and under
	// failurePolicy Fail that blocks pod creation in every opted-in namespace.
	var configuration admissionv1.MutatingWebhookConfiguration

	err = c.Get(context.Background(), client.ObjectKey{Name: opts.WebhookName}, &configuration)
	if err != nil {
		t.Fatalf("get the webhook configuration: %v", err)
	}

	if !bytes.Equal(configuration.Webhooks[0].ClientConfig.CABundle, stored.Data["tls.crt"]) {
		t.Error("the published caBundle is not the certificate that was issued")
	}
}

// A restart, or a second replica, must serve the certificate already published
// rather than issue one the API server does not trust.
func TestEnsureReusesTheStoredCertificate(t *testing.T) {
	t.Parallel()

	opts := options(t)
	c := newClient(t, webhookConfiguration(opts.WebhookName))

	err := certs.Ensure(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	first := readCert(t, opts.Dir)

	err = certs.Ensure(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	if readCert(t, opts.Dir).SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Error("the certificate was reissued instead of reused")
	}
}

func TestEnsureReplacesUnusableMaterial(t *testing.T) {
	t.Parallel()

	opts := options(t)

	//nolint:exhaustruct // only the fields under test
	broken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("not a certificate"), "tls.key": []byte("nor a key")},
	}

	c := newClient(t, broken, webhookConfiguration(opts.WebhookName))

	err := certs.Ensure(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	err = readCert(t, opts.Dir).VerifyHostname("g0efilter-webhook.g0efilter-system.svc")
	if err != nil {
		t.Errorf("the broken certificate was not replaced: %v", err)
	}
}

func TestEnsureKeepsThePreviousCertificateTrustedDuringRotation(t *testing.T) {
	t.Parallel()

	opts := options(t)
	oldOpts := opts
	oldOpts.ServiceName = "old-webhook"
	oldOpts.Dir = t.TempDir()

	c := newClient(t, webhookConfiguration(opts.WebhookName))

	err := certs.Ensure(context.Background(), c, oldOpts)
	if err != nil {
		t.Fatalf("issue old certificate: %v", err)
	}

	var before corev1.Secret

	key := client.ObjectKey{Namespace: opts.Namespace, Name: opts.SecretName}

	err = c.Get(context.Background(), key, &before)
	if err != nil {
		t.Fatalf("get old certificate: %v", err)
	}

	err = certs.Ensure(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("rotate certificate: %v", err)
	}

	var configuration admissionv1.MutatingWebhookConfiguration

	err = c.Get(context.Background(), client.ObjectKey{Name: opts.WebhookName}, &configuration)
	if err != nil {
		t.Fatalf("get webhook configuration: %v", err)
	}

	bundle := configuration.Webhooks[0].ClientConfig.CABundle
	if !bytes.Contains(bundle, before.Data["tls.crt"]) {
		t.Error("the caBundle dropped the certificate another replica may still serve")
	}

	if readCert(t, opts.Dir).SerialNumber.Cmp(readCert(t, oldOpts.Dir).SerialNumber) == 0 {
		t.Error("the certificate was not rotated for the new Service name")
	}
}

func TestRenewerRunsOnEveryReplica(t *testing.T) {
	t.Parallel()

	if (certs.Renewer{}).NeedLeaderElection() {
		t.Error("a non-leader replica would never refresh its local serving certificate")
	}
}

// The controller can be deployed without the webhook overlay, and a missing
// configuration must not stop it starting.
func TestEnsureToleratesAMissingWebhookConfiguration(t *testing.T) {
	t.Parallel()

	opts := options(t)

	err := certs.Ensure(context.Background(), newClient(t), opts)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	readCert(t, opts.Dir)
}
