// Package certs issues the webhook's serving certificate, so the control plane
// needs no cert-manager.
package certs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	certKey       = "tls.crt"
	keyKey        = "tls.key"
	previousCAKey = "previous-ca.crt"

	keyBits = 2048

	// A year, not a decade: the renewer re-checks daily and controller-runtime
	// reloads the serving certificate from disk, so rotation is not an outage.
	validFor    = 365 * 24 * time.Hour
	renewBefore = 30 * 24 * time.Hour

	renewInterval = 24 * time.Hour
)

// Bundle is a self-signed serving certificate and its key. It is its own CA, so
// the same PEM is served and published as the caBundle.
type Bundle struct {
	Cert       []byte
	Key        []byte
	PreviousCA []byte
}

// Options names the objects the bundle is stored in and published to.
type Options struct {
	Namespace   string
	SecretName  string
	ServiceName string
	WebhookName string
	Dir         string
}

// DNSNames are the names the API server reaches the webhook Service by.
func (o Options) DNSNames() []string {
	base := o.ServiceName + "." + o.Namespace

	return []string{o.ServiceName, base, base + ".svc", base + ".svc.cluster.local"}
}

// Ensure writes a usable certificate to disk and publishes its CA. Replicas race
// here; the loser reads the winner's Secret, so all serve the same certificate.
func Ensure(ctx context.Context, c client.Client, opts Options) error {
	bundle, err := load(ctx, c, opts)
	if err != nil {
		return err
	}

	if bundle == nil {
		bundle, err = create(ctx, c, opts)
		if err != nil {
			return err
		}
	}

	err = publish(ctx, c, opts, bundle.caBundle())
	if err != nil {
		return err
	}

	return write(opts.Dir, bundle)
}

// Renewer re-runs Ensure on a schedule. controller-runtime watches the certificate
// directory, so a replaced file is picked up without a restart.
type Renewer struct {
	Client client.Client
	Opts   Options
}

// Start implements manager.Runnable.
func (r Renewer) Start(ctx context.Context) error {
	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := Ensure(ctx, r.Client, r.Opts)
			if err != nil {
				logf.FromContext(ctx).Error(err, "renewing the webhook certificate")
			}
		}
	}
}

// NeedLeaderElection returns false so every replica refreshes its local certificate.
func (r Renewer) NeedLeaderElection() bool { return false }

// load returns the stored bundle, or nil when there is none worth using.
func load(ctx context.Context, c client.Client, opts Options) (*Bundle, error) {
	var secret corev1.Secret

	err := c.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: opts.SecretName}, &secret)
	if apierrors.IsNotFound(err) {
		return nil, nil //nolint:nilnil // absent is not an error, the caller creates one
	}

	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}

	bundle := &Bundle{
		Cert:       secret.Data[certKey],
		Key:        secret.Data[keyKey],
		PreviousCA: secret.Data[previousCAKey],
	}
	if !usable(bundle, opts) {
		return nil, nil //nolint:nilnil // as above
	}

	return bundle, nil
}

func usable(bundle *Bundle, opts Options) bool {
	if len(bundle.Cert) == 0 || len(bundle.Key) == 0 {
		return false
	}

	_, err := tls.X509KeyPair(bundle.Cert, bundle.Key)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(bundle.Cert)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return false
	}

	if time.Now().Add(renewBefore).After(cert.NotAfter) {
		return false
	}

	// A Service rename leaves a certificate for a name nothing dials.
	return cert.VerifyHostname(opts.DNSNames()[2]) == nil
}

func (b *Bundle) caBundle() []byte {
	if len(b.PreviousCA) == 0 {
		return b.Cert
	}

	return bytes.Join([][]byte{b.Cert, b.PreviousCA}, nil)
}

func create(ctx context.Context, c client.Client, opts Options) (*Bundle, error) {
	bundle, err := generate(opts)
	if err != nil {
		return nil, err
	}

	//nolint:exhaustruct // name, namespace and data only
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			certKey: bundle.Cert, keyKey: bundle.Key, previousCAKey: bundle.PreviousCA,
		},
	}

	err = c.Create(ctx, secret)
	if apierrors.IsAlreadyExists(err) {
		// Another replica won the race, or the stored one had expired.
		return replace(ctx, c, opts, bundle)
	}

	if err != nil {
		return nil, fmt.Errorf("create secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}

	return bundle, nil
}

func replace(ctx context.Context, c client.Client, opts Options, fresh *Bundle) (*Bundle, error) {
	var secret corev1.Secret

	err := c.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: opts.SecretName}, &secret)
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}

	stored := &Bundle{
		Cert:       secret.Data[certKey],
		Key:        secret.Data[keyKey],
		PreviousCA: secret.Data[previousCAKey],
	}
	if usable(stored, opts) {
		return stored, nil
	}

	// Trust both generations while every replica reloads the shared replacement.
	if certificatePEM(stored.Cert) {
		fresh.PreviousCA = stored.Cert
	}

	secret.Type = corev1.SecretTypeTLS
	secret.Data = map[string][]byte{
		certKey: fresh.Cert, keyKey: fresh.Key, previousCAKey: fresh.PreviousCA,
	}

	err = c.Update(ctx, &secret)
	if err != nil {
		return nil, fmt.Errorf("update secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}

	return fresh, nil
}

func certificatePEM(raw []byte) bool {
	block, _ := pem.Decode(raw)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	return err == nil && cert.IsCA && cert.CheckSignatureFrom(cert) == nil
}

func generate(opts Options) (*Bundle, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()

	//nolint:exhaustruct // only the fields a serving certificate needs
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.DNSNames()[2]}, //nolint:exhaustruct // CN only
		DNSNames:              opts.DNSNames(),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &Bundle{
		Cert: encode("CERTIFICATE", der),
		Key:  encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	}, nil
}

func encode(blockType string, der []byte) []byte {
	//nolint:exhaustruct // PEM blocks carry no headers here
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func write(dir string, bundle *Bundle) error {
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	for name, data := range map[string][]byte{certKey: bundle.Cert, keyKey: bundle.Key} {
		err = writeAtomic(dir, name, data)
		if err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return nil
}

func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-")
	if err != nil {
		return fmt.Errorf("create temporary certificate file: %w", err)
	}

	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	err = tmp.Chmod(0o600)
	if err == nil {
		_, err = tmp.Write(data)
	}

	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return fmt.Errorf("write temporary certificate file: %w", err)
	}

	err = os.Rename(tmpName, filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("replace certificate file: %w", err)
	}

	return nil
}

// publish writes the CA into the configuration. Without it every admission fails,
// which under failurePolicy Fail blocks pod creation outright.
func publish(ctx context.Context, c client.Client, opts Options, ca []byte) error {
	var configuration admissionv1.MutatingWebhookConfiguration

	err := c.Get(ctx, client.ObjectKey{Name: opts.WebhookName}, &configuration)
	if apierrors.IsNotFound(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("get webhook configuration %s: %w", opts.WebhookName, err)
	}

	changed := false

	for i := range configuration.Webhooks {
		if !bytes.Equal(configuration.Webhooks[i].ClientConfig.CABundle, ca) {
			configuration.Webhooks[i].ClientConfig.CABundle = ca
			changed = true
		}
	}

	if !changed {
		return nil
	}

	err = c.Update(ctx, &configuration)
	if err != nil {
		return fmt.Errorf("publish caBundle to %s: %w", opts.WebhookName, err)
	}

	return nil
}
