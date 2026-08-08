package main

import (
	"errors"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
)

func TestNewSchemeRegistersPolicyTypes(t *testing.T) {
	t.Parallel()

	scheme, err := newScheme()
	if err != nil {
		t.Fatalf("newScheme() = %v", err)
	}

	gvks, _, err := scheme.ObjectKinds(&v1alpha1.EgressPolicy{})
	if err != nil {
		t.Fatalf("EgressPolicy is not registered: %v", err)
	}

	if len(gvks) != 1 || gvks[0].Group != v1alpha1.GroupVersion.Group {
		t.Errorf("EgressPolicy GVKs = %v", gvks)
	}
}

func TestCertificateSourceModes(t *testing.T) {
	t.Parallel()

	err := setupCertificates(nil, options{certSource: certSourceExternal})
	if err != nil {
		t.Errorf("external certificate source = %v", err)
	}

	err = setupCertificates(nil, options{certSource: "invalid"})
	if !errors.Is(err, errCertSource) {
		t.Errorf("invalid certificate source = %v, want %v", err, errCertSource)
	}
}

func TestDisabledWebhookDoesNotRequireAManager(t *testing.T) {
	t.Parallel()

	err := startWebhook(nil, options{})
	if err != nil {
		t.Errorf("disabled webhook = %v", err)
	}
}
