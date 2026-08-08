package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSecretRefCopiesSelector(t *testing.T) {
	t.Parallel()

	selector := &corev1.SecretKeySelector{ //nolint:exhaustruct // name and key only
		LocalObjectReference: corev1.LocalObjectReference{Name: "credentials"},
		Key:                  "token",
	}

	env := secretRef("TOKEN", selector)
	env.ValueFrom.SecretKeyRef.Key = "changed"

	if selector.Key != "token" {
		t.Errorf("selector key = %q, want token", selector.Key)
	}
}
