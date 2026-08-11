package manifests_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// The webhook overlay is what decides whether a control-plane outage stops
// unfiltered pods or admits them, so its admission settings are asserted rather
// than left to review.
func TestWebhookOverlayFailsClosedAndOnlyOptedInNamespaces(t *testing.T) {
	t.Parallel()

	docs := byKind(t, decodeDocs(t, renderKustomize(t, filepath.Join("..", "..", "deploy", "webhook"))))

	configuration, ok := docs["MutatingWebhookConfiguration"]
	if !ok {
		t.Fatal("the overlay renders no MutatingWebhookConfiguration")
	}

	hooks := list(t, configuration, "webhooks")
	if len(hooks) != 1 {
		t.Fatalf("the configuration declares %d webhooks, want 1", len(hooks))
	}

	hook, isMap := hooks[0].(map[string]any)
	if !isMap {
		t.Fatalf("unexpected webhook entry %T", hooks[0])
	}

	if hook["failurePolicy"] != "Fail" {
		t.Errorf("failurePolicy = %v; an unreachable webhook must not admit unfiltered pods", hook["failurePolicy"])
	}

	if hook["sideEffects"] != "None" {
		t.Errorf("sideEffects = %v, want None", hook["sideEffects"])
	}

	assertNamespaceGating(t, hook)

	if _, ok := docs["Service"]; !ok {
		t.Error("the overlay renders no Service for the API server to reach")
	}
}

// The cert-manager overlay must hand the certificate over completely: a controller
// still issuing its own would fight cainjector over the caBundle.
func TestCertManagerOverlayDelegatesTheCertificate(t *testing.T) {
	t.Parallel()

	rendered := string(renderKustomize(t, filepath.Join("..", "..", "deploy", "webhook-cert-manager")))

	for _, want := range []string{
		"--webhook-cert-source=external",
		"cert-manager.io/inject-ca-from: g0efilter-system/g0efilter-webhook",
		"secretName: g0efilter-webhook-cert",
		"kind: Certificate",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the overlay is missing %q", want)
		}
	}

	// An emptyDir would shadow the Secret cert-manager writes.
	if strings.Contains(rendered, "emptyDir") {
		t.Error("the certificate volume is still an emptyDir")
	}
}

func TestWebhookSelfSignedCertificateRBACIsScoped(t *testing.T) {
	t.Parallel()

	selfSigned := decodeDocs(t, renderKustomize(t, filepath.Join("..", "..", "deploy", "webhook")))

	base, ok := findObject(selfSigned, "ClusterRole", "g0efilter-controller")
	if !ok {
		t.Fatal("the webhook overlay renders no base controller ClusterRole")
	}

	baseRules := normalise(t, base["rules"])
	for _, forbidden := range []string{"secrets", "mutatingwebhookconfigurations"} {
		if strings.Contains(baseRules, forbidden) {
			t.Errorf("the base controller ClusterRole still grants %s:\n%s", forbidden, baseRules)
		}
	}

	secretRole, ok := findObject(selfSigned, "Role", "g0efilter-controller-webhook-certificates")
	if !ok {
		t.Fatal("self-signed mode renders no namespace-scoped certificate Role")
	}

	secretRules := normalise(t, secretRole["rules"])
	for _, want := range []string{"secrets", "g0efilter-webhook-cert", "create", "get", "update"} {
		if !strings.Contains(secretRules, want) {
			t.Errorf("the certificate Role is missing %q:\n%s", want, secretRules)
		}
	}

	publisher, ok := findObject(selfSigned, "ClusterRole", "g0efilter-controller-webhook-certificates")
	if !ok {
		t.Fatal("self-signed mode renders no CA-publisher ClusterRole")
	}

	publisherRules := normalise(t, publisher["rules"])
	for _, want := range []string{"mutatingwebhookconfigurations", "g0efilter-sidecar-injector"} {
		if !strings.Contains(publisherRules, want) {
			t.Errorf("the CA-publisher ClusterRole is missing %q:\n%s", want, publisherRules)
		}
	}
}

func TestWebhookCertManagerHasNoControllerCertificateRBAC(t *testing.T) {
	t.Parallel()

	docs := decodeDocs(t, renderKustomize(t,
		filepath.Join("..", "..", "deploy", "webhook-cert-manager")))
	for _, kind := range []string{"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} {
		if _, found := findObject(docs, kind, "g0efilter-controller-webhook-certificates"); found {
			t.Errorf("cert-manager mode retained the self-signed %s", kind)
		}
	}
}

func findObject(docs []map[string]any, kind, name string) (map[string]any, bool) {
	for _, doc := range docs {
		metadata, ok := doc["metadata"].(map[string]any)
		if ok && doc["kind"] == kind && metadata["name"] == name {
			return doc, true
		}
	}

	return nil, false
}

// Without both selectors the webhook sees every namespace, and a failure would
// stop the control plane itself being rescheduled.
func assertNamespaceGating(t *testing.T, hook map[string]any) {
	t.Helper()

	expressions := list(t, child(t, hook, "namespaceSelector"), "matchExpressions")
	if len(expressions) != 2 {
		t.Fatalf("namespaceSelector has %d expressions, want an opt-in and an exclusion", len(expressions))
	}

	found := map[string]string{}

	for _, entry := range expressions {
		expression, isMap := entry.(map[string]any)
		if !isMap {
			t.Fatalf("unexpected selector entry %T", entry)
		}

		key, _ := expression["key"].(string)
		operator, _ := expression["operator"].(string)
		found[key] = operator
	}

	if found["g0efilter.g0lab.com/inject"] != "In" {
		t.Errorf("namespaces are not gated on g0efilter.g0lab.com/inject: %v", found)
	}

	if found["kubernetes.io/metadata.name"] != "NotIn" {
		t.Errorf("the control-plane namespaces are not excluded: %v", found)
	}
}
