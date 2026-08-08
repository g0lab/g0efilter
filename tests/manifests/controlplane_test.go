package manifests_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const controllerChart = "g0efilter-controller"

func controllerTemplate(t *testing.T, args ...string) map[string]map[string]any {
	t.Helper()
	serialHelm(t)

	base := make([]string, 0, 5+len(args))
	base = append(base, "template", "g0efilter", repoPath("deploy", "helm", controllerChart),
		"--namespace", "g0efilter-system")

	return byKind(t, decodeDocs(t, run(t, "helm", append(base, args...)...)))
}

// The chart installs the same control plane as deploy/webhook. A difference means an
// operator gets different admission behaviour depending on how they installed it.
func TestControllerChartMatchesTheWebhookOverlay(t *testing.T) {
	t.Parallel()

	fromHelm := controllerTemplate(t)
	fromKustomize := byKind(t, decodeDocs(t, renderKustomize(t, repoPath("deploy", "webhook"))))

	helmWebhook := webhookEntry(t, fromHelm["MutatingWebhookConfiguration"])
	kzWebhook := webhookEntry(t, fromKustomize["MutatingWebhookConfiguration"])

	for _, key := range []string{"failurePolicy", "timeoutSeconds", "sideEffects", "rules", "objectSelector"} {
		if normalise(t, helmWebhook[key]) != normalise(t, kzWebhook[key]) {
			t.Errorf("webhook %s differs:\nhelm:      %s\nkustomize: %s",
				key, normalise(t, helmWebhook[key]), normalise(t, kzWebhook[key]))
		}
	}

	if got := child(t, child(t, helmWebhook, "clientConfig"), "service")["path"]; got != "/inject-sidecar" {
		t.Errorf("the chart posts admission to %v", got)
	}
}

// The webhook must not watch the namespace its own control plane runs in, or a
// failing webhook could stop the controller being rescheduled.
func TestControllerChartExcludesItsOwnNamespace(t *testing.T) {
	t.Parallel()

	entry := webhookEntry(t, controllerTemplate(t)["MutatingWebhookConfiguration"])
	selector := child(t, entry, "namespaceSelector")

	var excluded []any

	for _, raw := range list(t, selector, "matchExpressions") {
		expression, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("unexpected match expression %T", raw)
		}

		if expression["key"] == "kubernetes.io/metadata.name" && expression["operator"] == "NotIn" {
			excluded = expression["values"].([]any) //nolint:forcetypeassert // asserted below
		}
	}

	if excluded == nil {
		t.Fatal("the chart excludes no namespace by name")
	}

	for _, want := range []string{"g0efilter-system", "kube-system"} {
		found := false

		for _, got := range excluded {
			if got == want {
				found = true
			}
		}

		if !found {
			t.Errorf("%s is not excluded: %v", want, excluded)
		}
	}
}

func webhookEntry(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	if doc == nil {
		t.Fatal("no MutatingWebhookConfiguration was rendered")
	}

	webhooks := list(t, doc, "webhooks")
	if len(webhooks) != 1 {
		t.Fatalf("%d webhooks declared, want 1", len(webhooks))
	}

	entry, ok := webhooks[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected webhook entry %T", webhooks[0])
	}

	return entry
}

// The chart's ClusterRole is hand-written, while deploy/controller/role.yaml is
// generated from the controller's kubebuilder markers. A drift would give the chart
// install too few - or too many - permissions.
func TestControllerChartRBACMatchesTheGeneratedRole(t *testing.T) {
	t.Parallel()

	fromHelm := controllerTemplate(t)

	raw, err := os.ReadFile(repoPath("deploy", "controller", "role.yaml"))
	if err != nil {
		t.Fatalf("read the generated role: %v", err)
	}

	generated := decodeDocs(t, raw)
	if len(generated) != 1 {
		t.Fatalf("deploy/controller/role.yaml holds %d documents, want 1", len(generated))
	}

	want := normalise(t, generated[0]["rules"])
	got := normalise(t, fromHelm["ClusterRole"]["rules"])

	if got != want {
		t.Errorf("the chart's ClusterRole rules differ from the generated role:\nchart:     %s\ngenerated: %s",
			got, want)
	}
}

// chartCRDsByName re-reads the rendered CRDs keyed by name, because byKind collapses
// the two of them onto one key.
func chartCRDsByName(t *testing.T) map[string]map[string]any {
	t.Helper()
	serialHelm(t)

	byName := map[string]map[string]any{}

	for _, doc := range decodeDocs(t, run(t, "helm", "template", "g0efilter",
		repoPath("deploy", "helm", controllerChart), "--namespace", "g0efilter-system")) {
		if doc["kind"] != "CustomResourceDefinition" {
			continue
		}

		name, ok := child(t, doc, "metadata")["name"].(string)
		if !ok {
			t.Fatal("a rendered CRD has no name")
		}

		byName[name] = doc
	}

	return byName
}

func assertCRDMatches(t *testing.T, chartCRD, source map[string]any, name string) {
	t.Helper()

	if normalise(t, chartCRD["spec"]) != normalise(t, source["spec"]) {
		t.Errorf("%s differs between the chart and deploy/crds; run scripts/gen-controller.sh", name)
	}

	// Deleting a CRD deletes every policy it holds, so uninstall must not.
	policy, ok := child(t, chartCRD, "metadata")["annotations"].(map[string]any)
	if !ok || policy["helm.sh/resource-policy"] != "keep" {
		t.Errorf("%s is not annotated helm.sh/resource-policy: keep", name)
	}
}

// The chart's CRD templates are generated from deploy/crds, so a regenerated CRD that
// was not propagated to the chart would install an older schema.
func TestControllerChartCRDsMatchDeployCRDs(t *testing.T) {
	t.Parallel()

	crds, err := filepath.Glob(repoPath("deploy", "crds", "*.yaml"))
	if err != nil || len(crds) == 0 {
		t.Fatalf("glob deploy/crds: %v", err)
	}

	byName := chartCRDsByName(t)

	if len(byName) != len(crds) {
		t.Fatalf("the chart renders %d CRDs, deploy/crds holds %d", len(byName), len(crds))
	}

	for _, path := range crds {
		raw, err := os.ReadFile(path) //nolint:gosec // a fixed repository path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		source := decodeDocs(t, raw)[0]
		name, _ := child(t, source, "metadata")["name"].(string)

		chartCRD, ok := byName[name]
		if !ok {
			t.Errorf("the chart does not install %s", name)

			continue
		}

		assertCRDMatches(t, chartCRD, source, name)
	}
}

func TestControllerChartCanSkipCRDs(t *testing.T) {
	t.Parallel()

	rendered := controllerTemplate(t, "--set", "crds.install=false")

	if _, ok := rendered["CustomResourceDefinition"]; ok {
		t.Error("crds.install=false still installed the CRDs")
	}

	// Everything else must still be there.
	for _, kind := range []string{"Deployment", "ClusterRole", "MutatingWebhookConfiguration"} {
		if _, ok := rendered[kind]; !ok {
			t.Errorf("%s was dropped along with the CRDs", kind)
		}
	}
}

// Without the webhook the chart is a plain controller: it renders policies into
// ConfigMaps and injects nothing.
func TestControllerChartCanRunWithoutTheWebhook(t *testing.T) {
	t.Parallel()

	rendered := controllerTemplate(t, "--set", "webhook.enabled=false")

	for _, kind := range []string{"MutatingWebhookConfiguration", "Service"} {
		if _, ok := rendered[kind]; ok {
			t.Errorf("%s was rendered with the webhook disabled", kind)
		}
	}

	container := containerNamed(t, list(t, podSpec(t, rendered["Deployment"]), "containers"), "controller")
	for _, arg := range list(t, container, "args") {
		if arg == "--webhook" {
			t.Error("the controller is still started with --webhook")
		}
	}
}

func TestControllerTopologySelectorTracksFullnameOverride(t *testing.T) {
	t.Parallel()

	pod := podSpec(t, controllerTemplate(t, "--set", "fullnameOverride=custom")["Deployment"])
	constraints := list(t, pod, "topologySpreadConstraints")

	constraint, ok := constraints[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected topology constraint %T", constraints[0])
	}

	labels := child(t, child(t, constraint, "labelSelector"), "matchLabels")
	if got := labels["app.kubernetes.io/name"]; got != "custom" {
		t.Errorf("topology selector name = %v, want custom", got)
	}
}

func TestDashboardChartRendersAndPersists(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	rendered := byKind(t, decodeDocs(t, run(t, "helm", "template", "dash",
		repoPath("deploy", "helm", "g0efilter-dashboard"), "--namespace", "g0efilter-system")))

	for _, kind := range []string{"Deployment", "Service", "PersistentVolumeClaim", "ServiceAccount"} {
		if _, ok := rendered[kind]; !ok {
			t.Errorf("%s was not rendered", kind)
		}
	}

	// SQLite has one writer, so a second replica could not share the database.
	if got := child(t, rendered["Deployment"], "spec")["replicas"]; got != 1 {
		t.Errorf("replicas = %v, want 1", got)
	}

	if got := child(t, child(t, rendered["Deployment"], "spec"), "strategy")["type"]; got != "Recreate" {
		t.Errorf("strategy = %v, want Recreate", got)
	}

	if got := podSpec(t, rendered["Deployment"])["automountServiceAccountToken"]; got != false {
		t.Errorf("automountServiceAccountToken = %v, want false", got)
	}

	// The collected history must survive an uninstall.
	annotations, ok := child(t, rendered["PersistentVolumeClaim"], "metadata")["annotations"].(map[string]any)
	if !ok || annotations["helm.sh/resource-policy"] != "keep" {
		t.Error("the claim is not annotated helm.sh/resource-policy: keep")
	}
}

func TestDashboardCredentialChangeUpdatesPodTemplate(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	render := func(key string) map[string]map[string]any {
		return byKind(t, decodeDocs(t, run(t, "helm", "template", "dash",
			repoPath("deploy", "helm", "g0efilter-dashboard"), "--set", "secrets.apiKey="+key)))
	}

	checksum := func(docs map[string]map[string]any) any {
		template := child(t, child(t, docs["Deployment"], "spec"), "template")

		return child(t, child(t, template, "metadata"), "annotations")["checksum/credentials"]
	}

	if checksum(render("first")) == checksum(render("second")) {
		t.Error("changing a chart-managed credential did not update the pod template")
	}
}

func TestDashboardChartRejectsExistingAndInlineSecrets(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("deploy", "helm", "g0efilter-dashboard")

	out := runHelmExpectingFailure(t, "template", "dash", chart,
		"--set", "secrets.existingSecret=managed", "--set", "secrets.apiKey=inline")
	if !strings.Contains(out, "cannot be combined") {
		t.Errorf("error does not explain the conflict:\n%s", out)
	}
}

func TestDashboardChartRejectsMultipleJWTKeySources(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	chart := repoPath("deploy", "helm", "g0efilter-dashboard")

	out := runHelmExpectingFailure(t, "template", "dash", chart,
		"--set", "auth.mode=jwt",
		"--set", "auth.jwt.jwksUrl=https://issuer.example/jwks",
		"--set", "auth.jwt.publicKey=key")
	if !strings.Contains(out, "exactly one key source") {
		t.Errorf("error does not explain the conflict:\n%s", out)
	}
}

// Credentials given in values must never end up as literals in the pod spec.
func TestDashboardChartKeepsCredentialsInASecret(t *testing.T) {
	t.Parallel()
	serialHelm(t)

	rendered := byKind(t, decodeDocs(t, run(t, "helm", "template", "dash",
		repoPath("deploy", "helm", "g0efilter-dashboard"), "--namespace", "g0efilter-system",
		"--set", "secrets.apiKey=super-secret-key")))

	if _, ok := rendered["Secret"]; !ok {
		t.Fatal("no Secret was rendered")
	}

	container := containerNamed(t, list(t, podSpec(t, rendered["Deployment"]), "containers"), "dashboard")

	for _, raw := range list(t, container, "env") {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("unexpected env entry %T", raw)
		}

		if entry["value"] == "super-secret-key" {
			t.Errorf("%v carries the API key as a literal", entry["name"])
		}
	}
}
