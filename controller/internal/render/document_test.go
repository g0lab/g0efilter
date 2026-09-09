package render_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
)

func runtimeBlock(t *testing.T, document string) map[string]any {
	t.Helper()

	_, encoded, found := strings.Cut(document, "\nruntime: ")
	if !found {
		t.Fatalf("document carries no runtime block:\n%s", document)
	}

	var block map[string]any

	err := json.Unmarshal([]byte(strings.TrimSpace(encoded)), &block)
	if err != nil {
		t.Fatalf("parse the runtime block %q: %v", encoded, err)
	}

	return block
}

func documentFor(t *testing.T, policy render.Policy, spec v1alpha1.SidecarSpec) string {
	t.Helper()

	document, err := policy.DocumentFor(spec)
	if err != nil {
		t.Fatalf("DocumentFor() = %v", err)
	}

	return document
}

// Rules and their settings must arrive in one file, or new rules run under the old settings.
func TestDocumentForKeepsTheRulesAndTheRuntimeSettingsTogether(t *testing.T) {
	t.Parallel()

	policy, err := render.Rules([]v1alpha1.EgressRule{
		{To: []v1alpha1.EgressPeer{{DomainNames: []string{"api.example.com"}}}},
	})
	if err != nil {
		t.Fatalf("Rules() = %v", err)
	}

	document := documentFor(t, policy, v1alpha1.SidecarSpec{Mode: "dns-strict"})

	if !strings.Contains(document, "api.example.com") {
		t.Errorf("document lost its rules:\n%s", document)
	}

	if got := runtimeBlock(t, document)["mode"]; got != "dns-strict" {
		t.Errorf("runtime mode = %v, want dns-strict", got)
	}
}

func TestDocumentForCarriesEveryReloadableSetting(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{
		Mode:        "dns",
		Enforcement: "audit",
		DNS: v1alpha1.DNSSpec{
			Upstreams: []string{"10.96.0.10:53"},
			Hardening: new(bool),
			RateQPS:   new(int32(25)),
			RateBurst: new(int32(50)),
		},
	}

	block := runtimeBlock(t, documentFor(t, render.Policy{}, spec))

	want := map[string]any{
		"mode":         "dns",
		"enforcement":  "audit",
		"dnsHardening": false,
		"dnsRateQps":   float64(25),
		"dnsRateBurst": float64(50),
	}

	for key, value := range want {
		if block[key] != value {
			t.Errorf("runtime[%q] = %v, want %v", key, block[key], value)
		}
	}

	upstreams, ok := block["dnsUpstreams"].([]any)
	if !ok || len(upstreams) != 1 || upstreams[0] != "10.96.0.10:53" {
		t.Errorf("runtime dnsUpstreams = %v, want [10.96.0.10:53]", block["dnsUpstreams"])
	}
}

// An unchanged spec must not rewrite the ConfigMap, or every pod reloads on every reconcile.
func TestDocumentForIsDeterministic(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{
		Mode: "dns-strict",
		DNS:  v1alpha1.DNSSpec{Upstreams: []string{"10.96.0.10:53", "10.96.0.11:53"}},
	}

	policy, err := render.Rules([]v1alpha1.EgressRule{
		{To: []v1alpha1.EgressPeer{{DomainNames: []string{"b.example.com", "a.example.com"}}}},
	})
	if err != nil {
		t.Fatalf("Rules() = %v", err)
	}

	first := documentFor(t, policy, spec)

	second := documentFor(t, policy, spec)
	if first != second {
		t.Errorf("DocumentFor is not deterministic:\n%s\n%s", first, second)
	}
}

func TestDocumentForStillRendersAnEmptyPolicy(t *testing.T) {
	t.Parallel()

	document := documentFor(t, render.Policy{}, v1alpha1.SidecarSpec{})

	for _, want := range []string{"ips: []", "domains: []", "runtime: "} {
		if !strings.Contains(document, want) {
			t.Errorf("empty document is missing %q:\n%s", want, document)
		}
	}
}

// The runtime block is appended after the allowlist, so the document must stay valid YAML.
func TestDocumentForEndsWithANewline(t *testing.T) {
	t.Parallel()

	document := documentFor(t, render.Policy{}, v1alpha1.SidecarSpec{})
	if !strings.HasSuffix(document, "\n") {
		t.Errorf("document does not end with a newline: %q", document)
	}
}
