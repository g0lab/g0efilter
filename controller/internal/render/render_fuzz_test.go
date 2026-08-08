package render_test

import (
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
	"sigs.k8s.io/yaml"
)

// document is the shape the agent's policy loader expects.
type document struct {
	Allowlist struct {
		IPs     []string `json:"ips"`
		Domains []string `json:"domains"`
	} `json:"allowlist"`
}

// The rendered document is written into a ConfigMap and parsed by the agent, so a
// value that breaks the YAML disables filtering for every pod that mounts it.
func FuzzDocumentIsParseableYAML(f *testing.F) {
	for _, seed := range []struct {
		domain, network string
		port            int32
	}{
		{"example.com", "10.0.0.0/8", 443},
		{"*.example.com", "1.2.3.4", 0},
		{`/^api\.example\.com$/`, "2001:db8::1", 8443},
		{"", "", 0},
		{"*", "not-an-ip", 1},
		{"a'b.example.com", "1.2.3.4", 0},
		{`/^a'b$/`, "1.2.3.4", 0},
		{"a\"b.example.com", "::1", 65535},
		{"#comment", "1.2.3.4", 0},
		{"-", "1.2.3.4", 0},
	} {
		f.Add(seed.domain, seed.network, seed.port)
	}

	f.Fuzz(func(t *testing.T, domain, network string, port int32) {
		policy, err := render.Rules(rules(domain, network, port))
		if err != nil {
			return
		}

		text := policy.Document()

		var parsed document

		err = yaml.Unmarshal([]byte(text), &parsed)
		if err != nil {
			t.Fatalf("rendered an unparseable document from domain=%q network=%q port=%d: %v\n%s",
				domain, network, port, err, text)
		}

		assertSameEntries(t, "domains", parsed.Allowlist.Domains, policy.Domains, text)
		assertSameEntries(t, "ips", parsed.Allowlist.IPs, policy.Networks, text)

		for _, entry := range parsed.Allowlist.Domains {
			if entry == "*" {
				t.Fatalf("domain %q rendered a bare wildcard:\n%s", domain, text)
			}
		}

		// The ConfigMap is only rewritten when the document changes, so an unstable
		// render would reload every filtered pod on every reconcile.
		if again := policy.Document(); again != text {
			t.Fatalf("render is not deterministic:\n%s\n%s", text, again)
		}
	})
}

// assertSameEntries checks the parsed document carries exactly what was rendered:
// a value that silently changes on the way through YAML is a policy change.
func assertSameEntries(t *testing.T, field string, got, want []string, text string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s: parsed %d entries, rendered %d:\n%s", field, len(got), len(want), text)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s[%d]: parsed %q, rendered %q:\n%s", field, i, got[i], want[i], text)
		}
	}
}

func rules(domain, network string, port int32) []v1alpha1.EgressRule {
	peer := v1alpha1.EgressPeer{DomainNames: nil, Networks: nil}

	if domain != "" {
		peer.DomainNames = []string{domain}
	}

	if network != "" {
		peer.Networks = []string{network}
	}

	rule := v1alpha1.EgressRule{Name: "fuzz", To: []v1alpha1.EgressPeer{peer}, Ports: nil}

	if port != 0 {
		rule.Ports = []v1alpha1.EgressPort{{Protocol: "TCP", Port: port}}
	}

	return []v1alpha1.EgressRule{rule}
}

// Merging a ClusterEgressPolicy must only ever add destinations: a baseline that
// could drop an entry would silently narrow a namespace's policy.
func FuzzClusterPolicyOnlyAdds(f *testing.F) {
	f.Add("example.com", "other.example.com")
	f.Add("*.example.com", "*.example.com")
	f.Add("a.example.com", "")
	f.Add("", "b.example.com")

	f.Fuzz(func(t *testing.T, namespaced, cluster string) {
		base, err := render.Rules(rules(namespaced, "", 0))
		if err != nil {
			return
		}

		merged, err := render.Rules(rules(namespaced, "", 0), rules(cluster, "", 0))
		if err != nil {
			return
		}

		present := make(map[string]bool, len(merged.Domains))
		for _, entry := range merged.Domains {
			present[entry] = true
		}

		for _, entry := range base.Domains {
			if !present[entry] {
				t.Fatalf("merging %q dropped %q from the namespaced policy", cluster, entry)
			}
		}

		if !strings.Contains(strings.Join(merged.Domains, "\n"), strings.TrimSpace(cluster)) &&
			cluster != "" && !base.Empty() {
			t.Fatalf("merging %q added nothing to %v", cluster, merged.Domains)
		}
	})
}
