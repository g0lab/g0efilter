package render_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readCRD(t *testing.T, name string) string {
	t.Helper()

	//nolint:gosec // a fixed path under the repository's own deploy/crds directory
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "crds", name))
	if err != nil {
		t.Fatalf("read CRD: %v (run scripts/gen-controller.sh)", err)
	}

	return string(raw)
}

// The CRD manifests are generated from the Go types by scripts/gen-controller.sh.
// These assertions cover the parts consumers depend on, so a regenerate that changes
// the API surface shows up in review rather than only at apply time.
func TestGeneratedCRDsMatchTheAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file     string
		wantText []string
	}{
		{
			file: "g0efilter.g0lab.com_egresspolicies.yaml",
			wantText: []string{
				"name: egresspolicies.g0efilter.g0lab.com",
				"group: g0efilter.g0lab.com",
				"kind: EgressPolicy",
				"scope: Namespaced",
				"- g0ep",
				"name: v1alpha1",
				"subresources:",
				"status: {}",
				"podSelector:",
				"domainNames:",
				"networks:",
			},
		},
		{
			file: "g0efilter.g0lab.com_clusteregresspolicies.yaml",
			wantText: []string{
				"name: clusteregresspolicies.g0efilter.g0lab.com",
				"kind: ClusterEgressPolicy",
				"scope: Cluster",
				"- g0cep",
				"namespaceSelector:",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()

			crd := readCRD(t, tc.file)

			for _, want := range tc.wantText {
				if !strings.Contains(crd, want) {
					t.Errorf("CRD does not contain %q", want)
				}
			}
		})
	}
}

// Server-side validation is what stops a bad policy reaching the controller, so the
// constraints declared on the Go types must survive generation.
func TestGeneratedCRDKeepsValidation(t *testing.T) {
	t.Parallel()

	crd := readCRD(t, "g0efilter.g0lab.com_egresspolicies.yaml")

	for _, want := range []string{
		"maximum: 65535",
		"minimum: 1",
		"- TCP",
		"- UDP",
		// `to` is required: a rule naming no destination allows nothing and is a mistake.
		"- to",
	} {
		if !strings.Contains(crd, want) {
			t.Errorf("CRD lost validation %q", want)
		}
	}
}
