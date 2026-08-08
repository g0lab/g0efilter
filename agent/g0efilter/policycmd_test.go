//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

const learnedPolicy = `allowlist:
  ips:
    - '10.96.0.10'
  domains:
    - 'api.example.com'
    - '*.cdn.example.com'
`

func writePolicy(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(path, []byte(body), 0o600)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	return path
}

// decodeConfigMap proves the output is real YAML rather than something that merely
// looks right, since the whole point is piping it into kubectl apply.
func decodeConfigMap(t *testing.T, rendered string) map[string]any {
	t.Helper()

	var doc map[string]any

	err := yaml.Unmarshal([]byte(rendered), &doc)
	if err != nil {
		t.Fatalf("rendered ConfigMap is not valid YAML: %v\n%s", err, rendered)
	}

	return doc
}

func TestHandlePolicyIgnoresOtherCommands(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"g0efilter"},
		{"g0efilter", "caps"},
		{"g0efilter", "healthcheck"},
		{"g0efilter", "policies"},
	} {
		var out, errOut bytes.Buffer

		handled, code := handlePolicy(args, &out, &errOut)
		if handled || code != 0 || out.Len() != 0 {
			t.Errorf("args %v were handled: code=%d out=%q", args, code, out.String())
		}
	}
}

func configMapData(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	data, ok := doc["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is %T", doc["data"])
	}

	return data
}

func configMapMetadata(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is %T", doc["metadata"])
	}

	return metadata
}

// Not parallel: t.Setenv cannot be used alongside t.Parallel.
func TestHandlePolicyRendersAnApplyableConfigMap(t *testing.T) {
	t.Setenv("POLICY_CONFIGMAP", "")
	t.Setenv("POD_NAMESPACE", "apps")

	path := writePolicy(t, learnedPolicy)

	var out, errOut bytes.Buffer

	_, code := handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}

	doc := decodeConfigMap(t, out.String())

	if doc["kind"] != "ConfigMap" || doc["apiVersion"] != "v1" {
		t.Errorf("apiVersion/kind = %v/%v", doc["apiVersion"], doc["kind"])
	}

	metadata := configMapMetadata(t, doc)
	if metadata["name"] != "g0efilter-policy" || metadata["namespace"] != "apps" {
		t.Errorf("metadata = %v", metadata)
	}

	embedded, ok := configMapData(t, doc)["policy.yaml"].(string)
	if !ok {
		t.Fatal("data[policy.yaml] is not a string")
	}

	// The embedded document has to survive the round trip intact, or applying it
	// would change the policy it came from.
	if strings.TrimSpace(embedded) != strings.TrimSpace(learnedPolicy) {
		t.Errorf("embedded policy changed:\ngot:\n%s\nwant:\n%s", embedded, learnedPolicy)
	}

	if !strings.Contains(errOut.String(), "2 allowed domains, 1 allowed IPs") {
		t.Errorf("no summary on stderr: %q", errOut.String())
	}
}

// The summary belongs on stderr so stdout can be piped straight into kubectl.
// Not parallel: t.Setenv cannot be used alongside t.Parallel.
func TestHandlePolicyKeepsStdoutPipeable(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")

	path := writePolicy(t, learnedPolicy)

	var out, errOut bytes.Buffer

	handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)

	if strings.Contains(out.String(), "g0efilter:") {
		t.Errorf("log output leaked into stdout: %q", out.String())
	}

	metadata := configMapMetadata(t, decodeConfigMap(t, out.String()))

	// Without POD_NAMESPACE the ConfigMap must stay namespace-less so it applies to
	// whichever namespace kubectl targets.
	if _, ok := metadata["namespace"]; ok {
		t.Errorf("a namespace was emitted without POD_NAMESPACE: %v", metadata)
	}
}

// Not parallel: t.Setenv cannot be used alongside t.Parallel.
func TestHandlePolicyHonoursOverrides(t *testing.T) {
	t.Setenv("POLICY_CONFIGMAP", "custom-policy")
	t.Setenv("POD_NAMESPACE", "team-a")

	path := writePolicy(t, learnedPolicy)

	var out, errOut bytes.Buffer

	handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)

	metadata := configMapMetadata(t, decodeConfigMap(t, out.String()))

	if metadata["name"] != "custom-policy" || metadata["namespace"] != "team-a" {
		t.Errorf("metadata = %v", metadata)
	}
}

func TestHandlePolicyReadsTheFileWhenEnvironmentPolicyIsSet(t *testing.T) {
	t.Setenv("ALLOWLIST_DOMAINS", "not a valid domain")

	path := writePolicy(t, learnedPolicy)

	var out, errOut bytes.Buffer

	_, code := handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}

	policyYAML, ok := configMapData(t, decodeConfigMap(t, out.String()))["policy.yaml"].(string)
	if !ok || !strings.Contains(policyYAML, "api.example.com") {
		t.Error("the emitted ConfigMap did not come from the requested file")
	}
}

// The ConfigMap key has to match the mounted file name, or the agent would not find
// the policy after the ConfigMap is applied.
func TestHandlePolicyKeyMatchesTheFileName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "egress.yaml")

	err := os.WriteFile(path, []byte(learnedPolicy), 0o600)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var out, errOut bytes.Buffer

	handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)

	data := configMapData(t, decodeConfigMap(t, out.String()))

	if _, ok := data["egress.yaml"]; !ok {
		t.Errorf("data keys = %v, want egress.yaml", data)
	}
}

func TestHandlePolicyFailsOnUnusableInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		path string
	}{
		{name: "missing file", path: filepath.Join(t.TempDir(), "absent.yaml")},
		{name: "empty file", body: "\n"},
		{name: "malformed yaml", body: "allowlist: [unclosed\n"},
		{name: "invalid domain", body: "allowlist:\n  domains:\n    - 'not a domain'\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := tc.path
			if path == "" {
				path = writePolicy(t, tc.body)
			}

			var out, errOut bytes.Buffer

			_, code := handlePolicy([]string{"g0efilter", "policy", path}, &out, &errOut)
			if code == 0 {
				t.Errorf("unusable policy accepted, stdout:\n%s", out.String())
			}

			if out.Len() != 0 {
				t.Errorf("a partial ConfigMap was printed: %q", out.String())
			}
		})
	}
}

func TestPolicyCmdPathPrefersTheArgument(t *testing.T) {
	t.Setenv("POLICY_PATH", "/from/env.yaml")

	if got := policyCmdPath([]string{"g0efilter", "policy", "/explicit.yaml"}); got != "/explicit.yaml" {
		t.Errorf("policyCmdPath() = %q, want the argument", got)
	}

	if got := policyCmdPath([]string{"g0efilter", "policy"}); got != "/from/env.yaml" {
		t.Errorf("policyCmdPath() = %q, want POLICY_PATH", got)
	}
}

func TestRenderConfigMapIndentsNestedDocuments(t *testing.T) {
	t.Parallel()

	rendered := renderConfigMap("p", "", "policy.yaml", "allowlist:\n  domains:\n    - 'a.example'")

	// Every non-empty line of the embedded document must be indented past the key, or
	// the block scalar ends early and the ConfigMap silently loses most of the policy.
	for line := range strings.SplitSeq(strings.TrimRight(rendered, "\n"), "\n") {
		if strings.HasPrefix(line, "allowlist:") || strings.HasPrefix(line, "  domains:") {
			t.Errorf("line %q is not indented into the block scalar", line)
		}
	}

	data := configMapData(t, decodeConfigMap(t, rendered))

	embedded, ok := data["policy.yaml"].(string)
	if !ok {
		t.Fatal("data[policy.yaml] is not a string")
	}

	if !strings.Contains(embedded, "a.example") {
		t.Errorf("embedded policy lost content: %v", data)
	}
}
