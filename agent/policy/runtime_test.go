package policy_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

// controllerDocument is copied verbatim from the controller's render output, pinning the contract.
const controllerDocument = `# Rendered by the g0efilter controller. Do not edit.
allowlist:
  ips:
    - '10.0.0.0/8'
  domains:
    - 'api.example.com'
runtime: {"mode":"dns-strict","enforcement":"audit","dnsUpstreams":["10.96.0.10:53"],` +
	`"dnsHardening":false,"dnsRateQps":25,"dnsRateBurst":50}
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

func TestTheAgentParsesTheDocumentTheControllerRenders(t *testing.T) {
	t.Parallel()

	pol, err := policy.ReadFile(writePolicy(t, controllerDocument))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	if pol.Runtime == nil {
		t.Fatal("the runtime block was not parsed")
	}

	want := policy.Runtime{
		Mode:         "dns-strict",
		Enforcement:  "audit",
		DNSUpstreams: []string{"10.96.0.10:53"},
		DNSRateQPS:   25,
		DNSRateBurst: 50,
	}

	got := *pol.Runtime
	hardening := got.DNSHardening
	got.DNSHardening = nil

	if !reflect.DeepEqual(got, want) {
		t.Errorf("runtime:\ngot  %+v\nwant %+v", got, want)
	}

	if hardening == nil || *hardening {
		t.Error("dnsHardening did not survive as an explicit false")
	}

	if !reflect.DeepEqual(pol.AllowIPs, []string{"10.0.0.0/8"}) {
		t.Errorf("allowIPs = %v, want [10.0.0.0/8]", pol.AllowIPs)
	}
}

// Docker and Compose users write no runtime block, and must keep their environment.
func TestAPolicyWithoutARuntimeBlockLeavesItUnset(t *testing.T) {
	t.Parallel()

	pol, err := policy.ReadFile(writePolicy(t, "allowlist:\n  domains:\n    - 'api.example.com'\n"))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	if pol.Runtime != nil {
		t.Errorf("runtime = %+v, want nil", pol.Runtime)
	}
}

// The hash covers the exact bytes parsed, so a reload is never attributed to unread content.
func TestThePolicyHashCoversTheBytesThatWereParsed(t *testing.T) {
	t.Parallel()

	first, err := policy.ReadFile(writePolicy(t, controllerDocument))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	same, err := policy.ReadFile(writePolicy(t, controllerDocument))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	if first.Hash == "" {
		t.Fatal("the policy hash is empty")
	}

	if first.Hash != same.Hash {
		t.Errorf("identical documents hashed differently: %s vs %s", first.Hash, same.Hash)
	}

	changed, err := policy.ReadFile(writePolicy(t, controllerDocument+"# trailing\n"))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	if changed.Hash == first.Hash {
		t.Error("a changed document kept the same hash")
	}
}

// A runtime block the agent cannot understand must not take the allowlist with it.
func TestAnUnknownRuntimeKeyIsIgnored(t *testing.T) {
	t.Parallel()

	document := "allowlist:\n  domains:\n    - 'api.example.com'\n" +
		`runtime: {"mode":"https","somethingNew":true}` + "\n"

	pol, err := policy.ReadFile(writePolicy(t, document))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}

	if pol.Runtime == nil || pol.Runtime.Mode != "https" {
		t.Errorf("runtime = %+v, want mode https", pol.Runtime)
	}
}
