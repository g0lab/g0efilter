package harness

import (
	"os"
	"slices"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"
)

const policyReloadTimeout = 45 * time.Second

// BaselinePolicy is the allowlist most phases start from.
const BaselinePolicy = `---
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'
`

// WritePolicy replaces the policy file atomically, so the agent never observes a
// half-written file mid-poll.
func (s *Stack) WritePolicy(t *testing.T, policy string) {
	t.Helper()

	err := writePolicyFile(s.PolicyFile, policy)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

// WritePolicyAndWait writes a policy and waits for the agent to apply it.
// Writing an identical policy produces no reload event, so this makes the
// no-op case explicit rather than hanging until the timeout.
func (s *Stack) WritePolicyAndWait(t *testing.T, policy string) {
	t.Helper()

	current, err := os.ReadFile(s.PolicyFile)
	if err == nil && string(current) == policy {
		t.Log("policy unchanged; no reload expected")

		return
	}

	mark := s.AgentLogMark(t)
	s.WritePolicy(t, policy)
	s.WaitForAgentEvent(t, mark, EventMatcher{Event: "policy.applied"}, policyReloadTimeout)
}

// ResetPolicy returns the stack to the baseline allowlist. Shared stacks are
// reused across phases, so each phase establishes its own starting policy rather
// than inheriting whatever the previous one left behind.
func (s *Stack) ResetPolicy(t *testing.T) {
	t.Helper()

	s.WritePolicyAndWait(t, BaselinePolicy)
}

// PolicyContents reads the policy file from the host side.
func (s *Stack) PolicyContents(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(s.PolicyFile)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}

	return string(data)
}

// AssertPolicyContains requires an entry to be present in the policy file,
// waiting because the agent writes it asynchronously (remote unblock, learning).
// The file is decoded rather than substring-matched so a change of YAML quoting
// style fails loudly instead of timing out.
func (s *Stack) AssertPolicyContains(t *testing.T, entry string, timeout time.Duration) {
	t.Helper()

	Eventually(t, timeout, time.Second, func() (bool, string) {
		data, err := os.ReadFile(s.PolicyFile)
		if err != nil {
			return false, "read policy: " + err.Error()
		}

		var doc struct {
			Allowlist struct {
				IPs     []string `yaml:"ips"`
				Domains []string `yaml:"domains"`
			} `yaml:"allowlist"`
		}

		err = yaml.Unmarshal(data, &doc)
		if err != nil {
			return false, "parse policy: " + err.Error() + "\n" + string(data)
		}

		found := slices.Contains(doc.Allowlist.IPs, entry) ||
			slices.Contains(doc.Allowlist.Domains, entry)

		return found, entry + " not in policy:\n" + string(data)
	})
}
