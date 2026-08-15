package e2e_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

const reloadChurnRounds = 4

func churnPolicy(round int) string {
	return `---
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'
    - 'churn` + strconv.Itoa(round) + `.example.com'
`
}

func TestPhase21Resilience(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.BaselineConfig(t, mode))

	mark := s.AgentLogMark(t)

	sendHostileInput(t, s)
	churnPolicyReloads(t, s)

	s.AssertAllowed(t, "https://github.com")
	s.AssertBlocked(t, "https://google.com")

	assertProcessSurvived(t, s, mark)
}

type hostilePayload struct {
	name    string
	command string
}

func hostilePayloads() []hostilePayload {
	return []hostilePayload{
		{"truncated TLS record", `printf '\x16\x03\x01\xff\xff\x01' | nc -w2 github.com 443`},
		{
			"TLS record with oversized extensions",
			`printf '\x16\x03\x01\x00\x05\x01\x00\xff\xfa\x00' | nc -w2 github.com 443`,
		},
		{"empty HTTP request line", `printf '\r\n\r\n' | nc -w2 github.com 80`},
		{"unterminated HTTP header block", `printf 'GET / HTTP/1.1\r\nHost: ' | nc -w2 github.com 80`},
		{"binary garbage as an HTTP request", `printf '\x00\x01\x02\x03\xff\xfe\xfd' | nc -w2 github.com 80`},
		{
			"DNS header with a missing question",
			`printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' | nc -u -w2 1.1.1.1 53`,
		},
		{"two-byte DNS message", `printf '\x00\x00' | nc -u -w2 1.1.1.1 53`},
		{
			"DNS query with an overlong label",
			`printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff' | nc -u -w2 1.1.1.1 53`,
		},
	}
}

func sendHostileInput(t *testing.T, s *harness.Stack) {
	t.Helper()

	for round := range 3 {
		for _, payload := range hostilePayloads() {
			res := s.ExecTester(t, "sh", "-lc", payload.command+" >/dev/null 2>&1 || true")
			if res.Err != nil {
				t.Fatalf("round %d, %s: %v", round, payload.name, res.Err)
			}
		}
	}

	s.ExecTester(t, "sh", "-lc",
		"for i in $(seq 1 20); do nc -w1 -z github.com 443 >/dev/null 2>&1 || true; done")
}

func churnPolicyReloads(t *testing.T, s *harness.Stack) {
	t.Helper()

	for round := range reloadChurnRounds {
		s.WritePolicyAndWait(t, churnPolicy(round))

		s.ExecTester(t, "sh", "-lc",
			"for i in 1 2 3; do (nc -w1 -z github.com 443 >/dev/null 2>&1 || true) & done; wait")
	}

	s.ResetPolicy(t)
}

func assertProcessSurvived(t *testing.T, s *harness.Stack, mark harness.LogMark) {
	t.Helper()

	running, restarts := s.AgentHealth(t)
	if !running || restarts > 0 {
		t.Errorf("agent did not survive: running=%v restarts=%d", running, restarts)
	}

	if n := s.AgentEventCountSince(t, mark, harness.EventMatcher{Event: "panic.recovered"}); n > 0 {
		t.Errorf("%d panic(s) reached a goroutine boundary; see the agent log for the stack", n)
	}

	for _, event := range []string{"dns.listen_udp_error", "dns.listen_tcp_error", "tcp.listen_error"} {
		if n := s.AgentEventCountSince(t, mark, harness.EventMatcher{Event: event}); n > 0 {
			t.Errorf("%d %s event(s): a listener failed to rebind after a reload", n, event)
		}
	}

	if n := s.AgentEventCountSince(t, mark, harness.EventMatcher{Event: "*.exited_unexpectedly"}); n > 0 {
		t.Errorf("%d service(s) exited unexpectedly", n)
	}
}

func TestPhase22CleanShutdown(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.BaselineConfig(t, mode))

	s.AssertAllowed(t, "https://github.com")

	mark := s.AgentLogMark(t)

	res := s.ExecAgent(t, "sh", "-lc", "kill -TERM 1")
	if res.Err != nil {
		t.Fatalf("send SIGTERM: %v", res.Err)
	}

	s.WaitForAgentEvent(t, mark, harness.EventMatcher{Event: "shutdown.complete"}, 30*time.Second)

	if n := s.AgentEventCountSince(t, mark, harness.EventMatcher{Event: "shutdown.incomplete"}); n > 0 {
		t.Error("shutdown timed out waiting for its goroutines instead of joining them")
	}

	if n := s.AgentEventCountSince(t, mark, harness.EventMatcher{Event: "panic.recovered"}); n > 0 {
		t.Errorf("%d panic(s) during shutdown", n)
	}
}
