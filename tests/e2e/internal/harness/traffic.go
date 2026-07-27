package harness

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	allowedTimeout = 10 * time.Second
	blockedTimeout = 5 * time.Second
	verdictTimeout = 15 * time.Second

	// connectRetryWindow covers a policy reload restarting the proxies.
	connectRetryWindow = 20 * time.Second

	resultPrefix = "G0E_RESULT"
)

// CurlResult is a structured request outcome from inside the tester container.
type CurlResult struct {
	URL       string
	ExitCode  int
	HTTPCode  int
	RemoteIP  string
	TimeTotal time.Duration
	Output    string
}

// Curl runs one request from the tester container, which shares the agent's
// network namespace.
func (s *Stack) Curl(t *testing.T, url string, timeout time.Duration, extra ...string) CurlResult {
	t.Helper()

	args := make([]string, 0, 12+len(extra))
	args = append(args,
		"curl", "--silent", "--show-error", "--output", "/dev/null",
		"--connect-timeout", "3",
		"--max-time", strconv.Itoa(curlTimeoutSeconds(timeout)),
		"--write-out", resultPrefix+" http=%{http_code} remote_ip=%{remote_ip} total=%{time_total}",
	)
	args = append(args, extra...)
	args = append(args, url)

	return parseCurlResult(url, s.ExecTester(t, args...))
}

func curlTimeoutSeconds(timeout time.Duration) int {
	return max(int(math.Ceil(timeout.Seconds())), 1)
}

func parseCurlResult(url string, res ExecResult) CurlResult {
	out := CurlResult{URL: url, ExitCode: res.ExitCode, Output: res.Output}

	for line := range strings.SplitSeq(res.Output, "\n") {
		_, tail, found := strings.Cut(line, resultPrefix)
		if !found {
			continue
		}

		for kv := range strings.FieldsSeq(tail) {
			key, value, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}

			switch key {
			case "http":
				out.HTTPCode, _ = strconv.Atoi(value)
			case "remote_ip":
				out.RemoteIP = value
			case "total":
				secs, err := strconv.ParseFloat(value, 64)
				if err == nil {
					out.TimeTotal = time.Duration(secs * float64(time.Second))
				}
			}
		}
	}

	return out
}

// Target is the host or IP a URL addresses, with scheme, path, brackets and port
// removed - the value the agent logs its verdict against.
func Target(url string) string {
	u := url
	if _, rest, ok := strings.Cut(u, "://"); ok {
		u = rest
	}

	u, _, _ = strings.Cut(u, "/")

	if bracketed, ok := strings.CutPrefix(u, "["); ok {
		inner, _, _ := strings.Cut(bracketed, "]")

		return inner
	}

	if strings.Count(u, ":") == 1 {
		u, _, _ = strings.Cut(u, ":")
	}

	return u
}

// AssertAllowed requires the request to connect and the agent to record an
// allow decision for it. Both halves matter: a connection that succeeds without
// a matching decision means the test is not measuring what it claims to.
func (s *Stack) AssertAllowed(t *testing.T, url string) CurlResult {
	t.Helper()

	mark := s.AgentLogMark(t)
	res := s.curlUntilConnected(t, url, "allowed")

	s.waitForVerdict(t, mark, url, allowedActions...)

	return res
}

// curlUntilConnected retries until the request connects or the window expires.
// A policy reload tears down and rebuilds the proxies and the ruleset, so a
// request landing in that window fails without the traffic being blocked. The
// assertion is unchanged - it still requires a real connection - but it will not
// fail on a reload it raced.
func (s *Stack) curlUntilConnected(t *testing.T, url, want string) CurlResult {
	t.Helper()

	var res CurlResult

	deadline := time.Now().Add(connectRetryWindow)

	for attempt := 1; ; attempt++ {
		res = s.Curl(t, url, allowedTimeout)
		if res.ExitCode == 0 {
			return res
		}

		if time.Now().After(deadline) {
			t.Fatalf("expected %s to be %s after %d attempts: curl exit=%d output=%q",
				url, want, attempt, res.ExitCode, res.Output)
		}

		time.Sleep(2 * time.Second)
	}
}

// AssertReachable requires the request to connect, without corroborating a
// verdict. Only for paths that record none by design: plain dns mode accepts
// direct-IP traffic in the kernel without logging it. Prefer AssertAllowed.
func (s *Stack) AssertReachable(t *testing.T, url string) CurlResult {
	t.Helper()

	return s.curlUntilConnected(t, url, "reachable")
}

// AssertBlocked requires the request to fail and the agent to record a block for
// it. The failure alone proves nothing - a broken resolver, a stopped tester or
// an unrelated network fault produces the same curl exit code.
func (s *Stack) AssertBlocked(t *testing.T, url string) CurlResult {
	t.Helper()

	deadline := time.Now().Add(connectRetryWindow)

	for attempt := 1; ; attempt++ {
		mark := s.AgentLogMark(t)

		res := s.Curl(t, url, blockedTimeout)
		if res.ExitCode == 0 {
			t.Fatalf("expected %s to be blocked, but it connected: %+v", url, res)
		}

		settle := time.Now().Add(time.Second)
		for time.Now().Before(settle) {
			if matched, _ := s.hasVerdict(t, mark, url, "BLOCKED"); matched {
				return res
			}

			time.Sleep(250 * time.Millisecond)
		}

		if time.Now().After(deadline) {
			_, detail := s.hasVerdict(t, mark, url, "BLOCKED")
			t.Fatalf("expected %s to be blocked after %d attempts: curl failed but %s",
				url, attempt, detail)
		}
	}
}

// AssertUnreachable requires the request to fail without corroborating a verdict.
// Kernel drops are logged against the destination IP rather than the hostname -
// pair this with AssertIPBlocked. Prefer AssertBlocked.
func (s *Stack) AssertUnreachable(t *testing.T, url string) CurlResult {
	t.Helper()

	res := s.Curl(t, url, blockedTimeout)
	if res.ExitCode == 0 {
		t.Fatalf("expected %s to be unreachable, but it connected: %+v", url, res)
	}

	return res
}

// allowedActions covers audit mode, where a would-be block is permitted through
// and recorded with the AUDIT action.
//
//nolint:gochecknoglobals // constant set
var allowedActions = []string{"ALLOWED", "AUDIT"}

// waitForVerdict finds a decision for the target under any of the field names
// the agent uses to record one.
func (s *Stack) waitForVerdict(t *testing.T, mark LogMark, url string, actions ...string) {
	t.Helper()

	Eventually(t, verdictTimeout, 500*time.Millisecond, func() (bool, string) {
		return s.hasVerdict(t, mark, url, actions...)
	})
}

func (s *Stack) hasVerdict(t *testing.T, mark LogMark, url string, actions ...string) (bool, string) {
	t.Helper()

	target := Target(url)
	keys := []string{"qname", "host", "https", "http_host", "destination_ip", "dst"}

	for _, e := range s.AgentEventsSince(t, mark) {
		if !slices.Contains(actions, e.Action()) {
			continue
		}

		for _, key := range keys {
			value := e.Fields[key]
			if value == target || strings.HasPrefix(value, target+":") {
				return true, ""
			}
		}
	}

	return false, "no " + strings.Join(actions, "/") + " decision recorded for " + target
}

// AssertIPVerdict requires an nflog decision for a destination IP, port and
// protocol - the only evidence available when the kernel drops or accepts a
// packet without any hostname context.
func (s *Stack) AssertIPVerdict(t *testing.T, action, ip string, port int, proto string) AgentEvent {
	t.Helper()

	return s.AssertIPVerdictSince(t, LogMark{}, action, ip, port, proto)
}

// AssertIPVerdictSince is AssertIPVerdict scoped to events after mark.
func (s *Stack) AssertIPVerdictSince(
	t *testing.T, mark LogMark, action, ip string, port int, proto string,
) AgentEvent {
	t.Helper()

	fields := map[string]string{
		"destination_ip":   ip,
		"destination_port": strconv.Itoa(port),
	}
	if proto != "" {
		fields["protocol"] = proto
	}

	return s.WaitForAgentEvent(t, mark, EventMatcher{
		Event:  "nflog.event",
		Action: action,
		Fields: fields,
	}, verdictTimeout)
}

// UDPDNSAnswer resolves qname through server over UDP/53 and returns the first
// answer address, or "". Unlike a fire-and-forget datagram this requires a real
// response carrying application data, so it proves a bidirectional round-trip.
func (s *Stack) UDPDNSAnswer(t *testing.T, server, qname string) string {
	t.Helper()

	res := s.ExecTester(t, "timeout", "6", "nslookup", qname, server)

	// busybox prints the server it queried as "Address:<tab>host:port" before the
	// answer section, so only read addresses that follow a "Name:" line.
	seenName := false

	for line := range strings.SplitSeq(res.Output, "\n") {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "Name:"):
			seenName = true
		case seenName && strings.HasPrefix(line, "Address:"):
			return strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
		}
	}

	return ""
}

// AssertUDPDNSAnswer requires a real, non-sinkhole answer over UDP/53.
func (s *Stack) AssertUDPDNSAnswer(t *testing.T, server, qname string) string {
	t.Helper()

	addr := s.UDPDNSAnswer(t, server, qname)
	if addr == "" || addr == "0.0.0.0" || addr == "::" {
		t.Fatalf("no UDP/53 answer for %s from %s (got %q)", qname, server, addr)
	}

	return addr
}

// AssertUDPDNSSinkholed requires the round-trip to succeed but return the
// sinkhole address, proving the proxy answered instead of the named server.
func (s *Stack) AssertUDPDNSSinkholed(t *testing.T, server, qname string) {
	t.Helper()

	addr := s.UDPDNSAnswer(t, server, qname)
	if addr != "0.0.0.0" && addr != "::" {
		t.Fatalf("expected %s sinkholed via %s, got %q", qname, server, addr)
	}
}

// AssertUDPDNSUnreachable requires no answer at all: UDP/53 egress was denied.
func (s *Stack) AssertUDPDNSUnreachable(t *testing.T, server, qname string) {
	t.Helper()

	addr := s.UDPDNSAnswer(t, server, qname)
	if addr != "" {
		t.Fatalf("UDP/53 to %s should be denied but resolved %s to %s", server, qname, addr)
	}
}

// UDPProbe fires datagrams at ip:port. Fire-and-forget, so pair it with
// AssertIPVerdict to read the kernel's decision.
func (s *Stack) UDPProbe(t *testing.T, ip string, port int) {
	t.Helper()

	s.ExecTester(t, "sh", "-lc",
		"for i in 1 2 3; do echo probe | nc -u -w1 "+ip+" "+strconv.Itoa(port)+" >/dev/null 2>&1 || true; done")
}
