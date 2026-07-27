package harness

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventMatcherWildcard(t *testing.T) {
	t.Parallel()

	event := AgentEvent{
		Event:  "dns.blocked",
		Fields: map[string]string{"action": "BLOCKED"},
	}

	if !(EventMatcher{Event: "*", Action: "BLOCKED"}).Matches(event) {
		t.Error("* did not match an arbitrary event name")
	}

	if !(EventMatcher{Event: "dns.*"}).Matches(event) {
		t.Error("trailing wildcard did not match the event prefix")
	}

	if (EventMatcher{Event: "https.*"}).Matches(event) {
		t.Error("unrelated event prefix matched")
	}
}

func TestParseCurlResultAndTarget(t *testing.T) {
	t.Parallel()

	res := parseCurlResult("https://[2001:db8::1]:443/path", ExecResult{
		ExitCode: 0,
		Output:   "noise\nG0E_RESULT http=204 remote_ip=2001:db8::1 total=0.125\n",
	})

	if res.HTTPCode != 204 || res.RemoteIP != "2001:db8::1" || res.TimeTotal != 125*time.Millisecond {
		t.Errorf("parseCurlResult = %+v", res)
	}

	if got := Target(res.URL); got != "2001:db8::1" {
		t.Errorf("Target(%q) = %q", res.URL, got)
	}
}

func TestDecodeNFTSetElement(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"elem":{"val":{"concat":["1.1.1.1","tcp",443]},"timeout":60000}}`)
	got := decodeSetElement(raw)

	if got.Value != "1.1.1.1 . tcp . 443" || got.Timeout != 60000 {
		t.Errorf("decodeSetElement = %+v", got)
	}
}

func TestStripDockerStreamHeaders(t *testing.T) {
	t.Parallel()

	frame := func(stream byte, payload string) []byte {
		frameBytes := make([]byte, 8+len(payload))
		frameBytes[0] = stream
		binary.BigEndian.PutUint32(frameBytes[4:], uint32(len(payload))) //nolint:gosec // tiny test fixture
		copy(frameBytes[8:], payload)

		return frameBytes
	}

	raw := append(frame(1, "stdout\n"), frame(2, "stderr\n")...)
	if got := stripDockerStreamHeaders(raw); got != "stdout\nstderr\n" {
		t.Errorf("stripDockerStreamHeaders = %q", got)
	}
}

func TestLastJSONLine(t *testing.T) {
	t.Parallel()

	got := lastJSONLine("diagnostic\n{\"first\":1}\nmore\n{\"last\":2}\n")
	if got != `{"last":2}` {
		t.Errorf("lastJSONLine = %q", got)
	}
}

func TestFailureLogSelection(t *testing.T) {
	t.Parallel()

	lines := []string{
		"INF startup",
		"DBG lookup err=expected-miss",
		"WRN dns.blocked",
		"level=error msg=ship_failed",
		"INF shutdown",
	}

	problems := filterProblems(lines)
	want := []string{"level=error msg=ship_failed"}

	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("filterProblems = %q, want %q", problems, want)
	}

	recent := withoutLines(lines, problems)
	if strings.Contains(strings.Join(recent, "\n"), "ship_failed") {
		t.Errorf("withoutLines retained a line already shown in the problem summary: %q", recent)
	}
}

func TestCurlTimeoutSecondsRoundsUp(t *testing.T) {
	t.Parallel()

	tests := map[time.Duration]int{
		0:                       1,
		time.Millisecond:        1,
		1500 * time.Millisecond: 2,
		5 * time.Second:         5,
	}

	for timeout, want := range tests {
		if got := curlTimeoutSeconds(timeout); got != want {
			t.Errorf("curlTimeoutSeconds(%s) = %d, want %d", timeout, got, want)
		}
	}
}
