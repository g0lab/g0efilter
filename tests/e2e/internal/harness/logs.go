package harness

import (
	"strings"
	"testing"
	"time"
)

// AgentEvent is one parsed line of the agent's structured console log.
type AgentEvent struct {
	Raw    string
	Level  string
	Event  string
	Fields map[string]string
}

// Field returns a log field, empty when absent.
func (e AgentEvent) Field(name string) string { return e.Fields[name] }

// Action is the policy decision the event recorded.
func (e AgentEvent) Action() string { return e.Fields["action"] }

// LogMark is a position in a container's log. Assertions take a mark before the
// traffic they trigger, so they can only match decisions caused by that traffic
// rather than anything an earlier phase happened to leave behind.
type LogMark struct{ LineCount int }

// AgentLogMark records the agent's current log position.
func (s *Stack) AgentLogMark(t *testing.T) LogMark {
	t.Helper()

	return LogMark{LineCount: len(containerLogLines(t, s.Agent))}
}

// AgentEventsSince parses the agent log lines written after mark.
func (s *Stack) AgentEventsSince(t *testing.T, mark LogMark) []AgentEvent {
	t.Helper()

	lines := containerLogLines(t, s.Agent)
	if mark.LineCount >= len(lines) {
		return nil
	}

	return parseAgentEvents(lines[mark.LineCount:])
}

// EventMatcher selects agent events. Zero-valued fields are ignored.
type EventMatcher struct {
	// Event matches the event name, e.g. "dns.blocked". A trailing "*" matches any
	// event with that prefix, and "*" alone matches any event.
	Event string
	// Action matches ALLOWED, BLOCKED or AUDIT.
	Action string
	// Fields must all be present with the given values.
	Fields map[string]string
	// Alert requires the alert flag to have this value when set.
	Alert *bool
}

// Matches reports whether an event satisfies the matcher.
func (m EventMatcher) Matches(e AgentEvent) bool {
	if m.Event != "" && !matchEventName(e.Event, m.Event) {
		return false
	}

	if m.Action != "" && e.Action() != m.Action {
		return false
	}

	for k, v := range m.Fields {
		if e.Fields[k] != v {
			return false
		}
	}

	if m.Alert != nil {
		want := "false"
		if *m.Alert {
			want = "true"
		}

		if e.Fields["alert"] != want {
			return false
		}
	}

	return true
}

func matchEventName(name, pattern string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	default:
		return name == pattern
	}
}

// WaitForAgentEvent blocks until an event written after mark matches, and
// returns it. It fails the test with the matcher and the events it did see, so a
// failure explains itself without a separate log dump.
func (s *Stack) WaitForAgentEvent(
	t *testing.T, mark LogMark, m EventMatcher, timeout time.Duration,
) AgentEvent {
	t.Helper()

	var found AgentEvent

	seen := 0

	Eventually(t, timeout, 500*time.Millisecond, func() (bool, string) {
		events := s.AgentEventsSince(t, mark)
		seen = len(events)

		for _, e := range events {
			if m.Matches(e) {
				found = e

				return true, ""
			}
		}

		return false, describeMiss(m, events)
	})

	t.Logf("matched %+v after scanning %d events", m, seen)

	return found
}

// AgentEventCountSince counts matching events written after mark.
func (s *Stack) AgentEventCountSince(t *testing.T, mark LogMark, m EventMatcher) int {
	t.Helper()

	n := 0

	for _, e := range s.AgentEventsSince(t, mark) {
		if m.Matches(e) {
			n++
		}
	}

	return n
}

// AssertNoAgentEvent fails if a matching event appears within the settle window.
// Proving absence needs a wait: the event it is guarding against would arrive
// slightly after the traffic that would have caused it.
func (s *Stack) AssertNoAgentEvent(t *testing.T, mark LogMark, m EventMatcher, settle time.Duration) {
	t.Helper()

	time.Sleep(settle)

	for _, e := range s.AgentEventsSince(t, mark) {
		if m.Matches(e) {
			t.Fatalf("unexpected event %+v: %s", m, e.Raw)
		}
	}
}

func describeMiss(m EventMatcher, events []AgentEvent) string {
	const sample = 3

	names := make([]string, 0, sample)

	for i := len(events) - 1; i >= 0 && len(names) < sample; i-- {
		names = append(names, events[i].Event+"("+events[i].Action()+")")
	}

	return "no event matched " + describeMatcher(m) + "; last events: " + strings.Join(names, ", ")
}

func describeMatcher(m EventMatcher) string {
	parts := make([]string, 0, len(m.Fields)+2)

	if m.Event != "" {
		parts = append(parts, "event="+m.Event)
	}

	if m.Action != "" {
		parts = append(parts, "action="+m.Action)
	}

	for k, v := range m.Fields {
		parts = append(parts, k+"="+v)
	}

	return "{" + strings.Join(parts, " ") + "}"
}

func parseAgentEvents(lines []string) []AgentEvent {
	events := make([]AgentEvent, 0, len(lines))

	for _, line := range lines {
		e, ok := parseAgentEvent(line)
		if ok {
			events = append(events, e)
		}
	}

	return events
}

// parseAgentEvent reads one console line:
//
//	2026-07-26T09:14:24Z INF dns.allowed action=ALLOWED qname=github.com
func parseAgentEvent(line string) (AgentEvent, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return AgentEvent{}, false
	}

	level := fields[1]
	switch level {
	case "TRC", "DBG", "INF", "WRN", "ERR", "FTL", "PNC":
	default:
		return AgentEvent{}, false
	}

	event := AgentEvent{
		Raw:    line,
		Level:  level,
		Event:  fields[2],
		Fields: map[string]string{},
	}

	for _, kv := range fields[3:] {
		key, value, ok := strings.Cut(kv, "=")
		if ok {
			event.Fields[key] = strings.Trim(value, `"`)
		}
	}

	return event, true
}

// Eventually polls until check passes, failing with the last explanation.
func Eventually(t *testing.T, timeout, interval time.Duration, check func() (bool, string)) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	var detail string

	for {
		ok, d := check()
		if ok {
			return
		}

		detail = d

		if time.Now().After(deadline) {
			break
		}

		time.Sleep(interval)
	}

	t.Fatalf("condition not satisfied within %s: %s", timeout, detail)
}
