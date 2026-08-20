//nolint:testpackage // Need access to internal implementation details
package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, m *Metrics) string {
	t.Helper()

	var b strings.Builder

	err := m.Render(&b)
	if err != nil {
		t.Fatalf("render metrics: %v", err)
	}

	return b.String()
}

func TestRecordConnectionCountsByComponentAndVerdict(t *testing.T) {
	t.Parallel()

	m := New()

	m.RecordConnection("https", "ALLOWED")
	m.RecordConnection("https", "ALLOWED")
	m.RecordConnection("https", "BLOCKED")
	m.RecordConnection("dns", "ALLOWED")

	out := render(t, m)

	for _, want := range []string{
		`g0efilter_connections_total{component="https",action="ALLOWED"} 2`,
		`g0efilter_connections_total{component="https",action="BLOCKED"} 1`,
		`g0efilter_connections_total{component="dns",action="ALLOWED"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestExpositionFormatIsWellFormed(t *testing.T) {
	t.Parallel()

	m := New()
	m.RecordDenial("https", "not-allowlisted")

	out := render(t, m)

	// Prometheus requires HELP and TYPE before the samples of each metric family.
	for _, want := range []string{
		"# HELP g0efilter_connections_total ",
		"# TYPE g0efilter_connections_total counter",
		"# HELP g0efilter_denials_total ",
		"# TYPE g0efilter_denials_total counter",
		"# TYPE g0efilter_policy_reloads_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	if !strings.HasSuffix(out, "\n") {
		t.Error("exposition output does not end with a newline")
	}
}

// Output has to be stable so a diff-based check or a scrape does not churn.
func TestOutputIsDeterministic(t *testing.T) {
	t.Parallel()

	m := New()

	for _, component := range []string{"https", "dns", "http", "filter"} {
		m.RecordConnection(component, "BLOCKED")
		m.RecordConnection(component, "ALLOWED")
	}

	first := render(t, m)

	for range 5 {
		if got := render(t, m); got != first {
			t.Fatalf("render is not deterministic:\n%s\n---\n%s", first, got)
		}
	}
}

// A scanner reaching thousands of distinct destinations must not grow the series
// count without bound, and the totals must still add up.
func TestSeriesCountIsCapped(t *testing.T) {
	t.Parallel()

	m := New()

	const denials = maxSeries * 3

	for i := range denials {
		m.RecordDenial("https", fmt.Sprintf("reason-%d", i))
	}

	out := render(t, m)

	var (
		lines int
		total uint64
	)

	for line := range strings.SplitSeq(out, "\n") {
		if !strings.HasPrefix(line, "g0efilter_denials_total{") {
			continue
		}

		lines++

		var value uint64

		_, field, _ := strings.CutLast(line, " ")

		_, err := fmt.Sscanf(field, "%d", &value)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}

		total += value
	}

	if lines > maxSeries {
		t.Errorf("%d series exposed, want at most %d", lines, maxSeries)
	}

	if total != denials {
		t.Errorf("counted %d denials, want %d", total, denials)
	}

	if !strings.Contains(out, `reason="other"`) {
		t.Errorf("overflowing denials were not folded into an other series:\n%s", out)
	}
}

// Once capped, an already-known series must keep incrementing normally.
func TestKnownSeriesStillIncrementsAfterTheCap(t *testing.T) {
	t.Parallel()

	m := New()

	m.RecordDenial("https", "not-allowlisted")

	for i := range maxSeries * 2 {
		m.RecordDenial("https", fmt.Sprintf("reason-%d", i))
	}

	m.RecordDenial("https", "not-allowlisted")

	out := render(t, m)

	want := `g0efilter_denials_total{component="https",reason="not-allowlisted"} 2`
	if !strings.Contains(out, want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}
}

func TestEscapeLabel(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                "unknown",
		"not-allowlisted": "not-allowlisted",
		`quo"te`:          `quo\"te`,
		`back\slash`:      `back\\slash`,
		"new\nline":       "new line",
		"  padded  ":      "padded",
	}

	for input, want := range tests {
		if got := escapeLabel(input); got != want {
			t.Errorf("escapeLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

// A reason containing a quote would otherwise produce an unparseable scrape.
func TestHostileLabelDoesNotBreakTheFormat(t *testing.T) {
	t.Parallel()

	m := New()
	m.RecordDenial("https", `evil" } fake_metric 1`)

	out := render(t, m)

	if strings.Contains(out, `fake_metric 1`) && !strings.Contains(out, `\"`) {
		t.Errorf("label value escaped the exposition format:\n%s", out)
	}

	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.HasPrefix(line, "g0efilter_") {
			t.Errorf("unexpected exposition line %q", line)
		}
	}
}

func TestNilMetricsIsANoOp(t *testing.T) {
	t.Parallel()

	var m *Metrics

	m.RecordConnection("https", "ALLOWED")
	m.RecordDenial("https", "not-allowlisted")
	m.RecordReload("success")

	err := m.Render(&strings.Builder{})
	if err != nil {
		t.Errorf("Render on a nil registry: %v", err)
	}
}

func TestHandlerServesTheRegistry(t *testing.T) {
	t.Parallel()

	m := New()
	m.RecordConnection("https", "BLOCKED")

	server := httptest.NewServer(m.Handler())
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("build scrape request: %v", err)
	}

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
}

// The recording path runs from every filter goroutine.
func TestConcurrentRecordingIsSafe(t *testing.T) {
	t.Parallel()

	m := New()

	var wg sync.WaitGroup

	for i := range 50 {
		wg.Go(func() {
			for range 20 {
				m.RecordConnection("https", "ALLOWED")
				m.RecordDenial("https", fmt.Sprintf("reason-%d", i%5))
			}
		})
	}

	wg.Wait()

	out := render(t, m)

	want := `g0efilter_connections_total{component="https",action="ALLOWED"} 1000`
	if !strings.Contains(out, want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}
}

func TestRecordReloadCountsByResult(t *testing.T) {
	t.Parallel()

	m := New()

	m.RecordReload("success")
	m.RecordReload("success")
	m.RecordReload("failure")

	out := render(t, m)

	for _, want := range []string{
		`g0efilter_policy_reloads_total{result="success"} 2`,
		`g0efilter_policy_reloads_total{result="failure"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRecordPanicCountsByComponent(t *testing.T) {
	t.Parallel()

	m := New()

	m.RecordPanic("dns")
	m.RecordPanic("dns")
	m.RecordPanic("https")

	out := render(t, m)

	for _, want := range []string{
		`g0efilter_panics_total{component="dns"} 2`,
		`g0efilter_panics_total{component="https"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRecordPanicOnNilRegistry(t *testing.T) {
	t.Parallel()

	var m *Metrics

	m.RecordPanic("dns")
}

func TestPanicsCounterIsAlwaysExposed(t *testing.T) {
	t.Parallel()

	out := render(t, New())

	if !strings.Contains(out, "# TYPE g0efilter_panics_total counter") {
		t.Errorf("the panics counter must be exposed before the first panic:\n%s", out)
	}
}
