// Package metrics exposes g0efilter counters in the Prometheus text format.
//
// Label values come from a fixed vocabulary (component, action, reason) rather than
// from traffic, and the number of distinct series is capped: a scanner reaching
// thousands of destinations must not be able to grow the series count without bound.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// maxSeries bounds each counter's total exposed series, including the "other" series
// that overflowing increments are folded into so totals stay correct.
const maxSeries = 200

const overflowLabel = "other"

type series struct {
	labels map[string]string
	value  uint64
}

// counter is a labeled monotonic counter with a bounded series count.
type counter struct {
	name string
	help string
	keys []string

	series map[string]*series
}

func newCounter(name, help string, keys ...string) *counter {
	return &counter{name: name, help: help, keys: keys, series: make(map[string]*series)}
}

func (c *counter) add(values []string) {
	key := strings.Join(values, "\x00")

	if existing, ok := c.series[key]; ok {
		existing.value++

		return
	}

	// The last slot is reserved for the overflow series itself, so the total number of
	// exposed series never exceeds maxSeries.
	if len(c.series) >= maxSeries-1 {
		values = overflow(len(c.keys))
		key = strings.Join(values, "\x00")

		if existing, ok := c.series[key]; ok {
			existing.value++

			return
		}
	}

	labels := make(map[string]string, len(c.keys))
	for i, name := range c.keys {
		labels[name] = values[i]
	}

	c.series[key] = &series{labels: labels, value: 1}
}

func overflow(n int) []string {
	values := make([]string, n)
	for i := range values {
		values[i] = overflowLabel
	}

	return values
}

func (c *counter) writeTo(w io.Writer) error {
	_, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	if err != nil {
		return fmt.Errorf("write %s header: %w", c.name, err)
	}

	keys := make([]string, 0, len(c.series))
	for key := range c.series {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		s := c.series[key]

		_, err = fmt.Fprintf(w, "%s{%s} %d\n", c.name, renderLabels(c.keys, s.labels), s.value)
		if err != nil {
			return fmt.Errorf("write %s series: %w", c.name, err)
		}
	}

	return nil
}

func renderLabels(order []string, labels map[string]string) string {
	parts := make([]string, 0, len(order))

	for _, name := range order {
		parts = append(parts, fmt.Sprintf("%s=%q", name, escapeLabel(labels[name])))
	}

	return strings.Join(parts, ",")
}

// escapeLabel keeps a label value from breaking the exposition format. Values are
// internal today, but a policy reason reaching a metric must never corrupt a scrape.
func escapeLabel(value string) string {
	if value == "" {
		return "unknown"
	}

	replaced := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", " ").Replace(value)

	return strings.TrimSpace(replaced)
}

// Metrics holds every counter g0efilter exposes.
type Metrics struct {
	mu sync.Mutex

	connections *counter
	denials     *counter
	reloads     *counter
	panics      *counter
}

// New builds an empty registry.
func New() *Metrics {
	return &Metrics{
		connections: newCounter("g0efilter_connections_total",
			"Connections evaluated, by filter component and verdict.", "component", "action"),
		denials: newCounter("g0efilter_denials_total",
			"Denied connections, by filter component and reason.", "component", "reason"),
		reloads: newCounter("g0efilter_policy_reloads_total",
			"Policy reload attempts, by result.", "result"),
		panics: newCounter("g0efilter_panics_total",
			"Panics contained without terminating the process, by component.", "component"),
	}
}

// RecordConnection counts one evaluated connection. A nil Metrics is a no-op.
func (m *Metrics) RecordConnection(component, action string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.connections.add([]string{component, action})
}

// RecordDenial counts one denial alongside its reason.
func (m *Metrics) RecordDenial(component, reason string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.denials.add([]string{component, reason})
}

// RecordReload counts a policy reload attempt.
func (m *Metrics) RecordReload(result string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.reloads.add([]string{result})
}

// RecordPanic counts one contained panic.
func (m *Metrics) RecordPanic(component string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.panics.add([]string{component})
}

// Render writes every counter in the Prometheus text format.
func (m *Metrics) Render(w io.Writer) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range []*counter{m.connections, m.denials, m.reloads, m.panics} {
		err := c.writeTo(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// Handler serves the registry at /metrics.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		err := m.Render(w)
		if err != nil {
			http.Error(w, "failed to render metrics", http.StatusInternalServerError)
		}
	})
}
