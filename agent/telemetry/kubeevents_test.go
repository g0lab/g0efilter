//nolint:testpackage // exercises the unexported Shipper fan-out
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/kubeevents"
	"github.com/g0lab/g0efilter/agent/metrics"
	"github.com/g0lab/g0efilter/shared/actions"
)

type recordedEvent struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

var errInvalidDomain = errors.New("invalid domain")

// eventSink stands in for the Kubernetes API server.
type eventSink struct {
	server *httptest.Server

	mu     sync.Mutex
	events []recordedEvent
}

func newEventSink(t *testing.T) *eventSink {
	t.Helper()

	sink := &eventSink{} //nolint:exhaustruct // fields accumulate per request

	sink.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read event: %v", err)

			return
		}

		var event recordedEvent

		err = json.Unmarshal(body, &event)
		if err != nil {
			t.Errorf("decode event: %v", err)

			return
		}

		sink.mu.Lock()
		sink.events = append(sink.events, event)
		sink.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
	}))

	t.Cleanup(sink.server.Close)

	return sink
}

func (s *eventSink) recorded() []recordedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]recordedEvent(nil), s.events...)
}

func newShipperWithSink(sink *eventSink) *Shipper {
	//nolint:exhaustruct // only the Kubernetes Events sink is under test
	return &Shipper{
		kubeevent: kubeevents.New(kubeevents.Config{
			Client:    sink.server.Client(),
			Endpoint:  sink.server.URL,
			Namespace: "apps",
			Pod:       "demo-abc123",
			Max:       10,
		}),
	}
}

func TestShipperRecordsKubernetesEventsForDenials(t *testing.T) {
	t.Parallel()

	sink := newEventSink(t)
	shipper := newShipperWithSink(sink)

	shipper.Handle(context.Background(), time.Now(), "https.blocked", map[string]any{
		actions.KeyAlert:   true,
		"action":           "BLOCKED",
		keyComponent:       "https",
		"https":            "github.com",
		"destination_ip":   "4.237.22.38",
		keyDestinationPort: "443",
		"reason":           "not-allowlisted",
		"source_ip":        "10.42.0.7",
	})

	shipper.kubeevent.Close()

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}

	if events[0].Type != "Warning" || events[0].Reason != "EgressBlocked" {
		t.Errorf("event type/reason = %q/%q", events[0].Type, events[0].Reason)
	}

	// The message is what shows up in `kubectl describe pod`, so it has to name the
	// destination and why it was refused.
	for _, want := range []string{"github.com", "not-allowlisted"} {
		if !strings.Contains(events[0].Message, want) {
			t.Errorf("message %q omits %q", events[0].Message, want)
		}
	}
}

// Allowed traffic must never reach the Events API: it would be pure noise and
// would blow through the per-pod cap.
func TestShipperIgnoresNonDenials(t *testing.T) {
	t.Parallel()

	sink := newEventSink(t)
	shipper := newShipperWithSink(sink)

	shipper.Handle(context.Background(), time.Now(), "https.allowed", map[string]any{
		"action":     "ALLOWED",
		keyComponent: "https",
		"https":      "example.com",
	})

	shipper.kubeevent.Close()

	if got := len(sink.recorded()); got != 0 {
		t.Errorf("recorded %d events for allowed traffic, want 0", got)
	}
}

func TestShipperRecordsPolicyErrors(t *testing.T) {
	t.Parallel()

	sink := newEventSink(t)
	shipper := newShipperWithSink(sink)

	shipper.RecordPolicyError(context.Background(), errInvalidDomain)
	shipper.kubeevent.Close()

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}

	if events[0].Type != "Warning" || events[0].Reason != "PolicyReloadFailed" {
		t.Errorf("event type/reason = %q/%q", events[0].Type, events[0].Reason)
	}

	if !strings.Contains(events[0].Message, "invalid domain") {
		t.Errorf("message %q omits the policy error", events[0].Message)
	}
}

func TestBlockReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{name: "explicit reason", attrs: map[string]any{"reason": "not-allowlisted"}, want: "not-allowlisted"},
		{name: "note fallback", attrs: map[string]any{"note": "sinkholed"}, want: "sinkholed"},
		{name: "reason wins over note", attrs: map[string]any{"reason": "a", "note": "b"}, want: "a"},
		{name: "generic default", attrs: map[string]any{}, want: "blocked by policy"},
		{name: "empty reason falls through", attrs: map[string]any{"reason": "", "note": "b"}, want: "b"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := blockReason(tc.attrs); got != tc.want {
				t.Errorf("blockReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestShipperCountsVerdicts(t *testing.T) {
	t.Parallel()

	registry := metrics.New()

	//nolint:exhaustruct // only the metrics sink is under test
	shipper := &Shipper{metrics: registry}

	shipper.Handle(context.Background(), time.Now(), "https.allowed", map[string]any{
		"action":     "ALLOWED",
		keyComponent: "https",
		"https":      "example.com",
	})

	shipper.Handle(context.Background(), time.Now(), "https.blocked", map[string]any{
		actions.KeyAlert: true,
		"action":         "BLOCKED",
		keyComponent:     "https",
		"https":          "github.com",
		"reason":         "not-allowlisted",
	})

	var out strings.Builder

	err := registry.Render(&out)
	if err != nil {
		t.Fatalf("render metrics: %v", err)
	}

	for _, want := range []string{
		`g0efilter_connections_total{component="https",action="ALLOWED"} 1`,
		`g0efilter_connections_total{component="https",action="BLOCKED"} 1`,
		// Only denials get a reason, so an allowed connection must not appear here.
		`g0efilter_denials_total{component="https",reason="not-allowlisted"} 1`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	if strings.Contains(out.String(), `g0efilter_denials_total{component="https",reason="blocked by policy"}`) {
		t.Errorf("an allowed connection was counted as a denial:\n%s", out.String())
	}
}

// A Shipper with no sinks configured must not panic on the recording path.
func TestShipperWithoutSinksIsSafe(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // deliberately empty
	shipper := &Shipper{}

	shipper.Handle(context.Background(), time.Now(), "https.blocked", map[string]any{
		actions.KeyAlert: true,
		"action":         "BLOCKED",
		keyComponent:     "https",
	})
}
