//nolint:testpackage // Need access to internal implementation details
package kubeevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type capturedEvent struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"involvedObject"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Type    string `json:"type"`
	Source  struct {
		Component string `json:"component"`
	} `json:"source"`
}

type apiServer struct {
	server *httptest.Server

	mu     sync.Mutex
	events []capturedEvent
	tokens []string
	status int
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()

	api := &apiServer{status: http.StatusCreated} //nolint:exhaustruct // remaining fields accumulate per request

	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read event body: %v", err)

			return
		}

		var event capturedEvent

		err = json.Unmarshal(body, &event)
		if err != nil {
			t.Errorf("decode event body: %v", err)

			return
		}

		api.mu.Lock()
		api.events = append(api.events, event)
		api.tokens = append(api.tokens, r.Header.Get("Authorization"))
		status := api.status
		api.mu.Unlock()

		w.WriteHeader(status)
	}))

	t.Cleanup(api.server.Close)

	return api
}

func (a *apiServer) recorded() []capturedEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]capturedEvent(nil), a.events...)
}

func (a *apiServer) failWith(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.status = status
}

func newRecorder(t *testing.T, api *apiServer, maxEvents int) *Recorder {
	t.Helper()

	return New(Config{
		Client:    api.server.Client(),
		Endpoint:  api.server.URL,
		Token:     "test-token",
		Namespace: "apps",
		Pod:       "demo-abc123",
		UID:       "pod-uid-1",
		Max:       maxEvents,
	})
}

func denial(destination string) Denial {
	return Denial{
		Component:   "https",
		Destination: destination,
		Reason:      "not-allowlisted",
		SourceIP:    "10.42.0.7",
	}
}

// kubectl describe finds events by involvedObject, so these have to be right or
// the event exists but is invisible where people look for it.
func assertInvolvedPod(t *testing.T, got capturedEvent) {
	t.Helper()

	if got.InvolvedObject.Kind != "Pod" || got.InvolvedObject.Name != "demo-abc123" {
		t.Errorf("involvedObject = %+v, want the demo-abc123 Pod", got.InvolvedObject)
	}

	if got.InvolvedObject.Namespace != "apps" || got.InvolvedObject.UID != "pod-uid-1" {
		t.Errorf("involvedObject namespace/uid = %+v", got.InvolvedObject)
	}
}

func assertEventMetadata(t *testing.T, got capturedEvent) {
	t.Helper()

	if got.Type != "Warning" || got.Reason != reasonBlocked {
		t.Errorf("type/reason = %q/%q, want Warning/%s", got.Type, got.Reason, reasonBlocked)
	}

	if got.Source.Component != sourceComponent {
		t.Errorf("source.component = %q, want %q", got.Source.Component, sourceComponent)
	}

	// The API server rejects a create without a name, and reuses would collide.
	if !strings.HasPrefix(got.Metadata.Name, "demo-abc123.") {
		t.Errorf("event name %q is not derived from the pod name", got.Metadata.Name)
	}

	if got.Metadata.Namespace != "apps" {
		t.Errorf("event namespace = %q, want apps", got.Metadata.Namespace)
	}
}

func TestRecordBlockPostsAnEventOnThePod(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	rec := newRecorder(t, api, 10)

	rec.RecordBlock(context.Background(), denial("github.com"))
	rec.Close()

	events := api.recorded()
	if len(events) != 1 {
		t.Fatalf("posted %d events, want 1", len(events))
	}

	assertInvolvedPod(t, events[0])
	assertEventMetadata(t, events[0])

	for _, want := range []string{"github.com", "https", "not-allowlisted"} {
		if !strings.Contains(events[0].Message, want) {
			t.Errorf("message %q omits %q", events[0].Message, want)
		}
	}
}

func TestRecordBlockSendsTheServiceAccountToken(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	rec := newRecorder(t, api, 10)

	rec.RecordBlock(context.Background(), denial("github.com"))
	rec.Close()

	api.mu.Lock()
	defer api.mu.Unlock()

	if len(api.tokens) != 1 || api.tokens[0] != "Bearer test-token" {
		t.Errorf("Authorization headers = %v", api.tokens)
	}
}

// A scanner hitting hundreds of destinations must not flood the pod's events or
// the API server.
func TestRecordBlockDeduplicatesAndCaps(t *testing.T) {
	t.Parallel()

	t.Run("repeat denials post once", func(t *testing.T) {
		t.Parallel()

		api := newAPIServer(t)
		rec := newRecorder(t, api, 10)

		for range 5 {
			rec.RecordBlock(context.Background(), denial("github.com"))
		}

		rec.Close()

		if got := len(api.recorded()); got != 1 {
			t.Errorf("posted %d events for one destination, want 1", got)
		}
	})

	t.Run("distinct denials stop at the cap", func(t *testing.T) {
		t.Parallel()

		api := newAPIServer(t)
		rec := newRecorder(t, api, 3)

		for _, host := range []string{"a.example", "b.example", "c.example", "d.example", "e.example"} {
			rec.RecordBlock(context.Background(), denial(host))
		}

		rec.Close()

		if got := len(api.recorded()); got != 3 {
			t.Errorf("posted %d events, want the cap of 3", got)
		}
	})

	t.Run("a different reason for the same host is its own event", func(t *testing.T) {
		t.Parallel()

		api := newAPIServer(t)
		rec := newRecorder(t, api, 10)

		first := denial("github.com")
		second := denial("github.com")
		second.Reason = "port-not-allowed"

		rec.RecordBlock(context.Background(), first)
		rec.RecordBlock(context.Background(), second)
		rec.Close()

		if got := len(api.recorded()); got != 2 {
			t.Errorf("posted %d events, want 2 distinct reasons", got)
		}
	})
}

// Missing RBAC is the expected failure, and it must not take filtering down.
func TestRecordBlockSurvivesRejection(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	api.failWith(http.StatusForbidden)

	rec := newRecorder(t, api, 10)

	for _, host := range []string{"a.example", "b.example"} {
		rec.RecordBlock(context.Background(), denial(host))
	}

	rec.Close()

	if !rec.failedOnce {
		t.Error("a rejected post was not recorded as a failure")
	}
}

func TestNilRecorderIsANoOp(t *testing.T) {
	t.Parallel()

	var rec *Recorder

	rec.RecordBlock(context.Background(), denial("github.com"))
	rec.Close()
}

func TestNewAppliesTheDefaultCap(t *testing.T) {
	t.Parallel()

	if got := New(Config{}).max; got != defaultMaxEvents { //nolint:exhaustruct // defaults are the subject
		t.Errorf("max = %d, want %d", got, defaultMaxEvents)
	}
}

// Not parallel: t.Setenv cannot be used alongside t.Parallel.
func TestNewFromEnvStaysDisabledOutsideKubernetes(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"unset":                 {},
		"explicitly off":        {"KUBE_EVENTS": "false"},
		"on but not in-cluster": {"KUBE_EVENTS": "true"},
	} {
		t.Run(name, func(t *testing.T) {
			for key, value := range env {
				t.Setenv(key, value)
			}

			// Guarantee the in-cluster markers are absent regardless of the host.
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			t.Setenv("KUBERNETES_SERVICE_PORT", "")

			if rec := NewFromEnv(discardLogger()); rec != nil {
				t.Error("a Recorder was built outside a cluster")
			}
		})
	}
}

func TestMaxEventsFromEnv(t *testing.T) {
	tests := map[string]int{
		"":         defaultMaxEvents,
		"25":       25,
		"0":        0,
		"-3":       defaultMaxEvents,
		"nonsense": defaultMaxEvents,
	}

	for raw, want := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("KUBE_EVENTS_MAX", raw)

			if got := maxEvents(); got != want {
				t.Errorf("maxEvents(%q) = %d, want %d", raw, got, want)
			}
		})
	}
}

func TestPodNameFallsBackToHostname(t *testing.T) {
	t.Setenv("POD_NAME", "")
	t.Setenv("HOSTNAME", "demo-xyz789")

	if got := podName(); got != "demo-xyz789" {
		t.Errorf("podName() = %q, want the hostname", got)
	}

	t.Setenv("POD_NAME", "explicit-pod")

	if got := podName(); got != "explicit-pod" {
		t.Errorf("podName() = %q, want POD_NAME to win", got)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

var errTestPolicy = errors.New("invalid domain")

// A rejected policy leaves the pod enforcing the previous one. Without an Event
// that is invisible to anyone reading `kubectl describe pod`.
func TestRecordPolicyErrorPostsAWarning(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	rec := newRecorder(t, api, 10)

	rec.RecordPolicyError(context.Background(), fmt.Errorf("%w: %q", errTestPolicy, "*"))
	rec.Close()

	events := api.recorded()
	if len(events) != 1 {
		t.Fatalf("posted %d events, want 1", len(events))
	}

	assertInvolvedPod(t, events[0])

	if events[0].Reason != reasonPolicy || events[0].Type != "Warning" {
		t.Errorf("reason/type = %q/%q, want %s/Warning", events[0].Reason, events[0].Type, reasonPolicy)
	}

	for _, want := range []string{"kept the previous policy", `invalid domain: "*"`} {
		if !strings.Contains(events[0].Message, want) {
			t.Errorf("message %q omits %q", events[0].Message, want)
		}
	}
}

// A reload that keeps failing must not post an Event every five seconds.
func TestRecordPolicyErrorDeduplicates(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	rec := newRecorder(t, api, 10)

	cause := errTestPolicy
	for range 5 {
		rec.RecordPolicyError(context.Background(), cause)
	}

	rec.RecordPolicyError(context.Background(), nil)
	rec.Close()

	if events := api.recorded(); len(events) != 1 {
		t.Errorf("posted %d events, want 1", len(events))
	}
}

// A policy error and a denial are separate events, not one deduplicated against
// the other.
func TestPolicyErrorsAndDenialsDoNotShareAKey(t *testing.T) {
	t.Parallel()

	api := newAPIServer(t)
	rec := newRecorder(t, api, 10)

	rec.RecordBlock(context.Background(), denial("github.com"))
	rec.RecordPolicyError(context.Background(), fmt.Errorf("%w: github.com", errTestPolicy))
	rec.Close()

	if events := api.recorded(); len(events) != 2 {
		t.Errorf("posted %d events, want 2", len(events))
	}
}
