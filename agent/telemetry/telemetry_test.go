//nolint:testpackage // exercises unexported poster/ship/payload internals
package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/metrics"
	"github.com/g0lab/g0efilter/agent/recovery"
	"github.com/g0lab/g0efilter/shared/actions"
	"github.com/rs/zerolog"
)

func TestShouldShipToDashboard(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		act  string
		comp string
		want bool
	}{
		{"blocked", actions.ActionBlocked, "https", true},
		{"allowed https", actions.ActionAllowed, "https", true},
		{"audit", actions.ActionAudit, "https", true},
		{"allowed nflog suppressed", actions.ActionAllowed, "nflog", false},
		{"other action", "REDIRECTED", "https", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := shouldShipToDashboard(tc.act, map[string]any{keyComponent: tc.comp})
			if got != tc.want {
				t.Errorf("shouldShipToDashboard(%q, %q) = %v, want %v", tc.act, tc.comp, got, tc.want)
			}
		})
	}
}

func TestShouldAlert(t *testing.T) {
	t.Parallel()

	if !shouldAlert(map[string]any{actions.KeyAlert: true}) {
		t.Error("alert=true should alert")
	}

	if shouldAlert(map[string]any{actions.KeyAlert: false}) {
		t.Error("alert=false should not alert")
	}

	if shouldAlert(map[string]any{}) {
		t.Error("missing alert key should not alert")
	}
}

func TestBuildDashboardPayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	attrs := map[string]any{
		"client_ip": "10.0.0.5", // normalized to source_ip
		"http_host": "evil.example",
	}

	p := buildDashboardPayload("host-1", "v1", now, "flow.decision", actions.ActionBlocked, attrs)

	if p[keyAction] != actions.ActionBlocked {
		t.Errorf("action = %v", p[keyAction])
	}

	if p[keyHostname] != "host-1" {
		t.Errorf("hostname = %v, want host-1", p[keyHostname])
	}

	if p["version"] != "v1" {
		t.Errorf("version = %v, want v1", p["version"])
	}

	if p["source_ip"] != "10.0.0.5" {
		t.Errorf("source_ip = %v (client_ip should normalize)", p["source_ip"])
	}

	if _, mutated := attrs["source_ip"]; mutated {
		t.Error("buildDashboardPayload must not mutate the caller's attrs")
	}
}

func TestBuildDestinationString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"https wins", map[string]any{"https": "a.example", "host": "b.example"}, "a.example"},
		{"qname", map[string]any{"qname": "q.example"}, "q.example"},
		{"ip and port", map[string]any{"destination_ip": "1.2.3.4", keyDestinationPort: "443"}, "1.2.3.4:443"},
		{"ip only", map[string]any{"destination_ip": "1.2.3.4"}, "1.2.3.4"},
		{"unknown", map[string]any{}, "unknown destination"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := buildDestinationString(tc.attrs); got != tc.want {
				t.Errorf("buildDestinationString = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetCanonicalTime(t *testing.T) {
	t.Parallel()

	fallback := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := getCanonicalTime(map[string]any{"time": "explicit"}, fallback); got != "explicit" {
		t.Errorf("explicit time = %q", got)
	}

	if got := getCanonicalTime(map[string]any{}, fallback); got != fallback.Format(time.RFC3339Nano) {
		t.Errorf("fallback time = %q", got)
	}
}

func TestSetAPIAuthHeaders(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	setAPIAuthHeaders(h, "secret")

	if h.Get("X-Api-Key") != "secret" || h.Get("Authorization") != "Bearer secret" {
		t.Errorf("headers not set: %v", h)
	}

	empty := http.Header{}
	setAPIAuthHeaders(empty, "")

	if len(empty) != 0 {
		t.Errorf("empty key should set no headers: %v", empty)
	}
}

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	if !shouldRetry(nil, io.EOF) {
		t.Error("transport error should retry")
	}

	if !shouldRetry(&http.Response{StatusCode: http.StatusServiceUnavailable}, nil) {
		t.Error("5xx should retry")
	}

	if !shouldRetry(&http.Response{StatusCode: http.StatusTooManyRequests}, nil) {
		t.Error("429 should retry")
	}

	if shouldRetry(&http.Response{StatusCode: http.StatusBadRequest}, nil) {
		t.Error("4xx should not retry")
	}
}

func TestAddJitterInRange(t *testing.T) {
	t.Parallel()

	base := time.Second
	for range 50 {
		j := addJitter(base)
		if j < base/2 || j > base {
			t.Fatalf("jitter %v out of [0.5s, 1s]", j)
		}
	}
}

func TestPosterProbe(t *testing.T) {
	t.Parallel()

	var gotKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newPoster(srv.URL, "probe-key", zerolog.Nop(), false)
	defer p.Stop(0)

	err := p.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if gotKey != "probe-key" {
		t.Errorf("probe did not send API key, got %q", gotKey)
	}
}

func TestPosterProbeBadStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newPoster(srv.URL, "", zerolog.Nop(), false)
	defer p.Stop(0)

	err := p.Probe(context.Background())
	if err == nil {
		t.Fatal("expected error on non-2xx probe")
	}
}

func TestNewFromEnvNilWhenUnconfigured(t *testing.T) {
	t.Setenv("DASHBOARD_HOST", "")
	t.Setenv("NOTIFICATION_URLS", "")

	if h, _ := NewFromEnv(context.Background(), io.Discard, slog.LevelInfo, ""); h != nil {
		t.Fatalf("expected nil hook when unconfigured, got %T", h)
	}
}

func TestNewFromEnvShipsBlocked(t *testing.T) {
	got := make(chan map[string]any, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any

		_ = json.NewDecoder(r.Body).Decode(&m)

		if m["msg"] == "_dashboard_probe" {
			// probe: ack and ignore
			w.WriteHeader(http.StatusOK)

			return
		}

		select {
		case got <- m:
		default:
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	t.Setenv("DASHBOARD_HOST", srv.URL)
	t.Setenv("DASHBOARD_START_DELAY", "0")

	hook, _ := NewFromEnv(context.Background(), io.Discard, slog.LevelInfo, "v-test")
	if hook == nil {
		t.Fatal("expected a hook with DASHBOARD_HOST set")
	}

	defer hook.Stop(time.Second)

	hook.Handle(context.Background(), time.Now(), "flow.decision", map[string]any{
		keyAction:   actions.ActionBlocked,
		"http_host": "evil.example",
	})

	select {
	case m := <-got:
		if m[keyAction] != actions.ActionBlocked || m["http_host"] != "evil.example" {
			t.Fatalf("unexpected shipped payload: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for shipped payload")
	}
}

//nolint:exhaustruct // only the metrics registry participates in this path
func TestHandleCountsContainedPanics(t *testing.T) {
	t.Parallel()

	registry := metrics.New()
	shipper := &Shipper{metrics: registry}

	shipper.Handle(t.Context(), time.Now(), recovery.PanicMessage, map[string]any{
		keyComponent: "dns",
		"panic":      "boom",
	})

	var out strings.Builder

	err := registry.Render(&out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(out.String(), `g0efilter_panics_total{component="dns"} 1`) {
		t.Errorf("a contained panic was not counted:\n%s", out.String())
	}
}

//nolint:exhaustruct // only the metrics registry participates in this path
func TestHandleDoesNotTreatAPanicAsADenial(t *testing.T) {
	t.Parallel()

	registry := metrics.New()
	shipper := &Shipper{metrics: registry}

	shipper.Handle(t.Context(), time.Now(), recovery.PanicMessage, map[string]any{
		keyComponent:     "dns",
		actions.KeyAlert: true,
	})

	var out strings.Builder

	err := registry.Render(&out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if strings.Contains(out.String(), "g0efilter_denials_total{component=\"dns\"") {
		t.Errorf("a panic must not be recorded as a policy denial:\n%s", out.String())
	}
}
