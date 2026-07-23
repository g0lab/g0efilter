package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/demo"
)

func TestBuildPayloadUsesCanonicalDestination(t *testing.T) {
	t.Parallel()

	destination := demo.Destination{
		Domain:    "api.example",
		Verdict:   "BLOCKED",
		Component: "https",
		Port:      443,
		Reason:    "not-allowlisted",
		IP:        "192.0.2.10",
	}
	payload := buildPayload("172.20", destination, "runner-1", 251)

	for key, want := range map[string]any{
		"msg":              "flow.decision",
		"action":           "BLOCKED",
		"component":        "https",
		"http_host":        "api.example",
		"reason":           "not-allowlisted",
		"source_ip":        "172.20.1.3",
		"source_port":      10311,
		"destination_ip":   "192.0.2.10",
		"destination_port": 443,
		"hostname":         "runner-1",
		"flow_id":          "dev-251",
		"version":          "dev",
	} {
		if got := payload[key]; got != want {
			t.Errorf("payload[%q] = %v, want %v", key, got, want)
		}
	}

	timestamp, ok := payload["time"].(string)
	if !ok {
		t.Fatalf("payload time = %T, want string", payload["time"])
	}

	_, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		t.Fatalf("payload time %q is not RFC3339: %v", timestamp, err)
	}
}

func TestPostEventSendsAuthenticatedJSON(t *testing.T) {
	t.Parallel()

	var received map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		if got := r.Header.Get("X-Api-Key"); got != "test-key" {
			t.Errorf("X-Api-Key = %q, want test-key", got)
		}

		err := json.NewDecoder(r.Body).Decode(&received)
		if err != nil {
			t.Errorf("decode body: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	err := postEvent(server.Client(), server.URL, "test-key", map[string]any{"action": "BLOCKED"})
	if err != nil {
		t.Fatalf("postEvent() error = %v", err)
	}

	if received["action"] != "BLOCKED" {
		t.Fatalf("received payload = %+v", received)
	}
}

func TestPostEventReportsFailures(t *testing.T) {
	t.Parallel()

	t.Run("marshal", func(t *testing.T) {
		t.Parallel()

		err := postEvent(http.DefaultClient, "http://unused", "", map[string]any{"bad": func() {}})
		if err == nil || !strings.Contains(err.Error(), "marshal payload") {
			t.Fatalf("postEvent() error = %v, want marshal payload", err)
		}
	})

	t.Run("request", func(t *testing.T) {
		t.Parallel()

		err := postEvent(http.DefaultClient, "://bad-url", "", map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("postEvent() error = %v, want build request", err)
		}
	})

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusUnauthorized)
		}))
		t.Cleanup(server.Close)

		err := postEvent(server.Client(), server.URL, "", map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "ingest returned 401") {
			t.Fatalf("postEvent() error = %v, want status error", err)
		}
	})

	t.Run("transport", func(t *testing.T) {
		t.Parallel()

		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}

		err := postEvent(client, "http://example.test", "", map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "post event") {
			t.Fatalf("postEvent() error = %v, want transport error", err)
		}
	})
}

func TestGetenv(t *testing.T) {
	t.Setenv("TEST_DEV_TRAFFIC_VALUE", "configured")

	if got := getenv("TEST_DEV_TRAFFIC_VALUE", "fallback"); got != "configured" {
		t.Errorf("getenv configured = %q, want configured", got)
	}

	t.Setenv("TEST_DEV_TRAFFIC_VALUE", "")

	if got := getenv("TEST_DEV_TRAFFIC_VALUE", "fallback"); got != "fallback" {
		t.Errorf("getenv empty = %q, want fallback", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
