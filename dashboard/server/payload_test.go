//nolint:testpackage // Need access to internal implementation details
package server

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func newPayloadTestServer() (*Server, *memStore, *broadcaster) {
	store := newMemStore(16)
	bc := newBroadcaster()

	srv := &Server{
		logger:      slog.New(slog.DiscardHandler),
		store:       store,
		broadcaster: bc,
	}

	return srv, store, bc
}

func TestProcessPayloadsProbeSkipped(t *testing.T) {
	t.Parallel()

	srv, store, _ := newPayloadTestServer()

	payloads := []map[string]any{
		{"msg": "_dashboard_probe"},
		{"msg": "_dashboard_healthcheck", "action": testActionBlocked},
	}

	results := srv.processPayloads(t.Context(), payloads, "10.0.0.1")
	if len(results) != 0 {
		t.Fatalf("probe payloads produced %d results, want 0", len(results))
	}

	stored, err := store.Query(t.Context(), "", 0, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(stored) != 0 {
		t.Fatalf("probe payloads stored %d entries, want 0", len(stored))
	}
}

func TestProcessPayloadsMixedBatch(t *testing.T) {
	t.Parallel()

	srv, store, _ := newPayloadTestServer()

	payloads := []map[string]any{
		{"msg": "kept", "action": "blocked"},
		{"msg": "redirect noise", "action": "REDIRECTED"},
		{"action": testActionBlocked}, // missing msg
	}

	results := srv.processPayloads(t.Context(), payloads, "10.0.0.1")
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	if results[0][keyStatus] != "ok" {
		t.Errorf("result status = %v, want ok", results[0][keyStatus])
	}

	stored, err := store.Query(t.Context(), "", 0, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(stored) != 1 {
		t.Fatalf("stored %d entries, want 1", len(stored))
	}

	if stored[0].Message != "kept" || stored[0].Action != testActionBlocked {
		t.Errorf("stored entry = %q/%q, want kept/BLOCKED", stored[0].Message, stored[0].Action)
	}
}

func TestProcessPayloadsBroadcastsStoredEntry(t *testing.T) {
	t.Parallel()

	srv, _, bc := newPayloadTestServer()
	ch := bc.Add()

	srv.processPayloads(t.Context(), []map[string]any{
		{"msg": "hit", "action": "allowed", "https": testExampleDomain},
	}, "10.0.0.1")

	select {
	case raw := <-ch:
		var entry LogEntry

		err := json.Unmarshal(raw, &entry)
		if err != nil {
			t.Fatalf("broadcast payload is not valid JSON: %v", err)
		}

		if entry.ID != 1 || entry.Message != "hit" || entry.Action != testActionAllowed {
			t.Errorf("broadcast entry = %+v, want id 1 / hit / ALLOWED", entry)
		}

		if entry.HTTPS != testExampleDomain {
			t.Errorf("broadcast HTTPS = %q, want %q", entry.HTTPS, testExampleDomain)
		}
	case <-time.After(time.Second):
		t.Fatal("no broadcast received for stored entry")
	}

	bc.Remove(ch)
}

func TestProcessPayloadActionNormalization(t *testing.T) {
	t.Parallel()

	srv, _, _ := newPayloadTestServer()

	tests := []struct {
		name       string
		action     any
		wantAction string
	}{
		{name: "audit kept", action: "AUDIT", wantAction: "AUDIT"},
		{name: "lowercase with spaces", action: "  audit  ", wantAction: "AUDIT"},
		{name: "mixed case allowed", action: "AlLoWeD", wantAction: testActionAllowed},
		{name: "redirected rejected", action: "REDIRECTED", wantAction: ""},
		{name: "unknown rejected", action: "whatever", wantAction: ""},
		{name: "missing rejected", action: nil, wantAction: ""},
		{name: "non-string rejected", action: 42, wantAction: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := map[string]any{"msg": "m"}
			if tt.action != nil {
				in["action"] = tt.action
			}

			entry := srv.processPayload(t.Context(), in, "10.0.0.1")

			if tt.wantAction == "" {
				if entry != nil {
					t.Fatalf("payload with action %v should be rejected, got %+v", tt.action, entry)
				}

				return
			}

			if entry == nil {
				t.Fatalf("payload with action %v should be kept", tt.action)

				return
			}

			if entry.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", entry.Action, tt.wantAction)
			}
		})
	}
}

func TestProcessPayloadTimestampParsing(t *testing.T) {
	t.Parallel()

	srv, _, _ := newPayloadTestServer()

	t.Run("valid RFC3339Nano used verbatim", func(t *testing.T) {
		t.Parallel()

		want := time.Date(2024, 3, 4, 5, 6, 7, 123456789, time.UTC)

		entry := srv.processPayload(t.Context(), map[string]any{
			"msg":    "m",
			"action": testActionBlocked,
			"time":   "2024-03-04T05:06:07.123456789Z",
		}, "10.0.0.1")
		if entry == nil {
			t.Fatal("entry rejected")

			return
		}

		if !entry.Time.Equal(want) {
			t.Errorf("Time = %v, want %v", entry.Time, want)
		}
	})

	for name, tval := range map[string]any{
		"invalid string falls back to now": "not-a-timestamp",
		"non-string falls back to now":     float64(1700000000),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			before := time.Now().UTC().Add(-time.Minute)

			entry := srv.processPayload(t.Context(), map[string]any{
				"msg":    "m",
				"action": testActionBlocked,
				"time":   tval,
			}, "10.0.0.1")
			if entry == nil {
				t.Fatal("entry rejected")

				return
			}

			after := time.Now().UTC().Add(time.Minute)
			if entry.Time.Before(before) || entry.Time.After(after) {
				t.Errorf("fallback Time = %v, want roughly now", entry.Time)
			}
		})
	}
}

func TestExtractFieldsMapProcessMetadata(t *testing.T) {
	t.Parallel()

	in := map[string]any{
		"msg":          "m",
		"pid":          float64(1234),
		"process_name": "curl",
		"cmdline":      "curl https://example.com",
		"executable":   "/usr/bin/curl",
		"reason":       nil, // nil values are skipped
		"fields": map[string]any{
			"nested": "kept",
			"pid":    float64(1), // top-level pid overrides nested pid
		},
	}

	got := extractFieldsMap(in)

	want := map[string]any{
		"pid":          float64(1234),
		"process_name": "curl",
		"cmdline":      "curl https://example.com",
		"executable":   "/usr/bin/curl",
		"nested":       "kept",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("fieldsMap[%q] = %v, want %v", k, got[k], v)
		}
	}

	if _, ok := got["reason"]; ok {
		t.Error("nil-valued key should not be copied")
	}

	if _, ok := got["msg"]; ok {
		t.Error("msg is not a passthrough field and should not be copied")
	}
}

func TestProcessPayloadProcessMetadataInFields(t *testing.T) {
	t.Parallel()

	srv, _, _ := newPayloadTestServer()

	entry := srv.processPayload(t.Context(), map[string]any{
		"msg":          "m",
		"action":       testActionBlocked,
		"pid":          float64(42),
		"process_name": "wget",
		"cmdline":      "wget example.com",
		"executable":   "/usr/bin/wget",
	}, "10.0.0.1")
	if entry == nil {
		t.Fatal("entry rejected")

		return
	}

	var fields map[string]any

	err := json.Unmarshal(entry.Fields, &fields)
	if err != nil {
		t.Fatalf("Fields is not valid JSON: %v", err)
	}

	want := map[string]any{
		"pid":          float64(42),
		"process_name": "wget",
		"cmdline":      "wget example.com",
		"executable":   "/usr/bin/wget",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("Fields[%q] = %v, want %v", k, fields[k], v)
		}
	}
}
