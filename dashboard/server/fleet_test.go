//nolint:testpackage // Need access to internal implementation details
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/store"
)

func newFleetServer(t *testing.T) *Server {
	t.Helper()

	client, db, err := store.Open(context.Background(), t.TempDir()+"/fleet.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = client.Close() })

	err = store.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	lg := slog.New(slog.DiscardHandler)
	srv := newServer(lg, Config{
		APIKey: "test-api-key", BufferSize: 10, ReadLimit: 10,
		AuthMode: AuthModeNone, FleetEnabled: true,
	})
	srv.apiKeys = newMemAPIKeyStore("test-api-key")
	srv.fleet = store.NewFleetStore(client, lg)

	return srv
}

// syncCall posts a report to /api/v1/sync and returns the decoded response.
func syncCall(t *testing.T, router http.Handler, body string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/sync", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "test-api-key")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var out map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}

	return w.Code, out
}

//nolint:cyclop,funlen // sequential end-to-end fleet scenario
func TestFleet_SyncAndGrouping(t *testing.T) {
	t.Parallel()

	srv := newFleetServer(t)
	router := srv.routes()

	// 1. First sync registers the instance; unmanaged, so no policy is pushed
	//    and the instance keeps its local file (managed:false, changed:false).
	code, resp := syncCall(t, router, `{"hostname":"host-a","filter_mode":"https","version":"1.0","config_hash":""}`)
	if code != http.StatusOK {
		t.Fatalf("sync = %d, want 200", code)
	}

	if resp["managed"] != false {
		t.Errorf("first sync should be unmanaged, got %+v", resp["managed"])
	}

	if resp["changed"] != false {
		t.Errorf("unmanaged sync must not report changed (would erase local policy)")
	}

	if _, ok := resp["policy"]; ok {
		t.Error("unmanaged sync must not include a policy body")
	}

	// 2. Instance now appears in the admin list.
	instances := listFleet(t, router)
	if len(instances) != 1 || instances[0]["hostname"] != "host-a" {
		t.Fatalf("instances = %+v, want 1 host-a", instances)
	}

	instID, _ := instances[0]["id"].(string)

	// 3. Create a group, give it a policy.
	grpID := createGroup(t, router, "builders")
	putJSON(t, router, "/api/v1/fleet/groups/"+grpID+"/policy",
		`{"policy":"ALLOW github.com","filter_mode":"https"}`)

	// 4. Assign the instance to the group.
	putJSON(t, router, "/api/v1/fleet/instances/"+instID+"/group",
		`{"group_id":"`+grpID+`"}`)

	// 5. Sync with a stale hash -> now managed, changed, policy shipped.
	code, resp = syncCall(t, router,
		`{"hostname":"host-a","filter_mode":"https","version":"1.0","config_hash":"stale"}`)
	if code != http.StatusOK || resp["changed"] != true {
		t.Fatalf("post-group sync should be changed: %d %+v", code, resp)
	}

	if resp["managed"] != true {
		t.Errorf("grouped instance should be managed, got %+v", resp["managed"])
	}

	if resp["policy"] != "ALLOW github.com" {
		t.Errorf("expected group policy shipped, got %+v", resp["policy"])
	}

	newHash, _ := resp["config_hash"].(string)

	// 6. Sync reporting the new hash -> steady state, no policy body.
	code, resp = syncCall(t, router,
		`{"hostname":"host-a","filter_mode":"https","version":"1.0","config_hash":"`+newHash+`"}`)
	if code != http.StatusOK || resp["changed"] != false {
		t.Fatalf("steady sync should be unchanged: %d %+v", code, resp)
	}

	if _, ok := resp["policy"]; ok {
		t.Error("steady-state sync must not include policy body")
	}

	// 7. Admin list now shows the instance in-sync and in the group.
	instances = listFleet(t, router)
	if instances[0]["group_name"] != "builders" || instances[0]["in_sync"] != true {
		t.Fatalf("instance not shown in-sync/in-group: %+v", instances[0])
	}

	// 8. Delete the instance.
	delJSON(t, router, "/api/v1/fleet/instances/"+instID, http.StatusOK)

	instances = listFleet(t, router)
	if len(instances) != 0 {
		t.Fatalf("instances after delete = %d, want 0", len(instances))
	}
}

func TestFleet_DisabledRoutesAbsent(t *testing.T) {
	t.Parallel()

	// Fleet not enabled: routes should not be registered (404).
	srv := newServer(slog.New(slog.DiscardHandler), Config{
		APIKey: "k", BufferSize: 10, ReadLimit: 10, AuthMode: AuthModeNone,
	})
	router := srv.routes()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/fleet/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("fleet route when disabled = %d, want 404", w.Code)
	}
}

func TestFleet_LongPollWakesOnDesiredStateChange(t *testing.T) {
	t.Parallel()

	srv := newFleetServer(t)
	router := srv.routes()

	code, initial := syncCall(t, router,
		`{"hostname":"host-a","filter_mode":"https","version":"1.0","config_hash":""}`)
	if code != http.StatusOK {
		t.Fatalf("initial sync = %d, want 200", code)
	}

	hash, _ := initial["config_hash"].(string)
	instances := listFleet(t, router)
	instID, _ := instances[0]["id"].(string)
	groupID := createGroup(t, router, "long-poll")
	putJSON(t, router, "/api/v1/fleet/groups/"+groupID+"/policy",
		`{"policy":"ALLOW example.com","filter_mode":"https"}`)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/sync?wait=5s", strings.NewReader(
			`{"hostname":"host-a","filter_mode":"https","version":"1.0","config_hash":"`+hash+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "test-api-key")

	rec := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		router.ServeHTTP(rec, req)
		close(done)
	}()

	putJSON(t, router, "/api/v1/fleet/instances/"+instID+"/group",
		`{"group_id":"`+groupID+`"}`)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("long poll did not wake after desired state changed")
	}

	var response map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("decode long-poll response: %v", err)
	}

	if rec.Code != http.StatusOK || response["changed"] != true {
		t.Fatalf("long-poll response = %d %+v, want changed", rec.Code, response)
	}

	if response["policy"] != "ALLOW example.com" {
		t.Fatalf("long-poll policy = %+v", response["policy"])
	}
}

func TestParseSyncWait(t *testing.T) {
	t.Parallel()

	if wait, ok := parseSyncWait(""); !ok || wait != 0 {
		t.Fatalf("empty wait = %v, %v", wait, ok)
	}

	if wait, ok := parseSyncWait("45s"); !ok || wait != maxSyncWait {
		t.Fatalf("capped wait = %v, %v", wait, ok)
	}

	for _, raw := range []string{"forever", "-1s"} {
		if _, ok := parseSyncWait(raw); ok {
			t.Errorf("parseSyncWait(%q) accepted invalid value", raw)
		}
	}
}

// --- helpers ---

func listFleet(t *testing.T, router http.Handler) []map[string]any {
	t.Helper()

	const path = "/api/v1/fleet/instances"

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, w.Code)
	}

	var out []map[string]any

	err := json.Unmarshal(w.Body.Bytes(), &out)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	return out
}

func createGroup(t *testing.T, router http.Handler, name string) string {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/fleet/groups", strings.NewReader(`{"name":"`+name+`"}`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create group = %d (%s)", w.Code, w.Body.String())
	}

	var g map[string]any

	_ = json.Unmarshal(w.Body.Bytes(), &g)

	id, _ := g["id"].(string)
	if id == "" {
		t.Fatal("group id empty")
	}

	return id
}

func putJSON(t *testing.T, router http.Handler, path, body string) {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s = %d, want %d (%s)", path, w.Code, http.StatusOK, w.Body.String())
	}
}

func delJSON(t *testing.T, router http.Handler, path string, want int) {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != want {
		t.Fatalf("DELETE %s = %d, want %d", path, w.Code, want)
	}
}
