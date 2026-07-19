//nolint:testpackage // Need access to internal implementation details
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// listGroups fetches GET /api/v1/fleet/groups and returns the decoded array.
func listGroups(t *testing.T, router http.Handler) []map[string]any {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/fleet/groups", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET groups = %d (%s)", w.Code, w.Body.String())
	}

	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode groups: %v", err)
	}

	return out
}

func TestFleet_GroupListAndDelete(t *testing.T) {
	t.Parallel()

	srv := newFleetServer(t)
	router := srv.routes()

	if got := listGroups(t, router); len(got) != 0 {
		t.Fatalf("groups on empty fleet = %d, want 0", len(got))
	}

	createGroup(t, router, "alpha")
	betaID := createGroup(t, router, "beta")

	groups := listGroups(t, router)
	if len(groups) != 2 {
		t.Fatalf("groups after create = %d, want 2", len(groups))
	}

	names := map[string]bool{}
	for _, g := range groups {
		name, _ := g["name"].(string)
		names[name] = true
	}

	if !names["alpha"] || !names["beta"] {
		t.Fatalf("group names = %v, want alpha+beta", names)
	}

	// Delete an existing group, then confirm it is gone.
	delJSON(t, router, "/api/v1/fleet/groups/"+betaID, http.StatusOK)

	if got := listGroups(t, router); len(got) != 1 {
		t.Fatalf("groups after delete = %d, want 1", len(got))
	}

	// Deleting an unknown id is a 404, not a silent success.
	delJSON(t, router, "/api/v1/fleet/groups/does-not-exist", http.StatusNotFound)
}

func TestFleet_InstancePolicyOverride(t *testing.T) {
	t.Parallel()

	srv := newFleetServer(t)
	router := srv.routes()

	// Register an ungrouped instance.
	code, resp := syncCall(t, router,
		`{"hostname":"host-o","filter_mode":"https","version":"1.0","config_hash":""}`)
	if code != http.StatusOK || resp["managed"] != false {
		t.Fatalf("initial sync = %d managed=%v, want 200 unmanaged", code, resp["managed"])
	}

	instID, _ := listFleet(t, router)[0]["id"].(string)

	// A per-instance override makes the instance managed with no group involved.
	putJSON(t, router, "/api/v1/fleet/instances/"+instID+"/policy",
		`{"policy":"ALLOW example.com"}`)

	code, resp = syncCall(t, router,
		`{"hostname":"host-o","filter_mode":"https","version":"1.0","config_hash":"stale"}`)
	if code != http.StatusOK || resp["managed"] != true {
		t.Fatalf("override sync = %d managed=%v, want 200 managed", code, resp["managed"])
	}

	if resp["policy"] != "ALLOW example.com" {
		t.Fatalf("override policy = %v, want ALLOW example.com", resp["policy"])
	}

	// Clearing the override (policy:null) reverts the instance to unmanaged.
	putJSON(t, router, "/api/v1/fleet/instances/"+instID+"/policy", `{"policy":null}`)

	code, resp = syncCall(t, router,
		`{"hostname":"host-o","filter_mode":"https","version":"1.0","config_hash":"stale-again"}`)
	if code != http.StatusOK || resp["managed"] != false {
		t.Fatalf("cleared sync = %d managed=%v, want 200 unmanaged", code, resp["managed"])
	}

	if _, ok := resp["policy"]; ok {
		t.Error("unmanaged sync must not ship a policy body")
	}
}

func TestFleet_RequestValidation(t *testing.T) {
	t.Parallel()

	srv := newFleetServer(t)
	router := srv.routes()

	grpID := createGroup(t, router, "gamma")

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"group policy rejects unknown filter_mode", http.MethodPut,
			"/api/v1/fleet/groups/" + grpID + "/policy",
			`{"policy":"ALLOW x","filter_mode":"bogus"}`, http.StatusBadRequest},
		{"instance policy rejects malformed json", http.MethodPut,
			"/api/v1/fleet/instances/whatever/policy",
			`{not-json`, http.StatusBadRequest},
		{"create group rejects empty name", http.MethodPost,
			"/api/v1/fleet/groups", `{"name":"  "}`, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(),
				tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.want {
				t.Fatalf("%s = %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
