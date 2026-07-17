//nolint:testpackage // drives the real ingest handler + SQLite store internals
package dashboard

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/store"
)

// stressBatch builds a JSON array of n synthetic flow events.
func stressBatch(n, base int) []byte {
	events := make([]map[string]any, n)
	for i := range n {
		action := "ALLOWED"
		if (base+i)%3 == 0 {
			action = "BLOCKED"
		}

		events[i] = map[string]any{
			"time":             "2026-07-17T00:00:00Z",
			"msg":              "flow.decision",
			"action":           action,
			"component":        "https",
			"http_host":        fmt.Sprintf("host%d.example", (base+i)%500),
			"source_ip":        fmt.Sprintf("172.20.0.%d", i%250+2),
			"destination_ip":   fmt.Sprintf("140.82.%d.%d", i%250, i%200),
			"destination_port": 443,
			"hostname":         fmt.Sprintf("runner-%d", i%8),
		}
	}

	b, _ := json.Marshal(events) //nolint:errchkjson // static test payload cannot fail

	return b
}

// stressServer returns a server backed by a real SQLite LogStore.
func stressServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()

	ctx := context.Background()

	client, db, err := store.Open(ctx, filepath.Join(t.TempDir(), "stress.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = client.Close() })

	err = store.Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	srv := newTestServer()
	srv.store = store.NewLogStore(client, 1_000_000) // retention above the test volume

	return srv, db
}

func ingest(t *testing.T, srv *Server, body []byte) {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.ingestHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
}

func rowCount(t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int

	err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM logs`).Scan(&n)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	return n
}

// TestIngestStress_Sequential confirms the persistent ingest path absorbs a
// large burst without errors and persists every event. The time bound is a
// generous "did not hang/regress catastrophically" guard, not a perf gate.
func TestIngestStress_Sequential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short mode")
	}

	t.Parallel()

	srv, db := stressServer(t)

	const (
		total   = 5_000
		perPost = 1_000
	)

	start := time.Now()

	for b := range total / perPost {
		ingest(t, srv, stressBatch(perPost, b*perPost))
	}

	elapsed := time.Since(start)
	t.Logf("ingested %d events in %s (%.0f events/s)", total, elapsed, float64(total)/elapsed.Seconds())

	if got := rowCount(t, db); got != total {
		t.Fatalf("persisted rows = %d, want %d", got, total)
	}

	if elapsed > 60*time.Second {
		t.Fatalf("ingest of %d events took %s (too slow)", total, elapsed)
	}
}

// TestIngestStress_Concurrent hammers the single-writer SQLite store from many
// goroutines at once - the realistic fleet case - and asserts no errors and no
// lost writes (WAL + busy_timeout must serialize cleanly, not deadlock).
func TestIngestStress_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short mode")
	}

	t.Parallel()

	srv, db := stressServer(t)

	const (
		workers        = 8
		batchesPerWork = 2
		perPost        = 500
	)

	var wg sync.WaitGroup

	start := time.Now()

	for w := range workers {
		wg.Add(1)

		go func(worker int) {
			defer wg.Done()

			for b := range batchesPerWork {
				ingest(t, srv, stressBatch(perPost, (worker*batchesPerWork+b)*perPost))
			}
		}(w)
	}

	wg.Wait()

	total := workers * batchesPerWork * perPost
	elapsed := time.Since(start)
	t.Logf("concurrently ingested %d events in %s (%.0f events/s)", total, elapsed, float64(total)/elapsed.Seconds())

	if got := rowCount(t, db); got != total {
		t.Fatalf("persisted rows = %d, want %d (lost writes under concurrency)", got, total)
	}
}
