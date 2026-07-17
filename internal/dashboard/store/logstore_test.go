package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/model"
	"github.com/g0lab/g0efilter/internal/dashboard/store"
)

//nolint:cyclop,funlen // sequential scenario test
func TestLogStore_InsertQueryClear(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client, _ := testDB(t)
	s := store.NewLogStore(client, 1000)

	entries := []model.LogEntry{
		{
			Time: time.Now(), Message: "flow.decision", Action: "ALLOWED",
			HTTPHost: "github.com", Fields: json.RawMessage(`{"x":1}`),
		},
		{Time: time.Now(), Message: "flow.decision", Action: "BLOCKED", HTTPHost: "evil.example"},
		{Time: time.Now(), Message: "dns.query", Action: "ALLOWED", HTTPHost: "example.com"},
	}

	ids := make([]int64, 0, len(entries))

	for i := range entries {
		id, err := s.Insert(ctx, &entries[i])
		if err != nil {
			t.Fatalf("insert: %v", err)
		}

		if id == 0 {
			t.Fatal("insert returned id 0")
		}

		ids = append(ids, id)
	}

	// Newest first, IDs assigned from row id.
	all, err := s.Query(ctx, "", 0, 100)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(all) != 3 || all[0].ID != ids[2] {
		t.Fatalf("query all = %d rows, newest id %d (want %d)", len(all), all[0].ID, ids[2])
	}

	// Substring filter over msg+fields.
	blocked, err := s.Query(ctx, "evil.example", 0, 100)
	if err != nil {
		t.Fatalf("query filter: %v", err)
	}

	if len(blocked) != 1 || blocked[0].HTTPHost != "evil.example" {
		t.Fatalf("filtered = %+v, want 1 evil.example", blocked)
	}

	// since_id returns only newer rows.
	newer, err := s.Query(ctx, "", ids[0], 100)
	if err != nil {
		t.Fatalf("query since: %v", err)
	}

	if len(newer) != 2 {
		t.Fatalf("since_id = %d rows, want 2", len(newer))
	}

	// LIKE wildcards in the query are matched literally, not as patterns.
	pct, err := s.Query(ctx, "100%", 0, 100)
	if err != nil {
		t.Fatalf("query wildcard: %v", err)
	}

	if len(pct) != 0 {
		t.Fatalf("wildcard query matched %d, want 0", len(pct))
	}

	err = s.Clear(ctx)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}

	all, _ = s.Query(ctx, "", 0, 100)
	if len(all) != 0 {
		t.Fatalf("after clear = %d rows, want 0", len(all))
	}
}

func TestLogStore_Retention(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// Retention smaller than logPruneEvery so a prune fires within the loop.
	client, _ := testDB(t)
	s := store.NewLogStore(client, 50)

	for range 600 {
		e := model.LogEntry{Time: time.Now(), Message: "m", Action: "ALLOWED"}

		_, err := s.Insert(ctx, &e)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	rows, err := s.Query(ctx, "", 0, 5000)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	// Prune runs every 256 inserts and keeps the newest ~retention rows; after
	// 600 inserts the table must be bounded well under the total.
	if len(rows) > 300 {
		t.Fatalf("retention not enforced: %d rows retained", len(rows))
	}
}
