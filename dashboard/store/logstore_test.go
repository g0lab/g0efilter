package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store"
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

//nolint:cyclop,wsl_v5 // sequential persistent aggregate scenario
func TestLogStore_AggregateUsesFullTimeWindow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client, _ := testDB(t)
	s := store.NewLogStore(client, 1000)
	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Time: now.Add(-40 * 24 * time.Hour), Action: "BLOCKED", HTTPHost: "old.example"},
		{Time: now.Add(-time.Hour), Action: "ALLOWED", HTTPHost: "recent.example"},
		{Time: now.Add(-30 * time.Minute), Action: "BLOCKED", HTTPHost: "recent.example"},
	}
	for i := range entries {
		_, err := s.Insert(ctx, &entries[i])
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result, err := s.Aggregate(ctx, now.Add(-30*24*time.Hour), now, "", 24)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if result.Events != 2 || len(result.Rows) != 1 || result.Rows[0].Key != "recent.example" {
		t.Fatalf("30-day aggregate = %+v", result)
	}

	all, err := s.Aggregate(ctx, time.Time{}, now, "old.example", 24)
	if err != nil {
		t.Fatalf("aggregate all: %v", err)
	}
	if all.Events != 1 || len(all.Rows) != 1 || all.Rows[0].Key != "old.example" {
		t.Fatalf("all-history filtered aggregate = %+v", all)
	}
}

func TestLogStore_AggregateRejectsCorruptRows(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client, _ := testDB(t)

	_, err := client.LogEvent.Create().
		SetTs(time.Now().UnixNano()).
		SetData(`{"incomplete"`).
		SetSearch("corrupt").
		Save(ctx)
	if err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}

	_, err = store.NewLogStore(client, 1000).Aggregate(ctx, time.Time{}, time.Time{}, "", 24)
	if err == nil || !strings.Contains(err.Error(), "unmarshal aggregate log") {
		t.Fatalf("Aggregate error = %v, want corrupt-row error", err)
	}
}
