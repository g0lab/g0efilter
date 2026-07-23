package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/demo"
	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store"
)

func testFixtures(t *testing.T) demo.Fixtures {
	t.Helper()

	fixtures, err := demo.Scenarios()
	if err != nil {
		t.Fatalf("load scenarios: %v", err)
	}

	return fixtures
}

//nolint:cyclop,wsl_v5 // sequential range + verdict-consistency assertions
func TestBuildEntriesCoversEveryDashboardRange(t *testing.T) {
	t.Parallel()

	fixtures := testFixtures(t)
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	entries := buildEntries(defaultSeedCount, now, fixtures)
	if len(entries) != defaultSeedCount {
		t.Fatalf("entries = %d, want %d", len(entries), defaultSeedCount)
	}

	// Key by domain, falling back to IP for raw-IP destinations. A shared CDN IP
	// may back two domains with different verdicts, so key by identity, not IP.
	// Each destination must keep a single, consistent verdict everywhere.
	verdicts := make(map[string]string)
	for _, entry := range entries {
		key := entry.HTTPHost
		if key == "" {
			key = entry.DestinationIP
		}

		if prev, ok := verdicts[key]; ok && prev != entry.Action {
			t.Fatalf("dest %s has inconsistent verdicts %s and %s", key, prev, entry.Action)
		}

		verdicts[key] = entry.Action
	}
	if len(verdicts) != len(fixtures.Destinations) {
		t.Fatalf("seeded destinations = %d, want %d", len(verdicts), len(fixtures.Destinations))
	}

	windows := []time.Duration{
		15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour,
		7 * 24 * time.Hour, 30 * 24 * time.Hour, 90 * 24 * time.Hour,
	}
	previous := 0
	for _, window := range windows {
		count := 0
		for _, entry := range entries {
			if !entry.Time.Before(now.Add(-window)) {
				count++
			}
		}
		if count <= previous || count >= defaultSeedCount {
			t.Fatalf("window %s has %d entries after previous %d", window, count, previous)
		}
		previous = count
	}
}

//nolint:wsl_v5 // sequential replacement scenario
func TestSeedDatabaseReplacesLogFixture(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	fixtures := testFixtures(t)
	dbPath := filepath.Join(t.TempDir(), "dashboard.db")

	err := seedDatabase(ctx, dbPath, 250, now, fixtures)
	if err != nil {
		t.Fatalf("seed database: %v", err)
	}
	assertSeedCount(ctx, t, dbPath, now, 250)

	err = seedDatabase(ctx, dbPath, 75, now, fixtures)
	if err != nil {
		t.Fatalf("reseed database: %v", err)
	}
	assertSeedCount(ctx, t, dbPath, now, 75)
}

func TestSeedDatabaseRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		path  string
		count int
	}{
		{name: "empty path", count: 1},
		{name: "blank path", path: "  ", count: 1},
		{name: "zero count", path: "unused.db"},
		{name: "negative count", path: "unused.db", count: -1},
		{name: "over maximum", path: "unused.db", count: maxSeedCount + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := seedDatabase(context.Background(), tt.path, tt.count, time.Now(), testFixtures(t))
			if !errors.Is(err, errInvalidSeedConfig) {
				t.Fatalf("seedDatabase error = %v, want errInvalidSeedConfig", err)
			}
		})
	}
}

//nolint:wsl_v5 // compact test helper
func assertSeedCount(ctx context.Context, t *testing.T, dbPath string, now time.Time, want int) {
	t.Helper()

	client, _, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open seeded database: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := store.NewLogStore(client, maxSeedCount).Aggregate(ctx, model.AggregateParams{To: now, Buckets: 24})
	if err != nil {
		t.Fatalf("aggregate seeded database: %v", err)
	}
	if result.Events != want {
		t.Fatalf("seeded events = %d, want %d", result.Events, want)
	}
}
