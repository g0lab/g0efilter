package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/store"
)

//nolint:wsl_v5 // sequential range assertions
func TestBuildEntriesCoversEveryDashboardRange(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	entries := buildEntries(defaultSeedCount, now)
	if len(entries) != defaultSeedCount {
		t.Fatalf("entries = %d, want %d", len(entries), defaultSeedCount)
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
	dbPath := filepath.Join(t.TempDir(), "dashboard.db")

	err := seedDatabase(ctx, dbPath, 250, now)
	if err != nil {
		t.Fatalf("seed database: %v", err)
	}
	assertSeedCount(ctx, t, dbPath, now, 250)

	err = seedDatabase(ctx, dbPath, 75, now)
	if err != nil {
		t.Fatalf("reseed database: %v", err)
	}
	assertSeedCount(ctx, t, dbPath, now, 75)
}

//nolint:wsl_v5 // compact test helper
func assertSeedCount(ctx context.Context, t *testing.T, dbPath string, now time.Time, want int) {
	t.Helper()

	client, _, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open seeded database: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := store.NewLogStore(client, maxSeedCount).Aggregate(ctx, time.Time{}, now, "", 24)
	if err != nil {
		t.Fatalf("aggregate seeded database: %v", err)
	}
	if result.Events != want {
		t.Fatalf("seeded events = %d, want %d", result.Events, want)
	}
}
