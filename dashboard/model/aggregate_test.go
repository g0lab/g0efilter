package model_test

import (
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
)

//nolint:cyclop,wsl_v5 // validates totals, rows, and buckets in one scenario
func TestAggregateLogs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	entries := []model.LogEntry{
		{Time: now.Add(-31 * 24 * time.Hour), Action: "BLOCKED", HTTPHost: "old.example"},
		{Time: now.Add(-2 * time.Hour), Action: "ALLOWED", HTTPHost: "api.example"},
		{Time: now.Add(-time.Hour), Action: "BLOCKED", HTTPHost: "api.example"},
		{Time: now.Add(-30 * time.Minute), Action: "AUDIT", HTTPS: "audit.example"},
		{Time: now.Add(-time.Minute), Action: "INFO", HTTPHost: "ignored.example"},
	}

	result := model.AggregateLogs(entries, now.Add(-30*24*time.Hour), now, "", 24)
	if result.Events != 3 {
		t.Fatalf("Events = %d, want 3", result.Events)
	}
	if result.Totals.Allowed != 1 || result.Totals.Blocked != 1 || result.Totals.Audit != 1 {
		t.Fatalf("Totals = %+v, want one of each verdict", result.Totals)
	}
	if len(result.Rows) != 2 || result.Rows[0].Key != "api.example" || result.Rows[0].Total != 2 {
		t.Fatalf("Rows = %+v, want api.example first with two events", result.Rows)
	}
	if len(result.Buckets) != 24 {
		t.Fatalf("Buckets = %d, want 24", len(result.Buckets))
	}

	var bucketEvents int
	for _, bucket := range result.Buckets {
		bucketEvents += bucket.Allowed + bucket.Blocked + bucket.Audit
	}
	if bucketEvents != result.Events {
		t.Fatalf("bucket events = %d, want %d", bucketEvents, result.Events)
	}
}

func TestAggregateLogs_QueryAndDestinationFallback(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Time: now, Action: "ALLOWED", DestinationIP: "2001:db8::1", DestinationPort: 443},
		{Time: now, Action: "BLOCKED", HTTPHost: "other.example"},
	}

	result := model.AggregateLogs(entries, time.Time{}, now.Add(time.Minute), "2001:db8", 4)
	if result.Events != 1 || len(result.Rows) != 1 || result.Rows[0].Key != "[2001:db8::1]:443" {
		t.Fatalf("filtered aggregate = %+v", result)
	}
}
