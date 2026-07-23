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

	result := model.AggregateLogs(entries, model.AggregateParams{
		From: now.Add(-30 * 24 * time.Hour), To: now, Buckets: 24,
	})
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

func TestAggregateLogs_DimensionAndComponent(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Time: now, Action: "ALLOWED", HTTPHost: "a.example", Hostname: "runner-1", Fields: []byte(`{"component":"https"}`)},
		{Time: now, Action: "BLOCKED", HTTPHost: "b.example", Hostname: "runner-1", Fields: []byte(`{"component":"dns"}`)},
		{Time: now, Action: "AUDIT", HTTPHost: "c.example", Hostname: "runner-2", Fields: []byte(`{"component":"https"}`)},
	}

	byClient := model.AggregateLogs(entries, model.AggregateParams{
		To: now.Add(time.Minute), Dimension: model.DimensionClient,
	})

	if len(byClient.Rows) != 2 {
		t.Fatalf("client rows = %+v, want two clients", byClient.Rows)
	}

	if byClient.Rows[0].Key != "runner-1" || byClient.Rows[0].Total != 2 {
		t.Fatalf("top client = %+v, want runner-1 with two events", byClient.Rows[0])
	}

	// Component facet must be exact: "https" must not sweep in the dns row.
	https := model.AggregateLogs(entries, model.AggregateParams{To: now.Add(time.Minute), Component: "https"})
	if https.Events != 2 || len(https.Rows) != 2 {
		t.Fatalf("https facet = %+v, want two https events", https)
	}

	for _, row := range https.Rows {
		if row.Key == "b.example" {
			t.Fatalf("https facet leaked the dns destination: %+v", https.Rows)
		}
	}
}

func TestAggregateLogs_DomainAndIPDimensions(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Time: now, Action: "ALLOWED", HTTPHost: "a.example", DestinationIP: "1.1.1.1"},
		{Time: now, Action: "BLOCKED", DestinationIP: "9.9.9.9"}, // raw IP, no domain
	}

	// Domain dimension groups by host and excludes the raw-IP event from rows.
	dom := model.AggregateLogs(entries, model.AggregateParams{To: now.Add(time.Minute), Dimension: model.DimensionDomain})
	if dom.Events != 2 || len(dom.Rows) != 1 || dom.Rows[0].Key != "a.example" {
		t.Fatalf("domain aggregate = %+v, want two events, one a.example row", dom)
	}

	// IP dimension groups by destination IP and includes both.
	ip := model.AggregateLogs(entries, model.AggregateParams{To: now.Add(time.Minute), Dimension: model.DimensionIP})

	keys := make(map[string]bool)
	for _, row := range ip.Rows {
		keys[row.Key] = true
	}

	if len(ip.Rows) != 2 || !keys["1.1.1.1"] || !keys["9.9.9.9"] {
		t.Fatalf("ip rows = %+v, want both 1.1.1.1 and 9.9.9.9", ip.Rows)
	}
}

func TestAggregateLogs_QueryAndDestinationFallback(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Time: now, Action: "ALLOWED", DestinationIP: "2001:db8::1", DestinationPort: 443},
		{Time: now, Action: "BLOCKED", HTTPHost: "other.example"},
	}

	result := model.AggregateLogs(entries, model.AggregateParams{
		To: now.Add(time.Minute), Query: "2001:db8", Buckets: 4,
	})
	if result.Events != 1 || len(result.Rows) != 1 || result.Rows[0].Key != "[2001:db8::1]:443" {
		t.Fatalf("filtered aggregate = %+v", result)
	}
}

//nolint:cyclop,wsl_v5 // validates related aggregation edge cases together
func TestAggregateLogs_DefaultBucketsAndDestinationEdges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	entries := []model.LogEntry{
		{Time: now, Action: "ALLOWED", DestinationIP: "198.51.100.10"},
		{Time: now, Action: "BLOCKED", Dst: "proxy.example:443", DestinationIP: "198.51.100.20"},
		{Time: now, Action: "AUDIT"},
	}

	result := model.AggregateLogs(entries, model.AggregateParams{})
	if result.Events != 3 || len(result.Buckets) != 24 {
		t.Fatalf("aggregate events/buckets = %d/%d, want 3/24", result.Events, len(result.Buckets))
	}
	if len(result.Rows) != 2 {
		t.Fatalf("Rows = %+v, want two destination rows", result.Rows)
	}
	if result.Rows[0].Key != "198.51.100.10" || result.Rows[1].Key != "proxy.example:443" {
		t.Fatalf("Rows = %+v, want deterministic destination ordering", result.Rows)
	}
	if !result.From.Equal(now) || result.To.Sub(result.From) != time.Minute {
		t.Fatalf("bounds = %s..%s, want a one-minute window from event time", result.From, result.To)
	}

	empty := model.AggregateLogs(entries, model.AggregateParams{Query: "not-present"})
	if empty.Events != 0 || len(empty.Rows) != 0 || len(empty.Buckets) != 0 {
		t.Fatalf("empty filtered aggregate = %+v", empty)
	}
}
