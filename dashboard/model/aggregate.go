package model

import (
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	verdictAllowed = "ALLOWED"
	verdictBlocked = "BLOCKED"
	verdictAudit   = "AUDIT"
)

const (
	DimensionDomain = "domain"
	DimensionIP     = "ip"
	DimensionClient = "client"
)

// AggregateParams controls how retained logs are summarized.
type AggregateParams struct {
	From      time.Time
	To        time.Time
	Query     string
	Dimension string // domain, ip, client, or empty for the legacy destination key
	Component string // "" keeps all; otherwise only nflog/http/dns/https events.
	Buckets   int
}

// AggregateResult is a compact summary of retained traffic logs.
type AggregateResult struct {
	From    time.Time         `json:"from"`
	To      time.Time         `json:"to"`
	Events  int               `json:"events"`
	Totals  AggregateTotals   `json:"totals"`
	Buckets []AggregateBucket `json:"buckets"`
	Rows    []AggregateRow    `json:"rows"`
}

// AggregateTotals contains verdict totals for an aggregate window.
type AggregateTotals struct {
	Allowed int `json:"allowed"`
	Blocked int `json:"blocked"`
	Audit   int `json:"audit"`
}

// AggregateBucket contains verdict totals for one chart interval.
type AggregateBucket struct {
	Start   time.Time `json:"start"`
	Allowed int       `json:"allowed"`
	Blocked int       `json:"blocked"`
	Audit   int       `json:"audit"`
}

// AggregateRow contains verdict totals for one destination key.
type AggregateRow struct {
	Key      string    `json:"key"`
	LastSeen time.Time `json:"last_seen"` //nolint:tagliatelle // API uses snake_case
	Total    int       `json:"total"`
	Allowed  int       `json:"allowed"`
	Blocked  int       `json:"blocked"`
	Audit    int       `json:"audit"`
}

type aggregateEvent struct {
	time    time.Time
	verdict string
}

// AggregateLogs reduces log entries to chart buckets and per-key rows keyed by
// the requested dimension (destination by default, or client hostname).
//
//nolint:cyclop,funlen,wsl_v5 // single-pass filtering and reduction is easier to audit together
func AggregateLogs(entries []LogEntry, p AggregateParams) AggregateResult {
	bucketCount := p.Buckets
	if bucketCount < 1 {
		bucketCount = 24
	}

	from, to := p.From, p.To
	query := strings.ToLower(strings.TrimSpace(p.Query))
	component := strings.ToLower(strings.TrimSpace(p.Component))
	rows := make(map[string]*AggregateRow)
	events := make([]aggregateEvent, 0, len(entries))
	result := AggregateResult{
		From:    from,
		To:      to,
		Buckets: []AggregateBucket{},
		Rows:    []AggregateRow{},
	}

	for i := range entries {
		entry := &entries[i]
		if (!from.IsZero() && entry.Time.Before(from)) || (!to.IsZero() && entry.Time.After(to)) {
			continue
		}

		verdict := strings.ToUpper(strings.TrimSpace(entry.Action))
		if verdict != verdictAllowed && verdict != verdictBlocked && verdict != verdictAudit {
			continue
		}

		if component != "" && ComponentOf(entry) != component {
			continue
		}

		key := dimensionKey(entry, p.Dimension)
		if query != "" && !strings.Contains(strings.ToLower(key), query) {
			continue
		}

		incrementTotals(&result.Totals, verdict)
		result.Events++
		events = append(events, aggregateEvent{time: entry.Time, verdict: verdict})

		if key == "" {
			continue
		}

		row := rows[key]
		if row == nil {
			row = &AggregateRow{Key: key}
			rows[key] = row
		}
		row.Total++
		if entry.Time.After(row.LastSeen) {
			row.LastSeen = entry.Time
		}
		incrementRow(row, verdict)
	}

	if len(events) == 0 {
		return result
	}

	result.Rows = make([]AggregateRow, 0, len(rows))
	for _, row := range rows {
		result.Rows = append(result.Rows, *row)
	}
	slices.SortFunc(result.Rows, func(a, b AggregateRow) int {
		if a.Total != b.Total {
			return b.Total - a.Total
		}

		return strings.Compare(a.Key, b.Key)
	})

	lo, hi := aggregateBounds(events, from, to)
	result.From = lo
	result.To = hi
	result.Buckets = make([]AggregateBucket, bucketCount)
	span := hi.Sub(lo)
	for i := range result.Buckets {
		result.Buckets[i].Start = lo.Add(time.Duration(i) * span / time.Duration(bucketCount))
	}
	for _, event := range events {
		index := int(event.time.Sub(lo) * time.Duration(bucketCount) / span)
		index = min(max(index, 0), bucketCount-1)
		incrementBucket(&result.Buckets[index], event.verdict)
	}

	return result
}

func aggregateBounds(events []aggregateEvent, from, to time.Time) (time.Time, time.Time) {
	lo, hi := events[0].time, events[0].time
	for _, event := range events[1:] {
		if event.time.Before(lo) {
			lo = event.time
		}

		if event.time.After(hi) {
			hi = event.time
		}
	}

	if !from.IsZero() {
		lo = from
	}

	if !to.IsZero() {
		hi = to
	}

	if hi.Sub(lo) < time.Minute {
		hi = lo.Add(time.Minute)
	}

	return lo, hi
}

func dimensionKey(entry *LogEntry, dimension string) string {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case DimensionClient:
		return strings.TrimSpace(entry.Hostname)
	case DimensionIP:
		return strings.TrimSpace(entry.DestinationIP)
	case DimensionDomain:
		return domainOf(entry)
	default:
		return aggregateKey(entry)
	}
}

func domainOf(entry *LogEntry) string {
	for _, value := range []string{entry.HTTPHost, entry.HTTPS} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}

	return ""
}

// ComponentOf returns the lowercased filter component (nflog/http/dns/https) for
// an entry, read from the Fields blob where the ingest path stores it.
func ComponentOf(entry *LogEntry) string {
	if len(entry.Fields) == 0 {
		return ""
	}

	var f struct {
		Component string `json:"component"`
	}

	_ = json.Unmarshal(entry.Fields, &f)

	return strings.ToLower(strings.TrimSpace(f.Component))
}

func aggregateKey(entry *LogEntry) string {
	for _, value := range []string{entry.HTTPHost, entry.HTTPS, entry.Dst} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}

	if entry.DestinationIP == "" {
		return ""
	}

	if entry.DestinationPort > 0 {
		return net.JoinHostPort(entry.DestinationIP, strconv.Itoa(entry.DestinationPort))
	}

	return entry.DestinationIP
}

func incrementTotals(totals *AggregateTotals, verdict string) {
	switch verdict {
	case verdictAllowed:
		totals.Allowed++
	case verdictBlocked:
		totals.Blocked++
	case verdictAudit:
		totals.Audit++
	}
}

func incrementRow(row *AggregateRow, verdict string) {
	switch verdict {
	case verdictAllowed:
		row.Allowed++
	case verdictBlocked:
		row.Blocked++
	case verdictAudit:
		row.Audit++
	}
}

func incrementBucket(bucket *AggregateBucket, verdict string) {
	switch verdict {
	case verdictAllowed:
		bucket.Allowed++
	case verdictBlocked:
		bucket.Blocked++
	case verdictAudit:
		bucket.Audit++
	}
}
