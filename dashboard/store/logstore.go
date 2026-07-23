package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store/ent"
	"github.com/g0lab/g0efilter/dashboard/store/ent/logevent"
	"github.com/g0lab/g0efilter/dashboard/store/ent/predicate"
)

const (
	defaultLogRetention = 100000
	logPruneEvery       = 256 // prune once every N inserts to amortize cost
	maxLogQueryLimit    = 5000
)

// LogStore is an Ent-backed implementation of the dashboard LogStore interface,
// used when DB_PATH is set. Pruning is amortized (every logPruneEvery
// inserts), so the row count settles around `retention` but can transiently
// exceed it by up to logPruneEvery-1 rows between prunes.
type LogStore struct {
	client    *ent.Client
	retention int64
	inserts   atomic.Int64
}

// NewLogStore creates a SQLite-backed log store with the given row retention.
func NewLogStore(client *ent.Client, retention int) *LogStore {
	if retention <= 0 {
		retention = defaultLogRetention
	}

	return &LogStore{client: client, retention: int64(retention)}
}

// Insert stores an entry and returns its assigned ID.
func (s *LogStore) Insert(ctx context.Context, e *model.LogEntry) (int64, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return 0, fmt.Errorf("marshal log entry: %w", err)
	}

	searchParts := []string{
		e.Message, string(e.Fields), e.Action, e.HTTPHost, e.HTTPS,
		e.SourceIP, e.DestinationIP, e.Hostname, e.Protocol, e.Src, e.Dst,
		`"action":"` + strings.ToLower(strings.TrimSpace(e.Action)) + `"`,
	}
	if component := model.ComponentOf(e); component != "" {
		searchParts = append(searchParts, `"component":"`+component+`"`)
	}
	search := strings.ToLower(strings.Join(searchParts, "\n"))

	ts := e.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	row, err := s.client.LogEvent.Create().
		SetTs(ts.UnixNano()).
		SetData(string(data)).
		SetSearch(search).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("insert log: %w", err)
	}

	if s.inserts.Add(1)%logPruneEvery == 0 {
		s.prune(ctx)
	}

	return int64(row.ID), nil
}

// Query returns entries matching q (substring over msg+fields) with ID greater
// than sinceID, newest first, capped at limit. IDs come from the row id.
func (s *LogStore) Query(ctx context.Context, q string, sinceID int64, limit int) ([]model.LogEntry, error) {
	if limit <= 0 || limit > maxLogQueryLimit {
		limit = maxLogQueryLimit
	}

	qb := s.client.LogEvent.Query()

	if sinceID > math.MaxInt {
		return []model.LogEntry{}, nil // no row id can exceed MaxInt
	}

	if sinceID > 0 {
		qb = qb.Where(logevent.IDGT(int(sinceID)))
	}

	q = strings.ToLower(strings.TrimSpace(q))
	if q != "" {
		qb = qb.Where(searchLike(q))
	}

	rows, err := qb.
		Order(logevent.ByID(entsql.OrderDesc())).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("query logs: %w", err)
	}

	out := make([]model.LogEntry, 0, len(rows))

	for _, r := range rows {
		var e model.LogEntry

		err = json.Unmarshal([]byte(r.Data), &e)
		if err != nil {
			return nil, fmt.Errorf("unmarshal log: %w", err)
		}

		e.ID = int64(r.ID)
		out = append(out, e)
	}

	return out, nil
}

// Aggregate summarizes every retained row in the requested time window.
func (s *LogStore) Aggregate(
	ctx context.Context, p model.AggregateParams,
) (model.AggregateResult, error) {
	qb := s.client.LogEvent.Query()
	if !p.From.IsZero() {
		qb = qb.Where(logevent.TsGTE(p.From.UnixNano()))
	}

	if !p.To.IsZero() {
		qb = qb.Where(logevent.TsLTE(p.To.UnixNano()))
	}

	q := strings.ToLower(strings.TrimSpace(p.Query))
	if q != "" {
		qb = qb.Where(searchLike(q))
	}

	rows, err := qb.Order(logevent.ByTs()).All(ctx)
	if err != nil {
		return model.AggregateResult{}, fmt.Errorf("query aggregate logs: %w", err)
	}

	entries := make([]model.LogEntry, 0, len(rows))
	for _, row := range rows {
		var entry model.LogEntry

		err = json.Unmarshal([]byte(row.Data), &entry)
		if err != nil {
			return model.AggregateResult{}, fmt.Errorf("unmarshal aggregate log: %w", err)
		}

		entries = append(entries, entry)
	}

	return model.AggregateLogs(entries, p), nil
}

// Browse returns a filtered, paginated page over the full retained store, newest
// first, plus the total number of matching rows.
func (s *LogStore) Browse(ctx context.Context, p model.BrowseParams) (model.BrowsePage, error) {
	limit := p.Limit
	if limit <= 0 || limit > maxLogQueryLimit {
		limit = maxLogQueryLimit
	}

	offset := max(p.Offset, 0)

	qb := browseQuery(s.client.LogEvent.Query(), p)

	total, err := qb.Clone().Count(ctx)
	if err != nil {
		return model.BrowsePage{}, fmt.Errorf("count browse logs: %w", err)
	}

	rows, err := qb.
		Order(logevent.ByID(entsql.OrderDesc())).
		Offset(offset).
		Limit(limit).
		All(ctx)
	if err != nil {
		return model.BrowsePage{}, fmt.Errorf("browse logs: %w", err)
	}

	page := model.BrowsePage{Total: total, Rows: make([]model.LogEntry, 0, len(rows))}

	for _, r := range rows {
		var e model.LogEntry

		err = json.Unmarshal([]byte(r.Data), &e)
		if err != nil {
			return model.BrowsePage{}, fmt.Errorf("unmarshal browse log: %w", err)
		}

		e.ID = int64(r.ID)
		page.Rows = append(page.Rows, e)
	}

	return page, nil
}

// Clear removes all stored logs.
func (s *LogStore) Clear(ctx context.Context) error {
	_, err := s.client.LogEvent.Delete().Exec(ctx)
	if err != nil {
		return fmt.Errorf("clear logs: %w", err)
	}

	return nil
}

// prune drops the oldest rows beyond the retention cap. Best-effort.
func (s *LogStore) prune(ctx context.Context) {
	ids, err := s.client.LogEvent.Query().
		Order(logevent.ByID(entsql.OrderDesc())).
		Limit(1).
		IDs(ctx)
	if err != nil || len(ids) == 0 {
		return // best-effort; next prune retries
	}

	threshold := ids[0] - int(s.retention)

	_, err = s.client.LogEvent.Delete().Where(logevent.IDLTE(threshold)).Exec(ctx)
	if err != nil {
		return // best-effort; next prune retries
	}
}

func browseQuery(qb *ent.LogEventQuery, p model.BrowseParams) *ent.LogEventQuery {
	if !p.From.IsZero() {
		qb = qb.Where(logevent.TsGTE(p.From.UnixNano()))
	}

	if !p.To.IsZero() {
		qb = qb.Where(logevent.TsLTE(p.To.UnixNano()))
	}

	if q := strings.ToLower(strings.TrimSpace(p.Query)); q != "" {
		qb = qb.Where(searchLike(q))
	}

	// Match the JSON tokens exactly (with quotes) so a value never matches a
	// substring elsewhere: action "blocked" must not match the host
	// "blocked-malware.example", and component "http" must not match "https".
	if action := strings.ToLower(strings.TrimSpace(p.Action)); action != "" {
		qb = qb.Where(searchLike(`"action":"` + action + `"`))
	}

	if comp := strings.ToLower(strings.TrimSpace(p.Component)); comp != "" {
		qb = qb.Where(searchLike(`"component":"` + comp + `"`))
	}

	return qb
}

// searchLike matches user input literally against the search column, escaping
// LIKE wildcards so a "%" or "_" is not treated as a pattern.
func searchLike(q string) predicate.LogEvent {
	return func(sel *entsql.Selector) {
		sel.Where(entsql.ExprP(
			sel.C(logevent.FieldSearch)+` LIKE ? ESCAPE '\'`,
			"%"+likeEscape(q)+"%",
		))
	}
}

// likeEscape escapes LIKE wildcards so user input is matched literally.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

	return r.Replace(s)
}
