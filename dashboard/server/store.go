package server

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/g0lab/g0efilter/shared/logging"
)

type memStore struct {
	mu     sync.RWMutex
	buf    []LogEntry
	head   int // next write position
	size   int // capacity
	count  int // number of valid records currently in buffer
	nextID int64
}

// newMemStore creates a new in-memory circular buffer log store with the specified capacity.
func newMemStore(n int) *memStore {
	if n < 1 {
		n = 1
	}

	return &memStore{
		buf:    make([]LogEntry, n),
		size:   n,
		nextID: 1,
	}
}

func (s *memStore) Insert(ctx context.Context, e *LogEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID
	s.nextID++

	e.ID = id
	s.buf[s.head] = *e
	s.head = (s.head + 1) % s.size

	if s.count < s.size {
		s.count++
	}

	slog.Log(ctx, logging.LevelTrace, "store.insert",
		"id", id,
		"count", s.count,
		"capacity", s.size,
	)

	return id, nil
}

func (s *memStore) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.head = 0
	s.count = 0
	s.nextID = 1

	return nil
}

// Query returns log entries matching the query string and ID filter, sorted by ID descending.
func (s *memStore) Query(_ context.Context, q string, sinceID int64, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}

	q = strings.ToLower(strings.TrimSpace(q))

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]LogEntry, 0, limit)
	if s.count == 0 {
		return out, nil
	}

	idx := (s.head - 1 + s.size) % s.size
	seen := 0

	for seen < s.count && len(out) < limit {
		it := s.buf[idx]

		if s.shouldSkipEntry(it, q, sinceID) {
			seen++
			idx = s.prevIndex(idx)

			continue
		}

		out = append(out, it)
		seen++
		idx = s.prevIndex(idx)
	}

	return out, nil
}

func (s *memStore) shouldSkipEntry(entry LogEntry, q string, sinceID int64) bool {
	if sinceID > 0 && entry.ID <= sinceID {
		return true
	}

	// Query filter (q is already lowered by caller)
	if q != "" {
		hay := strings.ToLower(strings.Join([]string{
			entry.Message,
			string(entry.Fields),
		}, " "))
		if !strings.Contains(hay, q) {
			return true
		}
	}

	return false
}

func (s *memStore) prevIndex(idx int) int {
	if idx == 0 {
		return s.size - 1
	}

	return idx - 1
}
