//nolint:testpackage // Need access to internal implementation details
package server

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestNewMemStoreMinimumCapacity(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -5} {
		s := newMemStore(n)
		if s.size != 1 {
			t.Errorf("newMemStore(%d) size = %d, want 1", n, s.size)
		}

		if len(s.buf) != 1 {
			t.Errorf("newMemStore(%d) buffer len = %d, want 1", n, len(s.buf))
		}
	}
}

func insertNumbered(t *testing.T, s *memStore, n int) {
	t.Helper()

	for i := 1; i <= n; i++ {
		entry := &LogEntry{
			Time:    time.Now().UTC(),
			Message: "entry-" + strconv.Itoa(i),
			Action:  testActionBlocked,
		}

		id, err := s.Insert(t.Context(), entry)
		if err != nil {
			t.Fatalf("Insert %d failed: %v", i, err)
		}

		if id != int64(i) {
			t.Fatalf("Insert %d returned id %d", i, id)
		}
	}
}

func TestMemStoreWrapEvictsOldest(t *testing.T) {
	t.Parallel()

	s := newMemStore(3)
	insertNumbered(t, s, 5)

	results, err := s.Query(t.Context(), "", 0, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Query returned %d results, want capacity 3", len(results))
	}

	// Newest first; entries 1 and 2 must have been overwritten.
	for i, wantID := range []int64{5, 4, 3} {
		if results[i].ID != wantID {
			t.Errorf("results[%d].ID = %d, want %d", i, results[i].ID, wantID)
		}

		wantMsg := "entry-" + strconv.FormatInt(wantID, 10)
		if results[i].Message != wantMsg {
			t.Errorf("results[%d].Message = %q, want %q", i, results[i].Message, wantMsg)
		}
	}
}

func TestMemStoreQueryLimitClamp(t *testing.T) {
	t.Parallel()

	s := newMemStore(10)
	insertNumbered(t, s, 10)

	for _, limit := range []int{0, -1, 6000} {
		results, err := s.Query(t.Context(), "", 0, limit)
		if err != nil {
			t.Fatalf("Query(limit=%d) failed: %v", limit, err)
		}

		if len(results) != 10 {
			t.Errorf("Query(limit=%d) returned %d results, want 10", limit, len(results))
		}
	}

	results, err := s.Query(t.Context(), "", 0, 2)
	if err != nil {
		t.Fatalf("Query(limit=2) failed: %v", err)
	}

	if len(results) != 2 || results[0].ID != 10 || results[1].ID != 9 {
		t.Errorf("Query(limit=2) = %+v, want newest two entries (10, 9)", results)
	}
}

func TestMemStoreQueryMatchesFieldsJSON(t *testing.T) {
	t.Parallel()

	s := newMemStore(4)

	entry := &LogEntry{
		Time:    time.Now().UTC(),
		Message: "dns query",
		Fields:  json.RawMessage(`{"qname":"Example.COM"}`),
	}

	_, err := s.Insert(t.Context(), entry)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Case-insensitive match against the raw fields JSON, not just the message.
	results, err := s.Query(t.Context(), "example.com", 0, 10)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("fields match returned %d results, want 1", len(results))
	}

	results, err = s.Query(t.Context(), "no-such-token", 0, 10)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("non-matching query returned %d results, want 0", len(results))
	}
}

func TestMemStoreQuerySinceIDAfterWrap(t *testing.T) {
	t.Parallel()

	s := newMemStore(3)
	insertNumbered(t, s, 5)

	results, err := s.Query(t.Context(), "", 4, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 1 || results[0].ID != 5 {
		t.Fatalf("Query(sinceID=4) = %+v, want only entry 5", results)
	}

	results, err = s.Query(t.Context(), "", 5, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Query(sinceID=5) returned %d results, want 0", len(results))
	}
}

func TestMemStoreClearResetsIDsAndCount(t *testing.T) {
	t.Parallel()

	s := newMemStore(3)
	insertNumbered(t, s, 5)

	err := s.Clear(t.Context())
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	results, err := s.Query(t.Context(), "", 0, 100)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Query after Clear returned %d results, want 0", len(results))
	}

	// ID sequence restarts from 1 after Clear.
	id, err := s.Insert(t.Context(), &LogEntry{Time: time.Now().UTC(), Message: "fresh"})
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	if id != 1 {
		t.Fatalf("first insert after Clear got id %d, want 1", id)
	}
}
