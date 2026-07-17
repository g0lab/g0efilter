package server

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
)

// UnblockRequest represents a pending request to remove a block rule.
type UnblockRequest = model.UnblockRequest

// CompletedUnblock records an unblock operation that has been acknowledged and applied.
type CompletedUnblock = model.CompletedUnblock

// UnblockStore manages pending unblock requests with thread-safe operations.
type UnblockStore interface {
	Add(reqType, value, targetHostname string) string
	GetPending() []UnblockRequest
	GetPendingForHost(hostname string) []UnblockRequest
	Acknowledge(id string) bool
	GetCompleted() []CompletedUnblock
}

type memUnblockStore struct {
	mu         sync.RWMutex
	requests   map[string]UnblockRequest
	completed  []CompletedUnblock
	maxPending int
}

func newUnblockStore() *memUnblockStore {
	return &memUnblockStore{
		requests:   make(map[string]UnblockRequest),
		completed:  make([]CompletedUnblock, 0),
		maxPending: 1000,
	}
}

func (s *memUnblockStore) Add(reqType, value, targetHostname string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetHostname = strings.ToLower(strings.TrimSpace(targetHostname))

	for _, req := range s.requests {
		if req.Type == reqType && req.Value == value && req.TargetHostname == targetHostname {
			return req.ID
		}
	}

	if len(s.requests) >= s.maxPending {
		return ""
	}

	id := generateID()

	s.requests[id] = UnblockRequest{
		ID:             id,
		Type:           reqType,
		Value:          value,
		TargetHostname: targetHostname,
		CreatedAt:      time.Now().UTC(),
	}

	return id
}

func (s *memUnblockStore) GetPending() []UnblockRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]UnblockRequest, 0, len(s.requests))
	for _, req := range s.requests {
		result = append(result, req)
	}

	return result
}

// GetPendingForHost returns pending requests matching a specific hostname.
// Returns requests where TargetHostname is empty (all hosts) or matches the given hostname.
func (s *memUnblockStore) GetPendingForHost(hostname string) []UnblockRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hostname = strings.ToLower(strings.TrimSpace(hostname))

	result := make([]UnblockRequest, 0, len(s.requests))
	for _, req := range s.requests {
		if req.TargetHostname == "" || req.TargetHostname == hostname {
			result = append(result, req)
		}
	}

	return result
}

func (s *memUnblockStore) Acknowledge(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[id]
	if exists {
		s.completed = append(s.completed, CompletedUnblock{
			Type:           req.Type,
			Value:          req.Value,
			TargetHostname: req.TargetHostname,
			CompletedAt:    time.Now().UTC(),
		})
		delete(s.requests, id)

		// Keep completed list bounded (last 100 entries)
		const maxCompleted = 100
		if len(s.completed) > maxCompleted {
			s.completed = s.completed[len(s.completed)-maxCompleted:]
		}

		return true
	}

	return false
}

func (s *memUnblockStore) GetCompleted() []CompletedUnblock {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]CompletedUnblock, len(s.completed))
	copy(result, s.completed)

	return result
}

// generateID creates a cryptographically random 16-character hex ID for an unblock request.
func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never errors on Linux (Go 1.20+)

	return hex.EncodeToString(b)
}
