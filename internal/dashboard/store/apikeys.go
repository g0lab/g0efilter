package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/model"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent/apikey"
)

const (
	apiKeyPrefix    = "g0e_"
	apiKeyRandBytes = 32
	// prefix chars kept for display: "g0e_" + 8 hex chars.
	apiKeyDisplayPrefixLen = len(apiKeyPrefix) + 8
	// seeded env keys may be low-entropy; never store any part of them.
	envKeyDisplayPrefix = "(env)"

	touchInterval = time.Minute
)

// APIKeyStore is the SQLite-backed API key store. Active key hashes are
// cached in memory so the ingest hot path never hits the database.
type APIKeyStore struct {
	client *ent.Client
	lg     *slog.Logger

	mu        sync.RWMutex
	active    map[string][]byte // key ID -> sha256(key)
	lastTouch map[string]time.Time
}

// NewAPIKeyStore creates the store and loads the active-key cache.
func NewAPIKeyStore(ctx context.Context, client *ent.Client, lg *slog.Logger) (*APIKeyStore, error) {
	s := &APIKeyStore{
		client:    client,
		lg:        lg,
		active:    map[string][]byte{},
		lastTouch: map[string]time.Time{},
	}

	err := s.reload(ctx)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Validate reports whether the presented key matches an active key.
// Comparison is constant-time over the cached hashes; the database is only
// touched asynchronously to record last_used_at.
func (s *APIKeyStore) Validate(_ context.Context, presented string) (string, bool) {
	if presented == "" {
		return "", false
	}

	h := sha256.Sum256([]byte(presented))

	var matched string

	s.mu.RLock()

	for id, kh := range s.active {
		if subtle.ConstantTimeCompare(kh, h[:]) == 1 {
			matched = id
		}
	}

	s.mu.RUnlock()

	if matched == "" {
		return "", false
	}

	//nolint:contextcheck // async touch must outlive the request context
	s.touch(matched)

	return matched, true
}

// Create mints a new key, returning the plaintext exactly once.
func (s *APIKeyStore) Create(ctx context.Context, label string) (string, model.APIKey, error) {
	key := apiKeyPrefix + randomHex(apiKeyRandBytes)
	hash := sha256.Sum256([]byte(key))
	now := time.Now().UTC()

	rec := model.APIKey{
		ID:        randomHex(8),
		Label:     label,
		Prefix:    key[:apiKeyDisplayPrefixLen],
		CreatedAt: now,
	}

	err := s.client.APIKey.Create().
		SetID(rec.ID).
		SetLabel(rec.Label).
		SetKeyHash(hash[:]).
		SetKeyPrefix(rec.Prefix).
		SetCreatedAt(now.Unix()).
		Exec(ctx)
	if err != nil {
		return "", model.APIKey{}, fmt.Errorf("insert api key: %w", err)
	}

	err = s.reload(ctx)
	if err != nil {
		return "", model.APIKey{}, err
	}

	return key, rec, nil
}

// Seed idempotently inserts an externally supplied key (the API_KEY env
// bootstrap). If the key already exists - including revoked - it is left
// untouched, so a revocation in the database sticks across restarts.
func (s *APIKeyStore) Seed(ctx context.Context, label, key string) error {
	hash := sha256.Sum256([]byte(key))

	err := s.client.APIKey.Create().
		SetID(randomHex(8)).
		SetLabel(label).
		SetKeyHash(hash[:]).
		SetKeyPrefix(envKeyDisplayPrefix).
		SetCreatedAt(time.Now().Unix()).
		OnConflictColumns(apikey.FieldKeyHash).
		Ignore().
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("seed api key: %w", err)
	}

	return s.reload(ctx)
}

// List returns all keys, active and revoked.
func (s *APIKeyStore) List(ctx context.Context) ([]model.APIKey, error) {
	rows, err := s.client.APIKey.Query().
		Order(apikey.ByCreatedAt(), apikey.ByID()).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}

	out := make([]model.APIKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, model.APIKey{
			ID:         r.ID,
			Label:      r.Label,
			Prefix:     r.KeyPrefix,
			CreatedAt:  time.Unix(r.CreatedAt, 0).UTC(),
			LastUsedAt: nullableTime(r.LastUsedAt),
			RevokedAt:  nullableTime(r.RevokedAt),
		})
	}

	return out, nil
}

// Revoke marks a key revoked and drops it from the active cache.
func (s *APIKeyStore) Revoke(ctx context.Context, id string) error {
	n, err := s.client.APIKey.Update().
		Where(apikey.ID(id), apikey.RevokedAtIsNil()).
		SetRevokedAt(time.Now().Unix()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}

	if n == 0 {
		return model.ErrAPIKeyNotFound
	}

	return s.reload(ctx)
}

func (s *APIKeyStore) reload(ctx context.Context) error {
	rows, err := s.client.APIKey.Query().
		Where(apikey.RevokedAtIsNil()).
		Select(apikey.FieldID, apikey.FieldKeyHash).
		All(ctx)
	if err != nil {
		return fmt.Errorf("load api key cache: %w", err)
	}

	active := make(map[string][]byte, len(rows))
	for _, r := range rows {
		active[r.ID] = r.KeyHash
	}

	s.mu.Lock()
	s.active = active
	s.mu.Unlock()

	return nil
}

// touch records last_used_at asynchronously, at most once per touchInterval per key.
func (s *APIKeyStore) touch(id string) {
	now := time.Now()

	s.mu.Lock()

	last, seen := s.lastTouch[id]
	if seen && now.Sub(last) < touchInterval {
		s.mu.Unlock()

		return
	}

	s.lastTouch[id] = now
	s.mu.Unlock()

	go func() {
		ctx, cancel := opCtx()
		defer cancel()

		err := s.client.APIKey.Update().
			Where(apikey.ID(id)).
			SetLastUsedAt(now.Unix()).
			Exec(ctx)
		if err != nil {
			s.lg.Debug("store.apikeys.touch_failed", "id", id, "error", err.Error())
		}
	}()
}

func nullableTime(v *int64) *time.Time {
	if v == nil {
		return nil
	}

	t := time.Unix(*v, 0).UTC()

	return &t
}
