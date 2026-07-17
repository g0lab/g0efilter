package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
	"golang.org/x/crypto/bcrypt"
)

// In-memory implementations used when no DB_PATH is configured (explicitly
// non-persistent mode) and in tests. Semantics mirror the SQLite stores.

type memAPIKey struct {
	rec  APIKey
	hash []byte
}

type memAPIKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*memAPIKey
}

// newMemAPIKeyStore seeds the store with the env-provided key, if any.
func newMemAPIKeyStore(envKey string) *memAPIKeyStore {
	s := &memAPIKeyStore{keys: map[string]*memAPIKey{}}

	if envKey != "" {
		h := sha256.Sum256([]byte(envKey))
		id := randomHexID()
		s.keys[id] = &memAPIKey{
			rec: APIKey{
				ID:        id,
				Label:     "env-bootstrap",
				Prefix:    "(env)",
				CreatedAt: time.Now().UTC(),
			},
			hash: h[:],
		}
	}

	return s
}

func (s *memAPIKeyStore) Validate(_ context.Context, presented string) (string, bool) {
	if presented == "" {
		return "", false
	}

	h := sha256.Sum256([]byte(presented))

	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched string

	for id, k := range s.keys {
		if k.rec.RevokedAt == nil && subtle.ConstantTimeCompare(k.hash, h[:]) == 1 {
			matched = id
		}
	}

	return matched, matched != ""
}

func (s *memAPIKeyStore) List(_ context.Context) ([]APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]APIKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.rec)
	}

	return out, nil
}

func (s *memAPIKeyStore) Create(_ context.Context, label string) (string, APIKey, error) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)

	key := "g0e_" + hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(key))

	rec := APIKey{
		ID:        randomHexID(),
		Label:     label,
		Prefix:    key[:12],
		CreatedAt: time.Now().UTC(),
	}

	s.mu.Lock()
	s.keys[rec.ID] = &memAPIKey{rec: rec, hash: h[:]}
	s.mu.Unlock()

	return key, rec, nil
}

func (s *memAPIKeyStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.keys[id]
	if !ok || k.rec.RevokedAt != nil {
		return model.ErrAPIKeyNotFound
	}

	now := time.Now().UTC()
	k.rec.RevokedAt = &now

	return nil
}

type memSessionStore struct {
	mu       sync.RWMutex
	sessions map[[32]byte]Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: map[[32]byte]Session{}}
}

func (s *memSessionStore) Create(_ context.Context, user User, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)

	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now().UTC()

	s.mu.Lock()
	s.sessions[sha256.Sum256([]byte(token))] = Session{
		UserID:    user.ID,
		Username:  user.Username,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	s.mu.Unlock()

	return token, nil
}

func (s *memSessionStore) Lookup(_ context.Context, token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}

	key := sha256.Sum256([]byte(token))

	s.mu.RLock()
	sess, ok := s.sessions[key]
	s.mu.RUnlock()

	if !ok || time.Now().After(sess.ExpiresAt) {
		return Session{}, false
	}

	return sess, true
}

func (s *memSessionStore) Revoke(_ context.Context, token string) error {
	key := sha256.Sum256([]byte(token))

	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()

	return nil
}

func (s *memSessionStore) GC(_ context.Context) error {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, k)
		}
	}

	return nil
}

//nolint:gochecknoglobals // fixed dummy hash for uniform login timing
var memDummyBcryptHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte(randomHexID()), bcrypt.DefaultCost)

	return h
}()

type memUserStore struct {
	mu    sync.RWMutex
	users map[string]User // lowercased username -> user (with hash)
}

func newMemUserStore() *memUserStore {
	return &memUserStore{users: map[string]User{}}
}

func (s *memUserStore) VerifyPassword(_ context.Context, username, password string) (User, bool) {
	s.mu.RLock()
	u, ok := s.users[normalizeUsername(username)]
	s.mu.RUnlock()

	if !ok {
		_ = bcrypt.CompareHashAndPassword(memDummyBcryptHash, []byte(password))

		return User{}, false
	}

	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	if err != nil {
		return User{}, false
	}

	u.PasswordHash = ""

	return u, true
}

func (s *memUserStore) Upsert(_ context.Context, username, passwordHash string) error {
	key := normalizeUsername(username)

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[key]
	if !ok {
		u = User{ID: randomHexID(), Username: username, CreatedAt: time.Now().UTC()}
	}

	u.PasswordHash = passwordHash
	s.users[key] = u

	return nil
}

func (s *memUserStore) Count(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return int64(len(s.users)), nil
}

// normalizeUsername matches the sqlite store's COLLATE NOCASE username semantics.
func normalizeUsername(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func randomHexID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}
