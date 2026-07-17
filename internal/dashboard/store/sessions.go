package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/model"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent/session"
)

const sessionTokenBytes = 32

// SessionStore is the SQLite-backed session store. Only the SHA-256 of each
// token is persisted, so a database read cannot hijack live sessions.
type SessionStore struct {
	client *ent.Client
	lg     *slog.Logger
}

// NewSessionStore creates a SQLite-backed session store.
func NewSessionStore(client *ent.Client, lg *slog.Logger) *SessionStore {
	return &SessionStore{client: client, lg: lg}
}

// Create mints a session for the user and returns the opaque token.
func (s *SessionStore) Create(ctx context.Context, user model.User, ttl time.Duration) (string, error) {
	raw := make([]byte, sessionTokenBytes)
	_, _ = rand.Read(raw) // crypto/rand.Read never errors on Linux (Go 1.20+)

	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()

	err := s.client.Session.Create().
		SetTokenHash(hash[:]).
		SetUserID(user.ID).
		SetCreatedAt(now.Unix()).
		SetExpiresAt(now.Add(ttl).Unix()).
		Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}

	return token, nil
}

// Lookup resolves a token to its session, if valid and unexpired.
func (s *SessionStore) Lookup(ctx context.Context, token string) (model.Session, bool) {
	if token == "" {
		return model.Session{}, false
	}

	hash := sha256.Sum256([]byte(token))

	row, err := s.client.Session.Query().
		Where(session.TokenHash(hash[:]), session.ExpiresAtGT(time.Now().Unix())).
		WithOwner().
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			s.lg.Error("store.sessions.lookup_failed", "error", err.Error())
		}

		return model.Session{}, false
	}

	username := ""
	if row.Edges.Owner != nil {
		username = row.Edges.Owner.Username
	}

	return model.Session{
		UserID:    row.UserID,
		Username:  username,
		CreatedAt: time.Unix(row.CreatedAt, 0).UTC(),
		ExpiresAt: time.Unix(row.ExpiresAt, 0).UTC(),
	}, true
}

// Revoke deletes the session for the given token.
func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))

	_, err := s.client.Session.Delete().Where(session.TokenHash(hash[:])).Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// GC prunes expired sessions.
func (s *SessionStore) GC(ctx context.Context) error {
	_, err := s.client.Session.Delete().
		Where(session.ExpiresAtLTE(time.Now().Unix())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("gc sessions: %w", err)
	}

	return nil
}
