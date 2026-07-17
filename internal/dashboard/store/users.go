package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/model"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent/user"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is compared against when a username is unknown so login
// timing does not reveal whether an account exists.
//
//nolint:gochecknoglobals // fixed dummy hash, computed once
var dummyBcryptHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte(randomHex(16)), bcrypt.DefaultCost)

	return h
}()

// UserStore is the SQLite-backed user store.
type UserStore struct {
	client *ent.Client
	lg     *slog.Logger
}

// NewUserStore creates a SQLite-backed user store.
func NewUserStore(client *ent.Client, lg *slog.Logger) *UserStore {
	return &UserStore{client: client, lg: lg}
}

// VerifyPassword checks credentials, with uniform timing for unknown users.
func (s *UserStore) VerifyPassword(ctx context.Context, username, password string) (model.User, bool) {
	row, err := s.client.User.Query().Where(user.Username(normalizeUsername(username))).Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			s.lg.Error("store.users.get_failed", "error", err.Error())
		}

		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))

		return model.User{}, false
	}

	err = bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password))
	if err != nil {
		return model.User{}, false
	}

	return model.User{
		ID:        row.ID,
		Username:  row.Username,
		CreatedAt: time.Unix(row.CreatedAt, 0).UTC(),
	}, true
}

// Upsert inserts the user or updates the password hash for an existing username.
func (s *UserStore) Upsert(ctx context.Context, username, passwordHash string) error {
	err := s.client.User.Create().
		SetID(randomHex(8)).
		SetUsername(normalizeUsername(username)).
		SetPasswordHash(passwordHash).
		SetCreatedAt(time.Now().Unix()).
		OnConflictColumns(user.FieldUsername).
		Update(func(u *ent.UserUpsert) {
			u.SetPasswordHash(passwordHash)
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}

	return nil
}

// Count returns the number of users.
func (s *UserStore) Count(ctx context.Context) (int64, error) {
	n, err := s.client.User.Query().Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}

	return int64(n), nil
}

// normalizeUsername enforces case-insensitive username semantics at the app
// layer (the column has a plain unique index, not a DB collation).
func normalizeUsername(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
