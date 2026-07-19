package server

import (
	"context"
	"net/http"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
)

// Domain type aliases so handlers keep short names while implementations
// live behind the model leaf package.
type (
	// APIKey describes a machine credential.
	APIKey = model.APIKey
	// Session is an authenticated browser session.
	Session = model.Session
	// User is a dashboard login.
	User = model.User
)

// LogStore defines the interface for log storage backends.
type LogStore interface {
	Insert(ctx context.Context, e *LogEntry) (int64, error)
	Query(ctx context.Context, q string, sinceID int64, limit int) ([]LogEntry, error)
	Aggregate(ctx context.Context, from, to time.Time, q string, buckets int) (model.AggregateResult, error)
	Clear(ctx context.Context) error
}

// APIKeyStore validates and manages machine API keys. Keys are stored hashed;
// Create returns the plaintext exactly once.
type APIKeyStore interface {
	Validate(ctx context.Context, presented string) (keyID string, ok bool)
	List(ctx context.Context) ([]APIKey, error)
	Create(ctx context.Context, label string) (plaintext string, key APIKey, err error)
	Revoke(ctx context.Context, id string) error
}

// SessionStore manages browser sessions. Tokens are opaque and stored hashed.
type SessionStore interface {
	Create(ctx context.Context, user User, ttl time.Duration) (token string, err error)
	Lookup(ctx context.Context, token string) (Session, bool)
	Revoke(ctx context.Context, token string) error
	GC(ctx context.Context) error
}

// UserStore verifies and manages dashboard logins.
type UserStore interface {
	VerifyPassword(ctx context.Context, username, password string) (User, bool)
	Upsert(ctx context.Context, username, passwordHash string) error
	Count(ctx context.Context) (int64, error)
}

// Authenticator is the AUTH_MODE strategy guarding browser-facing routes.
type Authenticator interface {
	// Authenticate returns the request principal ("" plus false when
	// unauthenticated). Middleware enforcement is built on top of this.
	Authenticate(r *http.Request) (principal string, ok bool)
}

// FleetStore manages the instance/group control plane.
type FleetStore interface {
	// Reconcile records an instance's report and returns its desired config.
	Reconcile(ctx context.Context, rep model.SyncReport) (model.DesiredConfig, error)
	ListInstances(ctx context.Context) ([]model.Instance, error)
	DeleteInstance(ctx context.Context, id string) error
	SetInstanceGroup(ctx context.Context, id, groupID string) error
	SetInstancePolicy(ctx context.Context, id string, policy *string) error
	ListGroups(ctx context.Context) ([]model.Group, error)
	CreateGroup(ctx context.Context, name string) (model.Group, error)
	DeleteGroup(ctx context.Context, id string) error
	SetGroupPolicy(ctx context.Context, id, policy, filterMode string) error
}

// EventBroadcaster broadcasts live events and invalidations to SSE clients.
type EventBroadcaster interface {
	Add() chan []byte
	Remove(ch chan []byte)
	Send(p []byte)
}

// RateLimiter defines the interface for rate limiting strategies.
type RateLimiter interface {
	Allow(key string) bool
}
