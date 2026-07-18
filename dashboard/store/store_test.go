package store_test

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/dashboard/store"
	"github.com/g0lab/g0efilter/dashboard/store/ent"
	"golang.org/x/crypto/bcrypt"
)

func testDB(t *testing.T) (*ent.Client, *sql.DB) {
	t.Helper()

	client, db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = client.Close() })

	err = store.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	return client, db
}

// TestMigrate_EmptyDatabase applies every migration to a fresh database.
func TestMigrate_EmptyDatabase(t *testing.T) {
	t.Parallel()

	_, db := testDB(t)

	// Re-running must be a no-op, not an error.
	err := store.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	for _, table := range []string{
		"unblock_requests", "completed_unblocks", "api_keys", "users", "sessions",
		"logs", "fleet_groups", "fleet_instances",
	} {
		var n int

		err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

//nolint:cyclop // sequential scenario test
func TestUnblockStore_SQLite(t *testing.T) {
	t.Parallel()

	client, _ := testDB(t)
	s := store.NewUnblockStore(client, slog.New(slog.DiscardHandler))

	id := s.Add("domain", "example.com", "Host-1")
	if id == "" {
		t.Fatal("Add returned empty id")
	}

	// Dedupe returns the same id (case-insensitive target).
	if again := s.Add("domain", "example.com", "host-1"); again != id {
		t.Errorf("dedupe id = %q, want %q", again, id)
	}

	pending := s.GetPending()
	if len(pending) != 1 || pending[0].TargetHostname != "host-1" {
		t.Fatalf("pending = %+v, want 1 with lowered hostname", pending)
	}

	// Host scoping: host-1 sees it, host-2 does not; global requests reach all.
	if got := s.GetPendingForHost("HOST-1"); len(got) != 1 {
		t.Errorf("host-1 pending = %d, want 1", len(got))
	}

	if got := s.GetPendingForHost("host-2"); len(got) != 0 {
		t.Errorf("host-2 pending = %d, want 0", len(got))
	}

	globalID := s.Add("ip", "10.0.0.1", "")
	if got := s.GetPendingForHost("host-2"); len(got) != 1 || got[0].ID != globalID {
		t.Errorf("host-2 should see the global request")
	}

	// Ack moves to completed.
	if !s.Acknowledge(id) {
		t.Fatal("Acknowledge = false")
	}

	if s.Acknowledge(id) {
		t.Error("second Acknowledge should be false")
	}

	completed := s.GetCompleted()
	if len(completed) != 1 || completed[0].Value != "example.com" {
		t.Fatalf("completed = %+v", completed)
	}

	if len(s.GetPending()) != 1 {
		t.Errorf("pending after ack = %d, want 1 (the global one)", len(s.GetPending()))
	}
}

//nolint:cyclop,funlen // sequential scenario test
func TestAPIKeyStore_SQLite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client, _ := testDB(t)
	lg := slog.New(slog.DiscardHandler)

	s, err := store.NewAPIKeyStore(ctx, client, lg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	key, rec, err := s.Create(ctx, "ci")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if len(key) < 20 || key[:4] != "g0e_" {
		t.Fatalf("key format: %q", key)
	}

	if id, ok := s.Validate(ctx, key); !ok || id != rec.ID {
		t.Fatalf("Validate = %q %v, want %q true", id, ok, rec.ID)
	}

	if _, ok := s.Validate(ctx, "g0e_wrong"); ok {
		t.Fatal("wrong key validated")
	}

	if _, ok := s.Validate(ctx, ""); ok {
		t.Fatal("empty key validated")
	}

	// Revoke drops it, and the cache survives a store reopen.
	err = s.Revoke(ctx, rec.ID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, ok := s.Validate(ctx, key); ok {
		t.Fatal("revoked key validated")
	}

	// Seeding an already-revoked key must not resurrect it.
	err = s.Seed(ctx, "env-bootstrap", key)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, ok := s.Validate(ctx, key); ok {
		t.Fatal("seed resurrected a revoked key")
	}

	// Fresh seed works and is idempotent.
	err = s.Seed(ctx, "env-bootstrap", "env-secret")
	if err != nil {
		t.Fatalf("seed2: %v", err)
	}

	err = s.Seed(ctx, "env-bootstrap", "env-secret")
	if err != nil {
		t.Fatalf("seed3: %v", err)
	}

	if _, ok := s.Validate(ctx, "env-secret"); !ok {
		t.Fatal("seeded env key rejected")
	}

	keys, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	// One revoked generated key + one seeded env key.
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}

	for _, k := range keys {
		if k.Label == "env-bootstrap" && k.Prefix != "(env)" {
			t.Errorf("env key prefix leaked: %q", k.Prefix)
		}
	}
}

//nolint:cyclop,funlen // sequential scenario test
func TestSessionAndUserStore_SQLite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client, db := testDB(t)
	lg := slog.New(slog.DiscardHandler)

	users := store.NewUserStore(client, lg)
	sessions := store.NewSessionStore(client, lg)

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)

	err := users.Upsert(ctx, "admin", string(hash))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Upsert again (password rotation) keeps a single user.
	hash2, _ := bcrypt.GenerateFromPassword([]byte("pw2"), bcrypt.MinCost)

	err = users.Upsert(ctx, "admin", string(hash2))
	if err != nil {
		t.Fatalf("upsert2: %v", err)
	}

	n, err := users.Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d %v, want 1", n, err)
	}

	if _, ok := users.VerifyPassword(ctx, "admin", "pw"); ok {
		t.Fatal("old password accepted after rotation")
	}

	user, ok := users.VerifyPassword(ctx, "ADMIN", "pw2") // COLLATE NOCASE
	if !ok {
		t.Fatal("valid credentials rejected")
	}

	if _, ok := users.VerifyPassword(ctx, "ghost", "pw2"); ok {
		t.Fatal("unknown user accepted")
	}

	// Session round trip.
	token, err := sessions.Create(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	sess, ok := sessions.Lookup(ctx, token)
	if !ok || sess.Username != "admin" {
		t.Fatalf("lookup = %+v %v", sess, ok)
	}

	if _, ok := sessions.Lookup(ctx, "not-a-token"); ok {
		t.Fatal("bogus token accepted")
	}

	err = sessions.Revoke(ctx, token)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, ok := sessions.Lookup(ctx, token); ok {
		t.Fatal("revoked session accepted")
	}

	// Expired sessions are rejected and GC'd.
	token, err = sessions.Create(ctx, user, -time.Minute)
	if err != nil {
		t.Fatalf("create expired: %v", err)
	}

	if _, ok := sessions.Lookup(ctx, token); ok {
		t.Fatal("expired session accepted")
	}

	err = sessions.GC(ctx)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}

	var left int

	err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sessions`).Scan(&left)
	if err != nil || left != 0 {
		t.Fatalf("sessions after gc = %d %v, want 0", left, err)
	}
}

// TestPersistenceAcrossReopen simulates a restart: state written through one
// handle is visible through a fresh one.
//
//nolint:cyclop // sequential scenario test
func TestPersistenceAcrossReopen(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reopen.db")
	lg := slog.New(slog.DiscardHandler)

	client, db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = store.Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ak, err := store.NewAPIKeyStore(ctx, client, lg)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	key, _, err := ak.Create(ctx, "persist")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	id := store.NewUnblockStore(client, lg).Add("ip", "10.1.1.1", "")
	if id == "" {
		t.Fatal("unblock add failed")
	}

	_ = client.Close()

	client2, db2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	defer func() { _ = client2.Close() }()

	err = store.Migrate(ctx, db2)
	if err != nil {
		t.Fatalf("re-migrate: %v", err)
	}

	ak2, err := store.NewAPIKeyStore(ctx, client2, lg)
	if err != nil {
		t.Fatalf("keys2: %v", err)
	}

	if _, ok := ak2.Validate(ctx, key); !ok {
		t.Fatal("api key lost across reopen")
	}

	if got := store.NewUnblockStore(client2, lg).GetPending(); len(got) != 1 || got[0].ID != id {
		t.Fatalf("unblocks lost across reopen: %+v", got)
	}
}
