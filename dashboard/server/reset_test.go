//nolint:testpackage // exercises the unexported reset-password subcommand
package server

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/g0lab/g0efilter/dashboard/store"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleResetPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "reset.db")
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("ADMIN_USERNAME", "admin")

	ctx := context.Background()
	lg := slog.New(slog.DiscardHandler)

	// Seed an admin with a known password.
	client, db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = store.Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldHash, _ := bcrypt.GenerateFromPassword([]byte("old-pw"), bcrypt.MinCost)

	err = store.NewUserStore(client, lg).Upsert(ctx, "admin", string(oldHash))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	_ = client.Close()

	// Reset rotates the credential.
	done, err := handleResetPassword([]string{"g0efilter-dashboard", "reset-password", "admin"})
	if !done || err != nil {
		t.Fatalf("reset-password: done=%v err=%v", done, err)
	}

	client2, _, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	defer func() { _ = client2.Close() }()

	users := store.NewUserStore(client2, lg)

	if _, ok := users.VerifyPassword(ctx, "admin", "old-pw"); ok {
		t.Fatal("old password still valid after reset")
	}

	if n, _ := users.Count(ctx); n != 1 {
		t.Fatalf("users = %d, want 1 (reset must not duplicate)", n)
	}
}

func TestHandleResetPassword_RequiresDB(t *testing.T) {
	t.Setenv("DB_PATH", "")

	done, err := handleResetPassword([]string{"g0efilter-dashboard", "reset-password"})
	if !done || !errors.Is(err, errResetNeedsDB) {
		t.Fatalf("want errResetNeedsDB, got done=%v err=%v", done, err)
	}
}
