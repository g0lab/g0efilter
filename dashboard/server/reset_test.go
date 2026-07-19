//nolint:testpackage // exercises unexported dashboard CLI commands
package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/dashboard/store"
	"golang.org/x/crypto/bcrypt"
)

//nolint:cyclop,wsl_v5 // sequential credential rotation scenario
func TestHandleResetPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reset.db")
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("EPHEMERAL", "false")
	t.Setenv("ADMIN_USERNAME", "admin")

	ctx := context.Background()
	lg := slog.New(slog.DiscardHandler)
	client, db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = store.Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash old password: %v", err)
	}

	err = store.NewUserStore(client, lg).Upsert(ctx, "admin", string(oldHash))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = client.Close()

	var out bytes.Buffer
	done, err := handleResetPasswordWithWriter(
		[]string{"g0efilter-dashboard", "reset-password", "admin"}, &out)
	if !done || err != nil {
		t.Fatalf("reset-password: done=%v err=%v", done, err)
	}

	newPassword := lastOutputLine(out.String())
	if newPassword == "" || newPassword == "old-pw" {
		t.Fatalf("invalid generated password in output: %q", out.String())
	}

	client, _, err = store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = client.Close() }()

	users := store.NewUserStore(client, lg)
	if _, ok := users.VerifyPassword(ctx, "admin", "old-pw"); ok {
		t.Fatal("old password still valid after reset")
	}
	if _, ok := users.VerifyPassword(ctx, "admin", newPassword); !ok {
		t.Fatal("printed replacement password does not authenticate")
	}
	if n, _ := users.Count(ctx); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}

func TestHandleResetPassword_CustomUsername(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reset-custom.db")
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("EPHEMERAL", "false")
	t.Setenv("ADMIN_USERNAME", "custom-admin")

	var out bytes.Buffer

	done, err := handleResetPasswordWithWriter(
		[]string{"g0efilter-dashboard", "reset-password"}, &out)
	if !done || err != nil {
		t.Fatalf("reset-password: done=%v err=%v", done, err)
	}

	client, _, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = client.Close() }()

	users := store.NewUserStore(client, slog.New(slog.DiscardHandler))
	if _, ok := users.VerifyPassword(context.Background(), "custom-admin", lastOutputLine(out.String())); !ok {
		t.Fatal("printed password does not authenticate custom admin")
	}
}

func TestHandleResetPassword_RequiresDB(t *testing.T) {
	t.Setenv("EPHEMERAL", "true")

	done, err := handleResetPasswordWithWriter(
		[]string{"g0efilter-dashboard", "reset-password"}, &bytes.Buffer{})
	if !done || !errors.Is(err, errResetPasswordNeedsDB) {
		t.Fatalf("want errResetPasswordNeedsDB, got done=%v err=%v", done, err)
	}
}

func TestHashPassword(t *testing.T) {
	t.Parallel()

	const password = "test-password-123"

	hash, err := hashPassword(strings.NewReader(password + "\n"))
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		t.Fatalf("printed hash does not verify: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-pw"))
	if err == nil {
		t.Fatal("wrong password verified against hash")
	}
}

func TestHashPassword_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := hashPassword(strings.NewReader(""))
	if !errors.Is(err, errEmptyPassword) {
		t.Fatalf("want errEmptyPassword, got %v", err)
	}
}

func lastOutputLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")

	return strings.TrimSpace(lines[len(lines)-1])
}
