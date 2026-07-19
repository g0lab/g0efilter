//nolint:testpackage // verifies concrete startup wiring
package server

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/dashboard/store"
)

var generatedAPIKeyPattern = regexp.MustCompile(`g0e_[0-9a-f]{64}`)

//nolint:cyclop,wsl_v5 // sequential restart and persistence scenario
func TestPersistentAPIKeyWiringAndEnvSeedLogOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := Config{DBPath: filepath.Join(t.TempDir(), "dashboard.db"), APIKey: "env-secret"}

	srv := newServer(lg, cfg)
	closeStores, err := srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("wire stores: %v", err)
	}
	if _, ok := srv.apiKeys.(*store.APIKeyStore); !ok {
		t.Fatalf("api key store = %T, want SQLite store", srv.apiKeys)
	}
	if _, ok := srv.apiKeys.Validate(ctx, cfg.APIKey); !ok {
		t.Fatal("seeded environment key does not validate")
	}
	persistedKey, _, err := srv.apiKeys.Create(ctx, "created-in-dashboard")
	if err != nil {
		t.Fatalf("create persisted key: %v", err)
	}
	closeStores()

	srv = newServer(lg, cfg)
	closeStores, err = srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("rewire stores: %v", err)
	}
	if _, ok := srv.apiKeys.Validate(ctx, persistedKey); !ok {
		t.Fatal("dashboard-created key did not survive restart")
	}
	closeStores()

	if got := strings.Count(logs.String(), "dashboard.api_key_seeded"); got != 1 {
		t.Fatalf("api key seed logs = %d, want 1\n%s", got, logs.String())
	}
	if strings.Contains(logs.String(), cfg.APIKey) {
		t.Fatal("operator-supplied API key leaked into startup logs")
	}

	// Once a database key exists, API_KEY can be removed from the environment.
	cfg.APIKey = ""
	srv = newServer(lg, cfg)
	closeStores, err = srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("wire without env key: %v", err)
	}
	defer closeStores()
	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ensure persisted key: %v", err)
	}
	if _, ok := srv.apiKeys.Validate(ctx, persistedKey); !ok {
		t.Fatal("persisted key does not validate without API_KEY")
	}
}

//nolint:cyclop,funlen,wsl_v5 // sequential restart and revocation scenario
func TestGeneratedAPIKeyIsLoggedOnceAndRevocationAllowsUIRecovery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := Config{DBPath: filepath.Join(t.TempDir(), "dashboard.db")}

	srv := newServer(lg, cfg)
	closeStores, err := srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("wire stores: %v", err)
	}
	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	generated := generatedAPIKeyPattern.FindString(logs.String())
	if generated == "" {
		t.Fatalf("generated API key missing from bootstrap log:\n%s", logs.String())
	}
	if _, ok := srv.apiKeys.Validate(ctx, generated); !ok {
		t.Fatal("logged generated API key does not validate")
	}
	closeStores()

	srv = newServer(lg, cfg)
	closeStores, err = srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("rewire stores: %v", err)
	}
	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ensure after restart: %v", err)
	}
	if got := strings.Count(logs.String(), "dashboard.api_key_generated"); got != 1 {
		t.Fatalf("generated key logs = %d, want 1\n%s", got, logs.String())
	}

	keys, err := srv.apiKeys.List(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("list keys = %v, err=%v", keys, err)
	}
	err = srv.apiKeys.Revoke(ctx, keys[0].ID)
	if err != nil {
		t.Fatalf("revoke generated key: %v", err)
	}
	closeStores()

	srv = newServer(lg, cfg)
	closeStores, err = srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("wire after revocation: %v", err)
	}
	defer closeStores()
	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ensure after revocation: %v", err)
	}
	if got := strings.Count(logs.String(), "dashboard.api_key_generated"); got != 1 {
		t.Fatalf("revocation caused regeneration; log count = %d", got)
	}
	if got := strings.Count(logs.String(), "dashboard.no_active_api_keys"); got != 1 {
		t.Fatalf("no-active-key warnings = %d, want 1", got)
	}

	replacement, _, err := srv.apiKeys.Create(ctx, "created-in-dashboard")
	if err != nil {
		t.Fatalf("create replacement key: %v", err)
	}
	if _, ok := srv.apiKeys.Validate(ctx, replacement); !ok {
		t.Fatal("replacement key created through dashboard store does not validate")
	}
}

//nolint:wsl_v5 // keeps setup values together
func TestEphemeralDashboardGeneratesAPIKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := Config{}
	srv := newServer(lg, cfg)

	closeStores, err := srv.wireStores(ctx, cfg)
	if err != nil {
		t.Fatalf("wire stores: %v", err)
	}
	defer closeStores()
	err = srv.ensureAPIKeys(ctx)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}

	generated := generatedAPIKeyPattern.FindString(logs.String())
	if generated == "" {
		t.Fatalf("generated API key missing from log:\n%s", logs.String())
	}
	if _, ok := srv.apiKeys.Validate(ctx, generated); !ok {
		t.Fatal("logged ephemeral key does not validate")
	}
}
