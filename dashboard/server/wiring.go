package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/g0lab/g0efilter/dashboard/store"
)

var errFleetNeedsDB = errors.New("FLEET_ENABLED requires persistent storage")

// wireStores swaps the in-memory defaults for SQLite-backed stores when
// DBPath is configured. Migrations are applied before returning, so a
// failure here must abort startup. The returned func closes the database.
func (s *Server) wireStores(ctx context.Context, cfg Config) (func(), error) {
	if cfg.DBPath == "" {
		if cfg.FleetEnabled {
			return nil, errFleetNeedsDB
		}

		s.logger.Warn("dashboard.ephemeral_stores",
			"msg", "ephemeral storage enabled; sessions, API keys, unblocks and logs reset on restart",
		)

		return func() {}, nil
	}

	return s.wirePersistentStores(ctx, cfg)
}

func (s *Server) wirePersistentStores(ctx context.Context, cfg Config) (func(), error) {
	client, db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	err = store.Migrate(ctx, db)
	if err != nil {
		_ = client.Close()

		return nil, fmt.Errorf("migrate db: %w", err)
	}

	apiKeys, err := store.NewAPIKeyStore(ctx, client, s.logger)
	if err != nil {
		_ = client.Close()

		return nil, fmt.Errorf("init api key store: %w", err)
	}

	if cfg.APIKey != "" {
		var inserted bool

		inserted, err = apiKeys.Seed(ctx, "env-bootstrap", cfg.APIKey)
		if err != nil {
			_ = client.Close()

			return nil, fmt.Errorf("seed env api key: %w", err)
		}

		if inserted {
			s.logger.Warn("dashboard.api_key_seeded",
				"label", "env-bootstrap",
				"msg", "API_KEY persisted on first startup; plaintext omitted because it was supplied by the operator")
		}
	}

	s.unblockStore = store.NewUnblockStore(client, s.logger)
	s.apiKeys = apiKeys
	s.sessions = store.NewSessionStore(client, s.logger)
	s.users = store.NewUserStore(client, s.logger)

	s.store = store.NewLogStore(client, cfg.LogRetention)
	s.logger.Info("dashboard.logs_persistent", "retention", cfg.LogRetention)

	if cfg.FleetEnabled {
		s.fleet = store.NewFleetStore(client, s.logger)
		s.logger.Info("dashboard.fleet_enabled")
	}

	s.logger.Info("dashboard.db_ready", "path", cfg.DBPath)

	return func() { _ = client.Close() }, nil
}

// ensureAPIKeys generates a first-boot machine credential when the key store is
// empty. If every stored key was explicitly revoked, the dashboard remains
// available so an administrator can create a replacement through the UI.
func (s *Server) ensureAPIKeys(ctx context.Context) error {
	keys, err := s.apiKeys.List(ctx)
	if err != nil {
		return fmt.Errorf("list api keys: %w", err)
	}

	for _, k := range keys {
		if k.RevokedAt == nil {
			return nil
		}
	}

	if len(keys) > 0 {
		s.logger.Warn("dashboard.no_active_api_keys",
			"msg", "all API keys are revoked; log ingestion is disabled until an administrator creates a key")

		return nil
	}

	key, rec, err := s.apiKeys.Create(ctx, "auto-bootstrap")
	if err != nil {
		return fmt.Errorf("generate bootstrap api key: %w", err)
	}

	_, _ = fmt.Fprintf(s.bootstrapOut, "dashboard.bootstrap_api_key label=%s key=%s\n", rec.Label, key)
	s.logger.Warn("dashboard.api_key_generated",
		"label", rec.Label,
		"credential_output", "stderr",
		"msg", "auto-generated API key on first startup; configure agents, then rotate it in the dashboard")

	return nil
}

// sessionGCLoop prunes expired sessions until ctx is canceled.
func (s *Server) sessionGCLoop(ctx context.Context) {
	t := time.NewTicker(sessionGCInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			err := s.sessions.GC(ctx)
			if err != nil {
				s.logger.Debug("sessions.gc_failed", "error", err.Error())
			}
		}
	}
}
