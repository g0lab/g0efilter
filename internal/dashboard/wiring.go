package dashboard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/g0lab/g0efilter/internal/dashboard/store"
)

var (
	errNoActiveAPIKeys = errors.New(
		"no active API keys: set API_KEY, or create a key in the dashboard before removing it")
	errFleetNeedsDB = errors.New("FLEET_ENABLED requires DB_PATH")
)

// wireStores swaps the in-memory defaults for SQLite-backed stores when
// DB_PATH is configured. Migrations are applied before returning, so a
// failure here must abort startup. The returned func closes the database.
func (s *Server) wireStores(ctx context.Context, cfg Config) (func(), error) {
	if cfg.DBPath == "" {
		// Fleet management has no in-memory fallback; logs fall back to the ring.
		if cfg.FleetEnabled {
			return nil, errFleetNeedsDB
		}

		s.logger.Warn("dashboard.ephemeral_stores",
			"msg", "DB_PATH not set; sessions, API keys, unblocks and logs reset on restart",
		)

		return func() {}, nil
	}

	client, db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	closeDB := func() { _ = client.Close() }

	err = store.Migrate(ctx, db)
	if err != nil {
		closeDB()

		return nil, fmt.Errorf("migrate db: %w", err)
	}

	apiKeys, err := store.NewAPIKeyStore(ctx, client, s.logger)
	if err != nil {
		closeDB()

		return nil, fmt.Errorf("init api key store: %w", err)
	}

	if cfg.APIKey != "" {
		err = apiKeys.Seed(ctx, "env-bootstrap", cfg.APIKey)
		if err != nil {
			closeDB()

			return nil, fmt.Errorf("seed env api key: %w", err)
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

	return closeDB, nil
}

// ensureAPIKeys fails startup when no machine credential exists at all:
// ingestion would be unusable and misconfiguration should surface immediately.
func (s *Server) ensureAPIKeys(ctx context.Context, cfg Config) error {
	if cfg.APIKey != "" {
		return nil
	}

	keys, err := s.apiKeys.List(ctx)
	if err != nil {
		return fmt.Errorf("list api keys: %w", err)
	}

	for _, k := range keys {
		if k.RevokedAt == nil {
			return nil
		}
	}

	return errNoActiveAPIKeys
}

// sessionGCLoop prunes expired sessions until ctx is cancelled.
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
