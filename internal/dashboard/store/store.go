// Package store provides SQLite-backed persistence for the dashboard, using an
// Ent client for queries and Atlas-generated versioned migrations. It depends
// only on the model leaf package so the dashboard package can import it for
// wiring without an import cycle.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent"
	_ "modernc.org/sqlite" // pure-Go sqlite driver (CGO_ENABLED=0 build)
)

// migrations are generated from the Ent schema by Atlas (scripts/gen-migration.sh)
// and applied at runtime by Migrate. Only the .sql files are embedded; atlas.sum
// is a dev-time integrity file.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

const opTimeout = 5 * time.Second

// Open opens (creating if needed) the SQLite database at path with WAL and
// busy-timeout pragmas suitable for concurrent readers with a single writer,
// and wraps it in an Ent client. The returned *sql.DB is the same underlying
// handle (used by Migrate); closing the client closes it.
func Open(ctx context.Context, path string) (*ent.Client, *sql.DB, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(on)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	// Single connection: serializes writes so SQLITE_BUSY cannot occur.
	// Dashboard DB traffic (auth, unblocks, keys) is far below this bottleneck.
	db.SetMaxOpenConns(1)

	err = db.PingContext(ctx)
	if err != nil {
		_ = db.Close()

		return nil, nil, fmt.Errorf("ping sqlite %s: %w", path, err)
	}

	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.SQLite, db)))

	return client, db, nil
}

// Migrate applies all pending versioned migrations, tracked in schema_migrations
// so re-running is a no-op. It must run (and succeed) before the HTTP server
// starts serving; callers should treat an error as fatal rather than serve
// against a half-migrated database.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	files, err := migrationFiles()
	if err != nil {
		return err
	}

	for _, name := range files {
		version := strings.TrimSuffix(name, ".sql")

		var applied int

		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}

		if applied > 0 {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		err = applyMigration(ctx, db, version, string(content))
		if err != nil {
			return err
		}
	}

	return nil
}

// migrationFiles lists the embedded .sql migrations in apply order (their
// timestamp prefix makes lexical order the correct order).
func migrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	files := make([]string, 0, len(entries))

	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}

	sort.Strings(files)

	return files, nil
}

// applyMigration executes one migration file and records it, atomically.
func applyMigration(ctx context.Context, db *sql.DB, version, sqlText string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", version, err)
	}

	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, sqlText)
	if err != nil {
		return fmt.Errorf("apply migration %s: %w", version, err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		version, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("record migration %s: %w", version, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit migration %s: %w", version, err)
	}

	return nil
}

// opCtx returns a bounded context for store operations invoked through
// legacy interfaces that do not carry a caller context.
func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

// randomHex returns n random bytes as a hex string (2n characters).
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never errors on Linux (Go 1.20+)

	return hex.EncodeToString(b)
}
