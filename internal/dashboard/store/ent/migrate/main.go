//go:build ignore

// Command migrate generates a versioned Atlas migration from the Ent schema.
// It never talks to the production database and needs no atlas binary: it
// replays the committed migrations onto a throwaway dev database, diffs the
// desired state (the Ent schema) against it, and writes the new .sql file.
//
// Usage: go run -mod=mod ./internal/dashboard/store/ent/migrate <name>
package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"

	atlas "ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/g0lab/g0efilter/internal/dashboard/store/ent/migrate"
	sqlite "modernc.org/sqlite"
)

const migrationsDir = "internal/dashboard/store/migrations"

// Atlas's sqlite opener does sql.Open("sqlite3", ...); modernc registers only
// "sqlite", so alias it.
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("migration name required: go run -mod=mod ./internal/dashboard/store/ent/migrate <name>")
	}

	ctx := context.Background()

	dir, err := atlas.NewLocalDir(migrationsDir)
	if err != nil {
		log.Fatalf("open migration dir: %v", err)
	}

	// Physical temp file dev database: avoids in-memory URI param quirks.
	devFile := filepath.Join(os.TempDir(), "g0efilter-migrate-dev.db")
	_ = os.Remove(devFile)
	defer func() { _ = os.Remove(devFile) }()

	opts := []schema.MigrateOption{
		schema.WithDir(dir),
		schema.WithMigrationMode(schema.ModeReplay),
		schema.WithDialect(dialect.SQLite),
		schema.WithFormatter(atlas.DefaultFormatter),
	}

	err = migrate.NamedDiff(ctx, "sqlite://"+devFile+"?_pragma=foreign_keys(1)", os.Args[1], opts...)
	if err != nil {
		log.Fatalf("generate migration: %v", err)
	}
}
