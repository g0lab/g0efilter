// Command dev-seed-dashboard replaces local dashboard logs with deterministic demo data.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/dashboard/demo"
	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store"
)

const (
	defaultSeedCount = 10_000
	maxSeedCount     = 100_000
)

var errInvalidSeedConfig = errors.New("dev seed requires a database path and a count from 1 to 100000")

type ageBand struct {
	minAge  time.Duration
	maxAge  time.Duration
	percent int
}

func main() {
	dbPath := flag.String("db", "", "dashboard SQLite path")
	count := flag.Int("count", defaultSeedCount, "number of log rows")

	flag.Parse()

	fixtures, err := demo.Scenarios()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = seedDatabase(context.Background(), *dbPath, *count, time.Now().UTC(), fixtures)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	_, _ = fmt.Fprintf(os.Stdout,
		"seeded %d dashboard events in %s (15m 10%%, 1h 20%%, 6h 32%%, 24h 45%%, 7d 60%%, 30d 77%%, 90d 90%%, all 100%%)\n",
		*count, *dbPath)
}

//nolint:cyclop,wsl_v5 // linear setup and transaction lifecycle
func seedDatabase(ctx context.Context, dbPath string, count int, now time.Time, fixtures demo.Fixtures) error {
	if strings.TrimSpace(dbPath) == "" || count < 1 || count > maxSeedCount {
		return errInvalidSeedConfig
	}

	client, db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open dev database: %w", err)
	}
	defer func() { _ = client.Close() }()

	err = store.Migrate(ctx, db)
	if err != nil {
		return fmt.Errorf("migrate dev database: %w", err)
	}

	logs := store.NewLogStore(client, maxSeedCount)
	err = logs.Clear(ctx)
	if err != nil {
		return fmt.Errorf("clear dev logs: %w", err)
	}

	tx, err := client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin dev seed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txLogs := store.NewLogStore(tx.Client(), maxSeedCount)
	entries := buildEntries(count, now, fixtures)
	for i := range entries {
		_, err = txLogs.Insert(ctx, &entries[i])
		if err != nil {
			return fmt.Errorf("insert dev log %d: %w", i, err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit dev seed: %w", err)
	}

	return nil
}

func buildEntries(count int, now time.Time, fixtures demo.Fixtures) []model.LogEntry {
	bands := []ageBand{
		{minAge: 0, maxAge: 15 * time.Minute, percent: 10},
		{minAge: 15 * time.Minute, maxAge: time.Hour, percent: 10},
		{minAge: time.Hour, maxAge: 6 * time.Hour, percent: 12},
		{minAge: 6 * time.Hour, maxAge: 24 * time.Hour, percent: 13},
		{minAge: 24 * time.Hour, maxAge: 7 * 24 * time.Hour, percent: 15},
		{minAge: 7 * 24 * time.Hour, maxAge: 30 * 24 * time.Hour, percent: 17},
		{minAge: 30 * 24 * time.Hour, maxAge: 90 * 24 * time.Hour, percent: 13},
		{minAge: 90 * 24 * time.Hour, maxAge: 180 * 24 * time.Hour, percent: 10},
	}
	subnet := fixtures.SourceSubnet

	entries := make([]model.LogEntry, 0, count)
	for i := range count {
		band := bandForPosition(bands, i, count)
		fraction := float64((i*7919)%10_000) / 10_000
		age := band.minAge + time.Duration(float64(band.maxAge-band.minAge)*fraction)
		// A fixed destination carries a fixed verdict/component, so the same
		// domain never flips verdict across events or clients.
		dest := fixtures.Destinations[(i*11)%len(fixtures.Destinations)]
		client := fixtures.Clients[(i*3)%len(fixtures.Clients)]

		entries = append(entries, model.LogEntry{
			Time:            now.Add(-age),
			Message:         "flow.decision",
			Fields:          seedFields(dest, client),
			Action:          dest.Verdict,
			HTTPHost:        dest.Domain,
			HTTPS:           dest.Domain,
			SourceIP:        fmt.Sprintf("%s.%d.%d", subnet, (i/250)%250, i%250+2),
			SourcePort:      1024 + (i*37)%40_000,
			DestinationIP:   dest.IP,
			DestinationPort: dest.Port,
			Protocol:        "TCP",
			FlowID:          fmt.Sprintf("dev-seed-%05d", i+1),
			Hostname:        client,
			Version:         "dev-seed",
		})
	}

	return entries
}

func bandForPosition(bands []ageBand, index, count int) ageBand {
	position := index * 100 / count
	cumulative := 0

	for _, band := range bands {
		cumulative += band.percent
		if position < cumulative {
			return band
		}
	}

	return bands[len(bands)-1]
}

func seedFields(dest demo.Destination, client string) json.RawMessage {
	fields, err := json.Marshal(map[string]string{
		"action": dest.Verdict, "component": dest.Component, "http_host": dest.Domain,
		"hostname": client, "reason": dest.Reason,
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}

	return fields
}
