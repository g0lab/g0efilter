package store

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store/ent"
	"github.com/g0lab/g0efilter/dashboard/store/ent/completedunblock"
	"github.com/g0lab/g0efilter/dashboard/store/ent/unblockrequest"
)

const (
	maxPendingUnblocks   = 1000
	maxCompletedUnblocks = 100
)

// UnblockStore is the SQLite-backed implementation of the dashboard's
// UnblockStore interface. The interface predates persistence and carries no
// context or error returns, so failures are logged and reported as zero values.
type UnblockStore struct {
	client *ent.Client
	lg     *slog.Logger
}

// NewUnblockStore creates a SQLite-backed unblock store.
func NewUnblockStore(client *ent.Client, lg *slog.Logger) *UnblockStore {
	return &UnblockStore{client: client, lg: lg}
}

// Add queues an unblock request, deduplicating on (type, value, target).
// Returns the request ID, or "" when the store is full or on error.
func (s *UnblockStore) Add(reqType, value, targetHostname string) string {
	ctx, cancel := opCtx()
	defer cancel()

	target := strings.ToLower(strings.TrimSpace(targetHostname))

	existing, err := s.dedupe(ctx, reqType, value, target)
	if err == nil {
		return existing
	}

	if !ent.IsNotFound(err) {
		s.lg.Error("store.unblocks.dedupe_failed", "error", err.Error())

		return ""
	}

	count, err := s.client.UnblockRequest.Query().Count(ctx)
	if err != nil {
		s.lg.Error("store.unblocks.count_failed", "error", err.Error())

		return ""
	}

	if count >= maxPendingUnblocks {
		return ""
	}

	id := randomHex(8)

	err = s.client.UnblockRequest.Create().
		SetID(id).
		SetType(reqType).
		SetValue(value).
		SetTargetHostname(target).
		SetCreatedAt(time.Now().Unix()).
		Exec(ctx)
	if err != nil {
		// Unique-index race with a concurrent identical request: return theirs.
		existing, derr := s.dedupe(ctx, reqType, value, target)
		if derr == nil {
			return existing
		}

		s.lg.Error("store.unblocks.insert_failed", "error", err.Error())

		return ""
	}

	return id
}

// GetPending returns all pending unblock requests.
func (s *UnblockStore) GetPending() []model.UnblockRequest {
	ctx, cancel := opCtx()
	defer cancel()

	rows, err := s.client.UnblockRequest.Query().
		Order(unblockrequest.ByCreatedAt(), unblockrequest.ByID()).
		All(ctx)
	if err != nil {
		s.lg.Error("store.unblocks.list_failed", "error", err.Error())

		return []model.UnblockRequest{}
	}

	return toUnblockRequests(rows)
}

// GetPendingForHost returns pending requests targeting the given hostname or all hosts.
func (s *UnblockStore) GetPendingForHost(hostname string) []model.UnblockRequest {
	ctx, cancel := opCtx()
	defer cancel()

	host := strings.ToLower(strings.TrimSpace(hostname))

	rows, err := s.client.UnblockRequest.Query().
		Where(unblockrequest.Or(
			unblockrequest.TargetHostname(""),
			unblockrequest.TargetHostname(host),
		)).
		Order(unblockrequest.ByCreatedAt(), unblockrequest.ByID()).
		All(ctx)
	if err != nil {
		s.lg.Error("store.unblocks.list_for_host_failed", "error", err.Error())

		return []model.UnblockRequest{}
	}

	return toUnblockRequests(rows)
}

// Acknowledge moves a pending request to the completed list. Returns false
// if the ID is unknown or on error.
func (s *UnblockStore) Acknowledge(id string) bool {
	ctx, cancel := opCtx()
	defer cancel()

	tx, err := s.client.Tx(ctx)
	if err != nil {
		s.lg.Error("store.unblocks.tx_failed", "error", err.Error())

		return false
	}

	defer func() { _ = tx.Rollback() }()

	err = s.acknowledgeTx(ctx, tx, id)
	if err != nil {
		if !ent.IsNotFound(err) {
			s.lg.Error("store.unblocks.ack_failed", "error", err.Error())
		}

		return false
	}

	err = tx.Commit()
	if err != nil {
		s.lg.Error("store.unblocks.commit_failed", "error", err.Error())

		return false
	}

	return true
}

// GetCompleted returns the bounded list of completed unblocks, oldest first.
func (s *UnblockStore) GetCompleted() []model.CompletedUnblock {
	ctx, cancel := opCtx()
	defer cancel()

	rows, err := s.client.CompletedUnblock.Query().
		Order(completedunblock.ByID(entsql.OrderDesc())).
		Limit(maxCompletedUnblocks).
		All(ctx)
	if err != nil {
		s.lg.Error("store.unblocks.list_completed_failed", "error", err.Error())

		return []model.CompletedUnblock{}
	}

	// Query is newest-first; return oldest-first.
	out := make([]model.CompletedUnblock, 0, len(rows))
	for _, r := range slices.Backward(rows) {
		out = append(out, model.CompletedUnblock{
			Type:           r.Type,
			Value:          r.Value,
			TargetHostname: r.TargetHostname,
			CompletedAt:    time.Unix(r.CompletedAt, 0).UTC(),
		})
	}

	return out
}

// acknowledgeTx performs the move-and-prune inside a transaction.
func (s *UnblockStore) acknowledgeTx(ctx context.Context, tx *ent.Tx, id string) error {
	req, err := tx.UnblockRequest.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get unblock: %w", err)
	}

	err = tx.CompletedUnblock.Create().
		SetType(req.Type).
		SetValue(req.Value).
		SetTargetHostname(req.TargetHostname).
		SetCompletedAt(time.Now().Unix()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("insert completed: %w", err)
	}

	err = tx.UnblockRequest.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete unblock: %w", err)
	}

	return pruneCompleted(ctx, tx.CompletedUnblock)
}

// dedupe returns the ID of an existing request matching (type, value, target).
func (s *UnblockStore) dedupe(ctx context.Context, reqType, value, target string) (string, error) {
	id, err := s.client.UnblockRequest.Query().
		Where(
			unblockrequest.TypeEQ(reqType),
			unblockrequest.Value(value),
			unblockrequest.TargetHostname(target),
		).
		OnlyID(ctx)
	if err != nil {
		return "", fmt.Errorf("dedupe unblock: %w", err)
	}

	return id, nil
}

// pruneCompleted drops all but the newest maxCompletedUnblocks rows.
func pruneCompleted(ctx context.Context, c *ent.CompletedUnblockClient) error {
	ids, err := c.Query().
		Order(completedunblock.ByID(entsql.OrderDesc())).
		Limit(maxCompletedUnblocks).
		IDs(ctx)
	if err != nil {
		return fmt.Errorf("list completed ids: %w", err)
	}

	if len(ids) < maxCompletedUnblocks {
		return nil
	}

	minKept := ids[len(ids)-1]

	_, err = c.Delete().Where(completedunblock.IDLT(minKept)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("prune completed: %w", err)
	}

	return nil
}

func toUnblockRequests(rows []*ent.UnblockRequest) []model.UnblockRequest {
	out := make([]model.UnblockRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, model.UnblockRequest{
			ID:             r.ID,
			Type:           r.Type,
			Value:          r.Value,
			TargetHostname: r.TargetHostname,
			CreatedAt:      time.Unix(r.CreatedAt, 0).UTC(),
		})
	}

	return out
}
