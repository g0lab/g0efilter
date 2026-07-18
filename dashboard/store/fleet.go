package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store/ent"
	"github.com/g0lab/g0efilter/dashboard/store/ent/group"
	"github.com/g0lab/g0efilter/dashboard/store/ent/instance"
)

// ErrGroupNotFound / ErrInstanceNotFound signal unknown IDs to handlers.
var (
	ErrGroupNotFound    = errors.New("group not found")
	ErrInstanceNotFound = errors.New("instance not found")
)

// instanceOnlineWindow marks an instance offline if it has not synced within it.
const instanceOnlineWindow = 90 * time.Second

// FleetStore is the SQLite-backed instance/group control plane.
type FleetStore struct {
	client *ent.Client
	lg     *slog.Logger
}

// NewFleetStore creates a SQLite-backed fleet store.
func NewFleetStore(client *ent.Client, lg *slog.Logger) *FleetStore {
	return &FleetStore{client: client, lg: lg}
}

// Reconcile records an instance report and returns its resolved desired config.
func (s *FleetStore) Reconcile(ctx context.Context, rep model.SyncReport) (model.DesiredConfig, error) {
	hostname := strings.ToLower(strings.TrimSpace(rep.Hostname))
	if hostname == "" {
		return model.DesiredConfig{}, fmt.Errorf("reconcile: %w", errEmptyHostname)
	}

	now := time.Now().Unix()

	err := s.client.Instance.Create().
		SetID(randomHex(8)).
		SetHostname(hostname).
		SetFilterMode(rep.FilterMode).
		SetReportedVersion(rep.Version).
		SetReportedHash(rep.ConfigHash).
		SetLastSeenAt(now).
		SetCreatedAt(now).
		OnConflictColumns(instance.FieldHostname).
		Update(func(u *ent.InstanceUpsert) {
			u.SetFilterMode(rep.FilterMode)
			u.SetReportedVersion(rep.Version)
			u.SetReportedHash(rep.ConfigHash)
			u.SetLastSeenAt(now)
		}).
		Exec(ctx)
	if err != nil {
		return model.DesiredConfig{}, fmt.Errorf("upsert instance: %w", err)
	}

	inst, err := s.client.Instance.Query().Where(instance.Hostname(hostname)).Only(ctx)
	if err != nil {
		return model.DesiredConfig{}, fmt.Errorf("get instance: %w", err)
	}

	return s.resolveDesired(ctx, inst)
}

// ListInstances returns all instances with resolved group + sync state.
func (s *FleetStore) ListInstances(ctx context.Context) ([]model.Instance, error) {
	rows, err := s.client.Instance.Query().
		WithGroup().
		Order(instance.ByHostname()).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}

	now := time.Now()
	out := make([]model.Instance, 0, len(rows))

	for _, r := range rows {
		groupName, groupPolicy, groupFilterMode := "", "", ""
		if r.Edges.Group != nil {
			groupName = r.Edges.Group.Name
			groupPolicy = r.Edges.Group.Policy
			groupFilterMode = r.Edges.Group.FilterMode
		}

		policy := groupPolicy
		filterMode := r.FilterMode

		if groupFilterMode != "" {
			filterMode = groupFilterMode
		}

		if r.PolicyOverride != nil {
			policy = *r.PolicyOverride
		}

		desired := configHash(policy, filterMode)
		lastSeen := time.Unix(r.LastSeenAt, 0).UTC()

		inst := model.Instance{
			ID:              r.ID,
			Hostname:        r.Hostname,
			GroupID:         r.GroupID,
			GroupName:       groupName,
			FilterMode:      filterMode,
			ReportedVersion: r.ReportedVersion,
			ReportedHash:    r.ReportedHash,
			DesiredHash:     desired,
			InSync:          r.ReportedHash == desired,
			LastSeenAt:      lastSeen,
			CreatedAt:       time.Unix(r.CreatedAt, 0).UTC(),
		}

		if r.PolicyOverride != nil {
			v := *r.PolicyOverride
			inst.PolicyOverride = &v
		}

		// Offline instances are reported as out of sync regardless of hash.
		if now.Sub(lastSeen) > instanceOnlineWindow {
			inst.InSync = false
		}

		out = append(out, inst)
	}

	return out, nil
}

// DeleteInstance removes an instance record.
func (s *FleetStore) DeleteInstance(ctx context.Context, id string) error {
	n, err := s.client.Instance.Delete().Where(instance.ID(id)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete instance: %w", err)
	}

	if n == 0 {
		return ErrInstanceNotFound
	}

	return nil
}

// SetInstanceGroup assigns (groupID != "") or clears an instance's group.
func (s *FleetStore) SetInstanceGroup(ctx context.Context, id, groupID string) error {
	upd := s.client.Instance.Update().Where(instance.ID(id))

	if groupID != "" {
		exists, err := s.client.Group.Query().Where(group.ID(groupID)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("get group: %w", err)
		}

		if !exists {
			return ErrGroupNotFound
		}

		upd.SetGroupID(groupID)
	} else {
		upd.ClearGroupID()
	}

	n, err := upd.Save(ctx)
	if err != nil {
		return fmt.Errorf("set instance group: %w", err)
	}

	if n == 0 {
		return ErrInstanceNotFound
	}

	return nil
}

// SetInstancePolicy sets (non-nil) or clears (nil) an instance policy override.
func (s *FleetStore) SetInstancePolicy(ctx context.Context, id string, policy *string) error {
	upd := s.client.Instance.Update().Where(instance.ID(id))

	if policy != nil {
		upd.SetPolicyOverride(*policy)
	} else {
		upd.ClearPolicyOverride()
	}

	n, err := upd.Save(ctx)
	if err != nil {
		return fmt.Errorf("set instance policy: %w", err)
	}

	if n == 0 {
		return ErrInstanceNotFound
	}

	return nil
}

// ListGroups returns all groups.
func (s *FleetStore) ListGroups(ctx context.Context) ([]model.Group, error) {
	rows, err := s.client.Group.Query().Order(group.ByName()).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}

	out := make([]model.Group, 0, len(rows))
	for _, r := range rows {
		out = append(out, toGroup(r))
	}

	return out, nil
}

// CreateGroup creates an empty group with the given name.
func (s *FleetStore) CreateGroup(ctx context.Context, name string) (model.Group, error) {
	g := model.Group{
		ID:        randomHex(8),
		Name:      strings.TrimSpace(name),
		UpdatedAt: time.Now().UTC(),
	}

	err := s.client.Group.Create().
		SetID(g.ID).
		SetName(g.Name).
		SetPolicy("").
		SetFilterMode("").
		SetUpdatedAt(g.UpdatedAt.Unix()).
		Exec(ctx)
	if err != nil {
		return model.Group{}, fmt.Errorf("insert group: %w", err)
	}

	return g, nil
}

// DeleteGroup removes a group; member instances fall back to unmanaged.
func (s *FleetStore) DeleteGroup(ctx context.Context, id string) error {
	n, err := s.client.Group.Delete().Where(group.ID(id)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}

	if n == 0 {
		return ErrGroupNotFound
	}

	return nil
}

// SetGroupPolicy updates a group's policy and optional filter mode.
func (s *FleetStore) SetGroupPolicy(ctx context.Context, id, policy, filterMode string) error {
	n, err := s.client.Group.Update().
		Where(group.ID(id)).
		SetPolicy(policy).
		SetFilterMode(filterMode).
		SetUpdatedAt(time.Now().Unix()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("update group policy: %w", err)
	}

	if n == 0 {
		return ErrGroupNotFound
	}

	return nil
}

// resolveDesired computes desired config: instance override -> group -> unmanaged.
// An instance is managed only when it belongs to a group or carries a policy
// override; otherwise the dashboard has no desired policy and must not push one.
func (s *FleetStore) resolveDesired(ctx context.Context, inst *ent.Instance) (model.DesiredConfig, error) {
	policy := ""
	filterMode := inst.FilterMode
	managed := false

	if inst.GroupID != "" {
		g, err := s.client.Group.Query().Where(group.ID(inst.GroupID)).Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return model.DesiredConfig{}, fmt.Errorf("get group: %w", err)
		}

		if err == nil {
			managed = true
			policy = g.Policy

			if g.FilterMode != "" {
				filterMode = g.FilterMode
			}
		}
	}

	if inst.PolicyOverride != nil {
		managed = true
		policy = *inst.PolicyOverride
	}

	return model.DesiredConfig{
		Policy:     policy,
		FilterMode: filterMode,
		Hash:       configHash(policy, filterMode),
		Managed:    managed,
	}, nil
}

func toGroup(r *ent.Group) model.Group {
	return model.Group{
		ID:         r.ID,
		Name:       r.Name,
		Policy:     r.Policy,
		FilterMode: r.FilterMode,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0).UTC(),
	}
}

// configHash is the desired-state fingerprint an instance compares against.
func configHash(policy, filterMode string) string {
	sum := sha256.Sum256([]byte(filterMode + "\n" + policy))

	return hex.EncodeToString(sum[:])
}

var errEmptyHostname = errors.New("hostname is required")
