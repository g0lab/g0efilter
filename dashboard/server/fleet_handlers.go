package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/dashboard/model"
	"github.com/g0lab/g0efilter/dashboard/store"
)

const maxGroupNameLen = 64

const maxSyncWait = 30 * time.Second

// fleetReady guards handlers when fleet is enabled but has no store (no DB).
func (s *Server) fleetReady(w http.ResponseWriter) bool {
	if s.fleet == nil {
		http.Error(w, `{"error":"fleet management requires persistent storage"}`, http.StatusServiceUnavailable)

		return false
	}

	return true
}

// syncHandler handles POST /api/v1/sync: an instance reports its state and
// receives its desired config. A wait query enables bounded long-polling; an
// omitted or zero wait preserves an immediate reconciliation for compatibility.
func (s *Server) syncHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	const maxBody = 1 << 16

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	defer func() { _ = r.Body.Close() }()

	var rep model.SyncReport

	err := json.NewDecoder(r.Body).Decode(&rep)
	if err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	if strings.TrimSpace(rep.Hostname) == "" {
		http.Error(w, `{"error":"hostname required"}`, http.StatusBadRequest)

		return
	}

	wait, ok := parseSyncWait(r.URL.Query().Get("wait"))
	if !ok {
		http.Error(w, `{"error":"invalid wait duration"}`, http.StatusBadRequest)

		return
	}

	s.reconcileUntilChanged(w, r, rep, wait)
}

func parseSyncWait(raw string) (time.Duration, bool) {
	if raw == "" {
		return 0, true
	}

	wait, err := time.ParseDuration(raw)
	if err != nil || wait < 0 {
		return 0, false
	}

	return min(wait, maxSyncWait), true
}

func (s *Server) reconcileUntilChanged(
	w http.ResponseWriter,
	r *http.Request,
	rep model.SyncReport,
	wait time.Duration,
) {
	ctx := r.Context()

	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	for {
		changed := s.fleetChanges.subscribe()

		desired, err := s.fleet.Reconcile(ctx, rep)
		if err != nil {
			s.logger.Error("fleet.reconcile_failed", "remote", clientIP(r), "error", err.Error())
			http.Error(w, `{"error":"reconcile failed"}`, http.StatusInternalServerError)

			return
		}

		if (desired.Managed && desired.Hash != rep.ConfigHash) || wait == 0 {
			s.writeSyncResponse(w, desired, rep.ConfigHash)

			return
		}

		select {
		case <-changed:
			// Re-read desired state. Unrelated fleet changes may wake this
			// instance, in which case it resumes waiting until the deadline.
		case <-deadline.C:
			s.writeSyncResponse(w, desired, rep.ConfigHash)

			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) writeSyncResponse(w http.ResponseWriter, desired model.DesiredConfig, reportedHash string) {
	// Only a managed instance whose hash differs receives a policy push.
	// Unmanaged instances keep their local policy (managed:false, changed:false).
	changed := desired.Managed && desired.Hash != reportedHash

	resp := map[string]any{"managed": desired.Managed, "changed": changed}
	if changed {
		resp["config_hash"] = desired.Hash
		resp["policy"] = desired.Policy
		resp["filter_mode"] = desired.FilterMode
	} else {
		resp["config_hash"] = reportedHash
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) listInstancesHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	instances, err := s.fleet.ListInstances(r.Context())
	if err != nil {
		s.logger.Error("fleet.list_instances_failed", "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)

		return
	}

	s.writeJSON(w, http.StatusOK, instances)
}

func (s *Server) deleteInstanceHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	err := s.fleet.DeleteInstance(r.Context(), r.PathValue("id"))
	if s.writeFleetErr(w, err) {
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{keyStatus: "deleted"})
}

func (s *Server) setInstanceGroupHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	//nolint:tagliatelle // snake_case JSON API
	var req struct {
		GroupID string `json:"group_id"` // "" clears the group
	}

	if !s.decodeJSON(w, r, &req) {
		return
	}

	err := s.fleet.SetInstanceGroup(r.Context(), r.PathValue("id"), strings.TrimSpace(req.GroupID))
	if s.writeFleetErr(w, err) {
		return
	}

	s.logger.Info("fleet.instance_group_set", "remote", clientIP(r),
		"id", r.PathValue("id"), "group_id", req.GroupID)
	s.fleetChanges.notify()
	s.writeJSON(w, http.StatusOK, map[string]string{keyStatus: "ok"})
}

func (s *Server) setInstancePolicyHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	var req struct {
		Policy *string `json:"policy"` // null clears the override (inherit group)
	}

	if !s.decodeJSON(w, r, &req) {
		return
	}

	err := s.fleet.SetInstancePolicy(r.Context(), r.PathValue("id"), req.Policy)
	if s.writeFleetErr(w, err) {
		return
	}

	s.logger.Info("fleet.instance_policy_set", "remote", clientIP(r), "id", r.PathValue("id"))
	s.fleetChanges.notify()
	s.writeJSON(w, http.StatusOK, map[string]string{keyStatus: "ok"})
}

func (s *Server) listGroupsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	groups, err := s.fleet.ListGroups(r.Context())
	if err != nil {
		s.logger.Error("fleet.list_groups_failed", "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)

		return
	}

	s.writeJSON(w, http.StatusOK, groups)
}

func (s *Server) createGroupHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if !s.decodeJSON(w, r, &req) {
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > maxGroupNameLen {
		http.Error(w, `{"error":"name required (max 64 chars)"}`, http.StatusBadRequest)

		return
	}

	group, err := s.fleet.CreateGroup(r.Context(), name)
	if err != nil {
		// UNIQUE(name) violation is the common case.
		s.logger.Debug("fleet.create_group_failed", "error", err.Error())
		http.Error(w, `{"error":"could not create group (duplicate name?)"}`, http.StatusConflict)

		return
	}

	s.logger.Info("fleet.group_created", "remote", clientIP(r), "id", group.ID, "name", group.Name)
	s.writeJSON(w, http.StatusCreated, group)
}

func (s *Server) deleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	err := s.fleet.DeleteGroup(r.Context(), r.PathValue("id"))
	if s.writeFleetErr(w, err) {
		return
	}

	s.logger.Info("fleet.group_deleted", "remote", clientIP(r), "id", r.PathValue("id"))
	s.fleetChanges.notify()
	s.writeJSON(w, http.StatusOK, map[string]string{keyStatus: "deleted"})
}

// validFilterMode reports whether m is an accepted fleet filter mode. Empty
// means "inherit / unset"; the rest mirror the g0efilter FILTER_MODE values.
func validFilterMode(m string) bool {
	switch m {
	case "", "https", "dns", "dns-strict":
		return true
	default:
		return false
	}
}

func (s *Server) setGroupPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if !s.fleetReady(w) {
		return
	}

	//nolint:tagliatelle // snake_case JSON API
	var req struct {
		Policy     string `json:"policy"`
		FilterMode string `json:"filter_mode"`
	}

	if !s.decodeJSON(w, r, &req) {
		return
	}

	mode := strings.TrimSpace(req.FilterMode)
	if !validFilterMode(mode) {
		http.Error(w, `{"error":"invalid filter_mode"}`, http.StatusBadRequest)

		return
	}

	err := s.fleet.SetGroupPolicy(r.Context(), r.PathValue("id"), req.Policy, mode)
	if s.writeFleetErr(w, err) {
		return
	}

	s.logger.Info("fleet.group_policy_set", "remote", clientIP(r), "id", r.PathValue("id"))
	s.fleetChanges.notify()
	s.writeJSON(w, http.StatusOK, map[string]string{keyStatus: "ok"})
}

// writeFleetErr maps store errors to responses; returns true if it wrote one.
func (s *Server) writeFleetErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, store.ErrGroupNotFound):
		http.Error(w, `{"error":"group not found"}`, http.StatusNotFound)
	case errors.Is(err, store.ErrInstanceNotFound):
		http.Error(w, `{"error":"instance not found"}`, http.StatusNotFound)
	default:
		s.logger.Error("fleet.store_error", "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)
	}

	return true
}
