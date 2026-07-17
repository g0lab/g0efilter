package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/g0lab/g0efilter/internal/dashboard/model"
)

const maxAPIKeyLabelLen = 64

// listAPIKeysHandler handles GET /api/v1/apikeys.
func (s *Server) listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := s.apiKeys.List(r.Context())
	if err != nil {
		s.logger.Error("apikeys.list_failed", "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(keys)
	if err != nil {
		s.logger.Error("failed to encode apikeys response", "error", err)
	}
}

// createAPIKeyHandler handles POST /api/v1/apikeys. The plaintext key is
// returned exactly once and never persisted.
func (s *Server) createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 4096

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	var req struct {
		Label string `json:"label"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	label := strings.TrimSpace(req.Label)
	if label == "" || len(label) > maxAPIKeyLabelLen {
		http.Error(w, `{"error":"label required (max 64 chars)"}`, http.StatusBadRequest)

		return
	}

	key, rec, err := s.apiKeys.Create(r.Context(), label)
	if err != nil {
		s.logger.Error("apikeys.create_failed", "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)

		return
	}

	s.logger.Info("apikeys.created",
		"remote", clientIP(r),
		"id", rec.ID,
		"label", rec.Label,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]any{
		"key":     key, // shown once; only the hash is stored
		"api_key": rec,
	})
	if err != nil {
		s.logger.Error("failed to encode apikey response", "error", err)
	}
}

// revokeAPIKeyHandler handles DELETE /api/v1/apikeys/{id}.
func (s *Server) revokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := s.apiKeys.Revoke(r.Context(), id)
	if err != nil {
		if errors.Is(err, model.ErrAPIKeyNotFound) {
			http.Error(w, `{"error":"api key not found"}`, http.StatusNotFound)

			return
		}

		s.logger.Error("apikeys.revoke_failed", "id", id, "error", err.Error())
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)

		return
	}

	s.logger.Info("apikeys.revoked", "remote", clientIP(r), "id", id)
	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{keyStatus: "revoked"})
	if err != nil {
		s.logger.Error("failed to encode revoke response", "error", err)
	}
}
