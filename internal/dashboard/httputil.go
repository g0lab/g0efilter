package dashboard

import (
	"encoding/json"
	"net/http"
)

const maxJSONBody = 1 << 16 // 64 KiB - admin JSON payloads are small

// writeJSON encodes v as a JSON response with the given status.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		s.logger.Error("http.encode_failed", "error", err.Error())
	}
}

// decodeJSON reads a bounded JSON body into v, writing a 400 on failure.
// Returns false if it wrote an error response.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	defer func() { _ = r.Body.Close() }()

	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return false
	}

	return true
}
