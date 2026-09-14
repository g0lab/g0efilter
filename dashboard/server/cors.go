package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SECURITY: Credentialed wildcard CORS is invalid in browsers and overly broad;
// origins must be explicit.
var errCORSWildcard = errors.New(
	`CORS_ALLOWED_ORIGINS must list explicit origins, not "*" (credentials are sent cross-origin)`)

// validateCORSOrigins fails startup on a wildcard origin.
func validateCORSOrigins(origins []string) error {
	if slices.Contains(origins, "*") {
		return fmt.Errorf("%w", errCORSWildcard)
	}

	return nil
}

// SECURITY: Credentials let allowed browser origins send the session cookie, so wildcards
// are rejected at startup. No configured origins means same-origin only.
func (s *Server) corsMiddleware() gin.HandlerFunc {
	if len(s.corsOrigins) == 0 {
		return nil
	}

	return cors.New(cors.Config{
		AllowOrigins:     s.corsOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Accept", "Content-Type", "X-Api-Key", "Authorization"},
		AllowCredentials: true,
		MaxAge:           5 * time.Minute,
	})
}
