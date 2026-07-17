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

// errCORSWildcard rejects a credentialed wildcard CORS config at startup.
// A wildcard cannot safely be combined with credentialed cross-origin requests.
// Browsers reject `Access-Control-Allow-Origin: *` with credentials, and it
// would also be an over-broad policy. Origins must be listed explicitly.
var errCORSWildcard = errors.New(
	`CORS_ALLOWED_ORIGINS must list explicit origins, not "*" (credentials are sent cross-origin)`)

// validateCORSOrigins fails startup on a wildcard origin.
func validateCORSOrigins(origins []string) error {
	if slices.Contains(origins, "*") {
		return fmt.Errorf("%w", errCORSWildcard)
	}

	return nil
}

// corsMiddleware returns a CORS handler for the configured origins, or nil
// when none are set (same-origin only - the correct default behind a proxy).
//
// AllowCredentials is enabled so a browser app on an allowed origin can send
// the session cookie; wildcard "*" is rejected at startup (validateCORSOrigins)
// since it cannot be combined with credentials.
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
