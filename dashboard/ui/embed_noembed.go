//go:build noembed

package ui

import "embed"

// Assets is empty when built with -tags noembed: no frontend is embedded, so
// the server serves a "UI not built" page. Useful for backend-only builds/lint.
var Assets embed.FS

// Built always reports false under -tags noembed.
func Built() bool { return false }
