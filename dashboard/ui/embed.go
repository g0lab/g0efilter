// Package ui embeds the built dashboard frontend so the server can serve it.
package ui

import "embed"

// Assets holds the built frontend. The Vite+Svelte project lives in this
// directory; only its build output (dist/, committed) is embedded. Rebuild
// with: pnpm build.
//
//go:embed all:dist
var Assets embed.FS
