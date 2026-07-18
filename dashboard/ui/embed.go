//go:build !noembed

// Package ui embeds the built dashboard frontend so the server can serve it.
package ui

import (
	"embed"
	"io/fs"
)

// Assets holds the built frontend. The Vite project lives in this directory;
// its build output (dist/) is embedded but generated, not committed - build it
// with pnpm build (or scripts/dev.sh). Build with -tags noembed to skip it.
//
//go:embed all:dist
var Assets embed.FS

// Built reports whether a real UI build is embedded (dist/index.html present),
// as opposed to just the tracked placeholder in a clean checkout.
func Built() bool {
	_, err := fs.Stat(Assets, "dist/index.html")

	return err == nil
}
