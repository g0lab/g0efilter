package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// The frontend is a Vite+Svelte project under ui/; only its build output
// (ui/dist, committed) is embedded. Rebuild with: cd internal/dashboard/ui && pnpm build
//
//go:embed all:ui/dist
var uiFiles embed.FS

// IndexHandler serves the embedded dashboard build (HTML/JS/CSS).
//
// Caching: hashed bundles under /assets/ are content-addressed, so they can be
// cached hard - a rebuild changes the filename, so the cache is never stale.
// HTML (index/login) must revalidate so a new build's asset references are
// picked up immediately. This gives local caching with no stale data.
func IndexHandler() http.Handler {
	uiFS, err := fs.Sub(uiFiles, "ui/dist")
	if err != nil {
		panic(err) // Should never happen at runtime with valid embed
	}

	fileServer := http.FileServer(http.FS(uiFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		fileServer.ServeHTTP(w, r)
	})
}
