package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/g0lab/g0efilter/dashboard/ui"
)

// IndexHandler serves the embedded dashboard build (HTML/JS/CSS).
//
// Caching: hashed bundles under /assets/ are content-addressed, so they can be
// cached hard - a rebuild changes the filename, so the cache is never stale.
// HTML (index/login) must revalidate so a new build's asset references are
// picked up immediately. This gives local caching with no stale data.
func IndexHandler() http.Handler {
	if !ui.Built() {
		return uiNotBuiltHandler()
	}

	uiFS, err := fs.Sub(ui.Assets, "dist")
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

// uiNotBuiltHandler serves a clear message when no real UI build is embedded
// (clean checkout or -tags noembed). No inline scripts, so it is CSP-safe.
func uiNotBuiltHandler() http.Handler {
	const page = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<title>g0efilter dashboard</title></head>` +
		`<body style="font-family:system-ui;margin:3rem;line-height:1.5">` +
		`<h1>Dashboard UI not built</h1>` +
		`<p>The frontend is generated, not committed. Build it with ` +
		`<code>pnpm build</code> in <code>dashboard/ui</code>, or run ` +
		`<code>scripts/dev.sh</code> for live development.</p></body></html>`

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(page))
	})
}
