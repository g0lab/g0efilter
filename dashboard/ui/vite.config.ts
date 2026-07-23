import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';

// dist/ is gitignored except a tracked .gitkeep that keeps `go:embed all:dist`
// compiling on a clean checkout. emptyOutDir wipes it, so restore it post-build.
const keepGitkeep = {
  name: 'keep-dist-gitkeep',
  closeBundle() {
    writeFileSync(resolve(import.meta.dirname, 'dist/.gitkeep'), '');
  },
};

export default defineConfig({
  // Tailwind must precede the Svelte plugin.
  plugins: [tailwindcss(), svelte(), keepGitkeep],
  resolve: {
    alias: {
      $lib: resolve(import.meta.dirname, 'src/lib'),
      // Canonical synthetic-traffic fixtures shared with the Go dev tools.
      $demo: resolve(import.meta.dirname, '../demo'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: resolve(import.meta.dirname, 'index.html'),
        login: resolve(import.meta.dirname, 'login.html'),
      },
      output: {
        // Readable names; the [hash] stays for cache-busting. The shared
        // Svelte runtime + lib code lands in "shared-*" instead of Vite's
        // default internal-module name ("disclose-version-*").
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/shared-[hash].js',
        assetFileNames: (info) => {
          const name = info.names?.[0] ?? info.name ?? '';
          if (name.endsWith('.css')) return 'assets/style-[hash][extname]';
          return 'assets/[name]-[hash][extname]';
        },
      },
    },
  },
  server: {
    // pnpm dev: HMR frontend on :5000, real Go backend on :8081
    // (scripts/dev-dashboard.sh). /api (incl. the SSE stream) is proxied so
    // the session cookie and same-origin requests just work.
    port: 5000,
    strictPort: true,
    // Allow importing the shared fixtures from ../demo (outside the UI root).
    fs: { allow: [resolve(import.meta.dirname, '..')] },
    proxy: {
      '/api': { target: 'http://localhost:8081', changeOrigin: true },
    },
  },
});
