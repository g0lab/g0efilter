// Package repo_test enforces repository-wide conventions that no linter covers.
package repo_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// asciiExempt lists the files allowed to contain non-ASCII, with the reason. Adding
// to this list should be a deliberate review decision.
var asciiExempt = map[string]string{ //nolint:gochecknoglobals // the exemption list is the test's data
	// IDNA and punycode conversion cannot be tested without unicode input.
	"agent/filter/common_test.go":              "IDN test vectors",
	"agent/filter/matcher_correctness_test.go": "IDN test vectors",
	"dashboard/server/handlers_test.go":        "unicode sanitisation vectors",
	"dashboard/server/sanitize_test.go":        "unicode sanitisation vectors",

	// User-facing output rather than source prose.
	"dashboard/ui/src/App.svelte":        "UI glyphs",
	"dashboard/ui/src/AggView.svelte":    "UI glyphs",
	"dashboard/ui/src/SearchView.svelte": "UI glyphs",
	"dashboard/ui/src/StreamView.svelte": "UI glyphs",
	"dashboard/ui/src/app.css":           "UI glyphs",
}

// skipExtensions are binary or generated formats where a byte scan is meaningless.
var skipExtensions = map[string]bool{ //nolint:gochecknoglobals // the skip list is the test's data
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".db": true, ".sum": true,
}

func trackedFiles(t *testing.T) []string {
	t.Helper()

	bin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git is not installed: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	//nolint:gosec // git resolved through LookPath, with literal arguments
	out, err := exec.CommandContext(ctx, bin, "-C", filepath.Join("..", ".."),
		"ls-files", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			t.Fatalf("git ls-files: %v\n%s", err, exitErr.Stderr)
		}

		t.Fatalf("git ls-files: %v", err)
	}

	var files []string

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}

		info, err := os.Stat(filepath.Join("..", "..", name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}

		if info.IsDir() {
			continue
		}

		if !skipExtensions[strings.ToLower(filepath.Ext(name))] {
			files = append(files, name)
		}
	}

	return files
}

// findNonASCII returns "line:column: rune" for each offending character.
func findNonASCII(content string) []string {
	var found []string

	for lineNumber, line := range strings.Split(content, "\n") {
		if utf8.ValidString(line) && isASCII(line) {
			continue
		}

		column := 1

		for _, r := range line {
			if r > unicode.MaxASCII {
				found = append(found, fmt.Sprintf("line %d, column %d: %q (U+%04X)",
					lineNumber+1, column, r, r))
			}

			column++
		}
	}

	return found
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}

	return true
}

// Smart quotes, arrows and non-breaking spaces are invisible in review and creep in
// through copy-paste. This is the only thing enforcing the ASCII-by-default rule:
// golangci-lint's asciicheck covers Go identifiers only, not comments, strings,
// Markdown or YAML.
func TestSourceIsASCII(t *testing.T) {
	t.Parallel()

	for _, name := range trackedFiles(t) {
		if _, exempt := asciiExempt[name]; exempt {
			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		for _, offence := range findNonASCII(string(content)) {
			t.Errorf("%s: %s\nuse ASCII, or add the file to asciiExempt with a reason", name, offence)
		}
	}
}

// An exemption for a file that no longer needs one is stale and should be removed.
func TestASCIIExemptionsAreStillNeeded(t *testing.T) {
	t.Parallel()

	tracked := make(map[string]bool)
	for _, name := range trackedFiles(t) {
		tracked[name] = true
	}

	for name, reason := range asciiExempt {
		if !tracked[name] {
			t.Errorf("asciiExempt lists %s (%q), which is no longer tracked", name, reason)

			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a tracked repository path
		if err != nil {
			t.Errorf("read %s: %v", name, err)

			continue
		}

		if len(findNonASCII(string(content))) == 0 {
			t.Errorf("%s is exempt (%q) but is now pure ASCII; remove the exemption", name, reason)
		}
	}
}
