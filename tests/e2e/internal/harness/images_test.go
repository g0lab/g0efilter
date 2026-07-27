package harness

import (
	"errors"
	"strings"
	"testing"
)

func TestEnsureImagesRejectsUnknownMode(t *testing.T) {
	t.Setenv("E2E_BUILD", "sometimes")

	err := ensureImages()
	if !errors.Is(err, errInvalidBuildMode) {
		t.Fatalf("ensureImages error = %v, want errInvalidBuildMode", err)
	}
}

func TestBuildComposeFileUsesE2EDefinition(t *testing.T) {
	t.Parallel()

	path, err := buildComposeFile()
	if err != nil {
		t.Fatalf("buildComposeFile: %v", err)
	}

	if !strings.HasSuffix(path, "tests/e2e/compose.build.yaml") {
		t.Errorf("build compose path = %q", path)
	}
}
