package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	buildTimeout = 15 * time.Minute

	buildModeAuto  = "auto"
	buildModeForce = "force"
	buildModeNever = "never"
)

var (
	errCannotBuildCustomTags = errors.New("E2E_BUILD=force cannot build custom image tags")
	errInvalidBuildMode      = errors.New("invalid E2E_BUILD (want auto, force or never)")
	errNoSourceDir           = errors.New("cannot locate the harness source directory")
)

//nolint:gochecknoglobals // build at most once per test binary and retain its result
var (
	buildOnce       sync.Once
	errEnsureImages error
)

// EnsureImages builds missing test images according to E2E_BUILD.
func EnsureImages() error {
	buildOnce.Do(func() { errEnsureImages = ensureImages() })

	return errEnsureImages
}

func ensureImages() error {
	mode := Env("E2E_BUILD", buildModeAuto)
	if mode != buildModeAuto && mode != buildModeForce && mode != buildModeNever {
		return fmt.Errorf("%w: %q", errInvalidBuildMode, mode)
	}

	if mode == buildModeNever {
		return nil
	}

	agent := Env("G0EFILTER_IMAGE", defaultAgentImage)
	dashboard := Env("G0EFILTER_DASHBOARD_IMAGE", defaultDashboardImage)

	// A custom tag is the caller's to provide; building would overwrite the
	// default tags instead, which is not what they asked for.
	if agent != defaultAgentImage || dashboard != defaultDashboardImage {
		if mode == buildModeForce {
			return fmt.Errorf("%w: custom tags %s, %s", errCannotBuildCustomTags, agent, dashboard)
		}

		return nil
	}

	if mode != buildModeForce && imageExists(agent) && imageExists(dashboard) {
		return nil
	}

	fmt.Fprintf(os.Stderr, "building %s and %s (E2E_BUILD=%s); set E2E_BUILD=never to skip\n",
		agent, dashboard, mode)

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	composeFile, err := buildComposeFile()
	if err != nil {
		return err
	}

	//nolint:gosec // fixed argv; the compose file path is derived from this source file
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", composeFile, "build", "g0efilter", "g0efilter-dashboard")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("build images: %w", err)
	}

	return nil
}

func imageExists(ref string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // argv only; ref is an image tag from config, never a shell string
	return exec.CommandContext(ctx, "docker", "image", "inspect", ref).Run() == nil
}

func buildComposeFile() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errNoSourceDir
	}

	path, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", "compose.build.yaml"))
	if err != nil {
		return "", fmt.Errorf("resolve build compose file: %w", err)
	}

	return path, nil
}
