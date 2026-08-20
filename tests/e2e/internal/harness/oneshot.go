package harness

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const oneShotTimeout = 60 * time.Second

// OneShot describes a container run directly from a production image, outside
// the compose stack - the capability and CLI tests exercise the real image with
// capability sets that compose cannot express per-case.
type OneShot struct {
	Image string
	Cmd   []string
	Env   map[string]string
	// CapAdd lists capabilities to grant on top of a full drop.
	CapAdd []string
	// User overrides the image's user, e.g. "65534:65534".
	User string
	// Binds are host:container mounts.
	Binds []string
	// SecurityOpt holds docker --security-opt values, e.g. "no-new-privileges".
	SecurityOpt []string
}

// OneShotResult is the outcome of a one-shot run.
type OneShotResult struct {
	ExitCode int
	Output   string
}

// Succeeded reports a zero exit code.
func (r OneShotResult) Succeeded() bool { return r.ExitCode == 0 }

// Contains reports whether the output contains a substring.
func (r OneShotResult) Contains(s string) bool { return strings.Contains(r.Output, s) }

// RunOneShot starts a container, waits for it to exit and returns its output.
func RunOneShot(t *testing.T, spec OneShot) OneShotResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), oneShotTimeout)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:      spec.Image,
		Cmd:        spec.Cmd,
		Env:        spec.Env,
		User:       spec.User,
		WaitingFor: wait.ForExit().WithExitTimeout(oneShotTimeout),
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapDrop = []string{"ALL"}
			hc.CapAdd = spec.CapAdd
			hc.Binds = spec.Binds
			hc.SecurityOpt = spec.SecurityOpt
			hc.AutoRemove = false
		},
	}

	created, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          false,
	})
	if err != nil {
		t.Fatalf("create one-shot container from %s: %v", spec.Image, err)
	}

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		_ = created.Terminate(cleanupCtx)
	}()

	err = created.Start(ctx)
	if err != nil {
		// A container that fails to start still has logs worth reporting.
		return OneShotResult{ExitCode: -1, Output: oneShotLogs(t, created) + "\nstart error: " + err.Error()}
	}

	// WaitingFor already blocked until exit, so the state is final.
	state, err := created.State(ctx)
	if err != nil {
		t.Fatalf("inspect one-shot state: %v", err)
	}

	return OneShotResult{ExitCode: state.ExitCode, Output: oneShotLogs(t, created)}
}

func oneShotLogs(t *testing.T, c testcontainers.Container) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reader, err := c.Logs(ctx)
	if err != nil {
		return ""
	}
	defer func() { _ = reader.Close() }()

	raw, err := io.ReadAll(reader)
	if err != nil {
		return ""
	}

	return StripANSI(stripDockerStreamHeaders(raw))
}

// RunOneShotStdin runs a one-shot container that reads stdin. Testcontainers has
// no attach-stdin path, and `docker run -i` is the clearest way to deliver a
// password to the CLI and then close the stream.
func RunOneShotStdin(t *testing.T, spec OneShot, stdin string) OneShotResult {
	t.Helper()

	args := []string{"run", "--rm", "-i", "--cap-drop=ALL"}

	for _, capability := range spec.CapAdd {
		args = append(args, "--cap-add="+capability)
	}

	for key, value := range spec.Env {
		args = append(args, "-e", key+"="+value)
	}

	for _, bind := range spec.Binds {
		args = append(args, "-v", bind)
	}

	if spec.User != "" {
		args = append(args, "--user", spec.User)
	}

	args = append(args, spec.Image)
	args = append(args, spec.Cmd...)

	ctx, cancel := context.WithTimeout(context.Background(), oneShotTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(stdin)

	out, err := cmd.CombinedOutput()

	code := 0

	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("docker run %v: %v", args, err)
		}
	}

	return OneShotResult{ExitCode: code, Output: StripANSI(string(out))}
}
