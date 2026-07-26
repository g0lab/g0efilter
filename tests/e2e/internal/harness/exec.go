package harness

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const execTimeout = 60 * time.Second

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ExecResult is the outcome of a container command.
type ExecResult struct {
	Command  []string
	ExitCode int
	Output   string
	Err      error
}

// Exec runs a command in a container and collects its combined output.
func Exec(ctx context.Context, c *testcontainers.DockerContainer, command ...string) ExecResult {
	// Multiplexed demuxes Docker's stdout/stderr framing; without it the output
	// carries 8-byte frame headers that corrupt any parsing of it.
	code, reader, err := c.Exec(ctx, command, tcexec.Multiplexed())

	var out strings.Builder

	if reader != nil {
		_, copyErr := io.Copy(&out, reader)
		if err == nil {
			err = copyErr
		}
	}

	return ExecResult{
		Command:  command,
		ExitCode: code,
		Output:   StripANSI(out.String()),
		Err:      err,
	}
}

// ExecAgent runs a command in the g0efilter container.
func (s *Stack) ExecAgent(t *testing.T, command ...string) ExecResult {
	t.Helper()

	return s.exec(t, s.Agent, command...)
}

// ExecTester runs a command in the tester container, which shares the agent's
// network namespace - the only place traffic tests exercise the real path.
func (s *Stack) ExecTester(t *testing.T, command ...string) ExecResult {
	t.Helper()

	return s.exec(t, s.Tester, command...)
}

// ExecDashboard runs a command in the dashboard container.
func (s *Stack) ExecDashboard(t *testing.T, command ...string) ExecResult {
	t.Helper()

	return s.exec(t, s.Dashboard, command...)
}

func (s *Stack) exec(t *testing.T, c *testcontainers.DockerContainer, command ...string) ExecResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	res := Exec(ctx, c, command...)
	if res.Err != nil {
		t.Fatalf("exec %v: %v (output: %s)", command, res.Err, res.Output)
	}

	return res
}

// StripANSI removes the colour escapes the agent's console logger emits.
func StripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}
