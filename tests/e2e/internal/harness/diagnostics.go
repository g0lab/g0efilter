package harness

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

const (
	defaultLogTail = 20
	problemLines   = 12

	logFetchTimeout = 30 * time.Second
)

// DumpDiagnostics prints error lines followed by a short, deduplicated tail.
// Set E2E_LOG_TAIL=0 for complete container logs.
func (s *Stack) DumpDiagnostics(t *testing.T) {
	t.Helper()

	tail := EnvInt("E2E_LOG_TAIL", defaultLogTail)

	t.Logf("===== failure diagnostics (mode=%s) =====", s.Config.Mode)

	for _, c := range []struct {
		name      string
		container *testcontainers.DockerContainer
	}{
		{agentService, s.Agent},
		{dashboardService, s.Dashboard},
	} {
		if c.container == nil {
			continue
		}

		lines := containerLogLines(t, c.container)
		problems := filterProblems(lines)

		if len(problems) > 0 {
			t.Logf("--- %s: last %d error lines (%d total log lines) ---\n%s",
				c.name, len(problems), len(lines), strings.Join(problems, "\n"))
		}

		if tail <= 0 {
			t.Logf("--- %s: full log (%d lines) ---\n%s",
				c.name, len(lines), strings.Join(lines, "\n"))

			continue
		}

		recent := withoutLines(lastN(lines, tail), problems)
		if len(recent) > 0 {
			t.Logf("--- %s: last %d non-duplicate lines (%d total log lines) ---\n%s",
				c.name, len(recent), len(lines), strings.Join(recent, "\n"))
		}
	}

	t.Log("===== end failure diagnostics; see the failed assertion above =====")
}

func filterProblems(lines []string) []string {
	markers := []string{"ERR ", "ERROR", "PANIC", "FATAL"}

	var out []string

	for _, line := range lines {
		upper := strings.ToUpper(line)

		for _, m := range markers {
			if strings.Contains(upper, m) {
				out = append(out, line)

				break
			}
		}
	}

	return lastN(out, problemLines)
}

func withoutLines(lines, excluded []string) []string {
	skip := make(map[string]struct{}, len(excluded))
	for _, line := range excluded {
		skip[line] = struct{}{}
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if _, found := skip[line]; !found {
			out = append(out, line)
		}
	}

	return out
}

func lastN(lines []string, n int) []string {
	if n <= 0 || len(lines) <= n {
		return lines
	}

	return lines[len(lines)-n:]
}

func containerLogLines(t *testing.T, c *testcontainers.DockerContainer) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), logFetchTimeout)
	defer cancel()

	reader, err := c.Logs(ctx)
	if err != nil {
		t.Logf("read container logs: %v", err)

		return nil
	}
	defer func() { _ = reader.Close() }()

	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Logf("read container logs: %v", err)

		return nil
	}

	text := strings.TrimRight(StripANSI(stripDockerStreamHeaders(raw)), "\n")
	if text == "" {
		return nil
	}

	return strings.Split(text, "\n")
}

// stripDockerStreamHeaders removes the 8-byte multiplexing header Docker prefixes
// to each log frame when a container has no TTY.
func stripDockerStreamHeaders(raw []byte) string {
	const headerLen = 8

	var out strings.Builder

	for len(raw) >= headerLen {
		// A real header starts with a stream type of 0, 1 or 2.
		if raw[0] > 2 {
			break
		}

		size := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7])
		if size < 0 || size > len(raw)-headerLen {
			break
		}

		out.Write(raw[headerLen : headerLen+size])
		raw = raw[headerLen+size:]
	}

	if out.Len() == 0 {
		return string(raw)
	}

	out.Write(raw)

	return out.String()
}
