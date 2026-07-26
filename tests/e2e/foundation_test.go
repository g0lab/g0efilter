package e2e_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
	tclog "github.com/testcontainers/testcontainers-go/log"
)

func TestMain(m *testing.M) {
	if harness.Env("E2E_TESTCONTAINERS_LOG", "0") != "1" {
		tclog.SetDefault(log.New(io.Discard, "", 0))
	}

	err := harness.EnsureImages()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	code := m.Run()

	harness.ShutdownShared()

	os.Exit(code)
}

func TestFoundation(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	stack := harness.Shared(t, harness.BaselineConfig(t, mode))
	stack.ResetPolicy(t)

	t.Run("service handles resolve", func(t *testing.T) {
		for name, c := range map[string]any{
			"agent":     stack.Agent,
			"dashboard": stack.Dashboard,
			"tester":    stack.Tester,
		} {
			if c == nil {
				t.Errorf("no container handle for %s", name)
			}
		}
	})

	t.Run("tester shares the agent network namespace", func(t *testing.T) {
		// Same namespace means the same interface addresses; a mismatch would mean
		// traffic tests were not exercising the filtered path at all.
		agentAddrs := stack.ExecAgent(t, "cat", "/proc/net/fib_trie")
		testerAddrs := stack.ExecTester(t, "cat", "/proc/net/fib_trie")

		if agentAddrs.ExitCode != 0 || testerAddrs.ExitCode != 0 {
			t.Fatalf("could not read interface tables: agent=%d tester=%d",
				agentAddrs.ExitCode, testerAddrs.ExitCode)
		}

		if agentAddrs.Output != testerAddrs.Output {
			t.Errorf("tester is not in the agent's network namespace")
		}
	})

	t.Run("dashboard is reachable from the tester", func(t *testing.T) {
		res := stack.ExecTester(t, "curl", "-sf", "http://127.0.0.1:8081/health")
		if res.ExitCode != 0 {
			t.Fatalf("health check failed: exit=%d output=%q", res.ExitCode, res.Output)
		}
	})

	t.Run("dashboard is reachable on a mapped host port", func(t *testing.T) {
		if strings.HasSuffix(stack.DashboardURL, ":8081") {
			t.Errorf("dashboard was published on the fixed port 8081 (%s); "+
				"concurrent stacks would collide", stack.DashboardURL)
		}

		client := &http.Client{Timeout: 10 * time.Second}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.DashboardURL+"/health", nil)
		if err != nil {
			t.Fatalf("build health request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s/health: %v", stack.DashboardURL, err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("health status = %d, want 200 (body %q)", resp.StatusCode, body)
		}
	})

	t.Run("agent applied the baseline policy", func(t *testing.T) {
		res := stack.ExecAgent(t, "cat", "/app/policy/policy.yaml")
		if !strings.Contains(res.Output, "github.com") {
			t.Errorf("agent cannot see the seeded policy: %q", res.Output)
		}
	})

	t.Run("nftables rules are installed", func(t *testing.T) {
		res := stack.ExecAgent(t, "nft", "list", "table", "ip", "g0efilter_v4")
		if res.ExitCode != 0 {
			t.Fatalf("nft list failed: exit=%d output=%q", res.ExitCode, res.Output)
		}

		if !strings.Contains(res.Output, "allow_daddr_v4") {
			t.Errorf("expected the allowlist set in the ruleset:\n%s", res.Output)
		}
	})

	t.Run("a second stack starts without name collisions", func(t *testing.T) {
		// The decisive isolation check: fixed container names or a fixed host port
		// would make this fail, and with it any hope of concurrent suites.
		other := harness.StartStack(t, harness.BaselineConfig(t, mode))

		if other.DashboardURL == stack.DashboardURL {
			t.Errorf("both stacks published the same URL %s", other.DashboardURL)
		}

		res := other.ExecTester(t, "curl", "-sf", "http://127.0.0.1:8081/health")
		if res.ExitCode != 0 {
			t.Errorf("second stack unhealthy: exit=%d output=%q", res.ExitCode, res.Output)
		}
	})
}

func TestSharedStackIsReused(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)

	first := harness.Shared(t, harness.BaselineConfig(t, mode))
	second := harness.Shared(t, harness.BaselineConfig(t, mode))

	if first != second {
		t.Errorf("identical configurations started two stacks (%s vs %s)",
			first.DashboardURL, second.DashboardURL)
	}
}
