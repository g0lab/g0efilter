package e2e_test

import (
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

// Deliberately not parallel: the idle-CPU sample would be inflated by whatever
// else is driving the host, in particular the load phase.
func TestPhase11Resources(t *testing.T) {
	var (
		maxMemoryMiB    = int64(harness.EnvInt("E2E_MAX_MEMORY_MIB", 256))
		maxGrowthMiB    = int64(harness.EnvInt("E2E_MAX_MEMORY_GROWTH_MIB", 64))
		maxIdleCPU      = float64(harness.EnvInt("E2E_MAX_IDLE_CPU_PERCENT", 25))
		cpuSampleWindow = harness.EnvDuration("E2E_CPU_SAMPLE_WINDOW", 6*time.Second)
	)

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.BaselineConfig(t, mode))

	before := s.MemoryBytes(t)
	t.Logf("baseline memory: %d MiB", harness.MiB(before))

	for range 6 {
		s.AssertAllowed(t, "https://github.com")
		s.AssertBlocked(t, "https://google.com")
	}

	time.Sleep(3 * time.Second)

	after := s.MemoryBytes(t)

	growth := max(after-before, 0)

	t.Logf("memory after traffic: %d MiB (growth %d MiB)", harness.MiB(after), harness.MiB(growth))

	if harness.MiB(after) > maxMemoryMiB {
		t.Errorf("memory %d MiB exceeds the %d MiB ceiling", harness.MiB(after), maxMemoryMiB)
	}

	if harness.MiB(growth) > maxGrowthMiB {
		t.Errorf("memory grew %d MiB, limit %d MiB", harness.MiB(growth), maxGrowthMiB)
	}

	idle := s.IdleCPUPercent(t, cpuSampleWindow)
	t.Logf("idle CPU: %.1f%% (limit %.0f%%)", idle, maxIdleCPU)

	if idle > maxIdleCPU {
		t.Errorf("idle CPU %.1f%% exceeds %.0f%%", idle, maxIdleCPU)
	}

	if running, restarts := s.AgentHealth(t); !running || restarts > 0 {
		t.Errorf("agent unhealthy after traffic: running=%v restarts=%d", running, restarts)
	}
}

func TestPhase12Load(t *testing.T) {
	t.Parallel()

	var (
		total          = harness.EnvInt("LOAD_TOTAL", 500)
		totalHTTP      = harness.EnvInt("LOAD_TOTAL_HTTP", total/2)
		concurrency    = harness.EnvInt("LOAD_CONCURRENCY", 50)
		allowedTotal   = harness.EnvInt("LOAD_ALLOWED", 25)
		requestTimeout = time.Duration(harness.EnvInt("LOAD_MAX_TIME", 8)) * time.Second
		maxLatency     = time.Duration(harness.EnvInt("LOAD_MAX_LATENCY_MS", 2000)) * time.Millisecond
		maxMemoryMi    = int64(harness.EnvInt("E2E_LOAD_MAX_MEMORY_MIB", 384))
		allowedMin     = harness.EnvInt("LOAD_MIN_ALLOWED_PERCENT", 100)
		blockedURL     = harness.Env("LOAD_BLOCKED_URL", "https://google.com")
		blockedHTTPURL = harness.Env("LOAD_BLOCKED_URL_HTTP", "http://google.com")
		// Two independent providers, both already covered by BaselinePolicy
		// (github.com by domain, 1.1.1.1 by IP), so one being degraded cannot sink
		// the success rate on its own.
		allowedURLs = strings.Fields(harness.Env("LOAD_ALLOWED_URLS",
			"https://github.com https://1.1.1.1"))
	)

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.BaselineConfig(t, mode))

	s.WritePolicyAndWait(t, harness.BaselinePolicy)

	loadMark := s.AgentLogMark(t)

	t.Run("blocked traffic does not leak under concurrency", func(t *testing.T) {
		countProbe := s.RunBatch(t, harness.BatchRequest{
			URL: blockedURL, Count: 7, Concurrency: 3,
			Timeout: requestTimeout, IPv4Only: true,
		})
		if countProbe.Attempted != 7 {
			t.Fatalf("non-divisible batch attempted %d requests, want 7", countProbe.Attempted)
		}

		httpsBatch := s.RunBatch(t, harness.BatchRequest{
			URL: blockedURL, Count: total, Concurrency: concurrency,
			Timeout: requestTimeout, IPv4Only: true,
		})
		t.Logf("blocked https: %+v", httpsBatch)

		if httpsBatch.Attempted != total {
			t.Errorf("blocked HTTPS attempted %d requests, want %d", httpsBatch.Attempted, total)
		}

		if httpsBatch.Succeeded > 0 {
			t.Errorf("%d/%d blocked HTTPS requests connected", httpsBatch.Succeeded, httpsBatch.Attempted)
		}

		httpBatch := s.RunBatch(t, harness.BatchRequest{
			URL: blockedHTTPURL, Count: totalHTTP, Concurrency: concurrency,
			Timeout: requestTimeout, IPv4Only: true,
		})
		t.Logf("blocked http: %+v", httpBatch)

		if httpBatch.Attempted != totalHTTP {
			t.Errorf("blocked HTTP attempted %d requests, want %d", httpBatch.Attempted, totalHTTP)
		}

		if httpBatch.Succeeded > 0 {
			t.Errorf("%d/%d blocked HTTP requests connected", httpBatch.Succeeded, httpBatch.Attempted)
		}

		if httpsBatch.LatencyMS.Median > maxLatency.Milliseconds() {
			t.Errorf("median blocked latency %dms exceeds %dms",
				httpsBatch.LatencyMS.Median, maxLatency.Milliseconds())
		}

		t.Logf("blocked HTTPS latency: median=%dms p95=%dms max=%dms",
			httpsBatch.LatencyMS.Median, httpsBatch.LatencyMS.P95, httpsBatch.LatencyMS.Max)
	})

	t.Run("the DNS proxy rate-limits the flood rather than absorbing it", func(t *testing.T) {
		if mode == harness.FilterModeHTTPS {
			t.Skip("https mode does not intercept DNS")
		}

		if total+totalHTTP < 200 {
			t.Skip("configured load is too small to require the 100-token DNS bucket to rate-limit")
		}

		// Confirm the flood exercised the per-source limiter.
		n := s.AgentEventCountSince(t, loadMark, harness.EventMatcher{Event: "dns.rate_limited"})
		t.Logf("dns.rate_limited events during the flood: %d", n)

		if n == 0 {
			t.Errorf("expected the DNS rate limiter to engage under a %d-request flood", total+totalHTTP)
		}
	})

	t.Run("allowed traffic still succeeds under load", func(t *testing.T) {
		// Measure the filter after the limiter refills.
		time.Sleep(harness.EnvDuration("LOAD_RECOVERY_PAUSE", 4*time.Second))

		blockedTotal := concurrency
		if mode != harness.FilterModeHTTPS {
			blockedTotal = 15
		}

		mixedMark := s.AgentLogMark(t)

		mixed := s.RunMixedBatch(t, harness.MixedBatchRequest{
			AllowedURLs: allowedURLs, BlockedURL: blockedURL,
			AllowedCount: allowedTotal, BlockedCount: blockedTotal,
			Timeout: max(requestTimeout, 15*time.Second), IPv4Only: true,
		})
		t.Logf("mixed allowed/blocked load: %+v", mixed)

		if mixed.AllowedAttempted != allowedTotal || mixed.BlockedAttempted != blockedTotal {
			t.Errorf("mixed batch attempted allowed=%d/%d blocked=%d/%d",
				mixed.AllowedAttempted, allowedTotal, mixed.BlockedAttempted, blockedTotal)
		}

		if mixed.BlockedSucceeded > 0 {
			t.Errorf("%d/%d blocked requests connected during mixed load",
				mixed.BlockedSucceeded, mixed.BlockedAttempted)
		}

		// The decisive check: whether the filter permitted the traffic is entirely
		// under its control, so it takes zero tolerance. The success rate below is
		// only a backstop, and is loose because it also measures the upstream.
		for _, url := range allowedURLs {
			if n := s.CountVerdictsSince(t, mixedMark, url, "BLOCKED"); n > 0 {
				t.Errorf("filter recorded %d BLOCKED verdicts for allowed %s under load", n, url)
			}
		}

		percent := mixed.AllowedSucceeded * 100 / max(mixed.AllowedAttempted, 1)
		if percent < allowedMin {
			t.Errorf("allowed success rate %d%% below the %d%% floor (%+v)", percent, allowedMin, mixed)
		}
	})

	t.Run("the agent stays healthy", func(t *testing.T) {
		running, restarts := s.AgentHealth(t)
		if !running || restarts > 0 {
			t.Errorf("agent unhealthy after load: running=%v restarts=%d", running, restarts)
		}

		mem := harness.MiB(s.MemoryBytes(t))
		t.Logf("memory after load: %d MiB", mem)

		if mem > maxMemoryMi {
			t.Errorf("memory %d MiB exceeds the %d MiB ceiling after load", mem, maxMemoryMi)
		}
	})
}
