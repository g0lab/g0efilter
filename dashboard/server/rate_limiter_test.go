//nolint:testpackage // Need access to internal implementation details
package server

import (
	"testing"
	"time"
)

func TestNewRateLimiterDefaults(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(0, -1)
	if rl.rps != 50 {
		t.Errorf("rps = %v, want default 50", rl.rps)
	}

	if rl.burst != 100 {
		t.Errorf("burst = %v, want default 100", rl.burst)
	}

	rl = newRateLimiter(5, 10)
	if rl.rps != 5 || rl.burst != 10 {
		t.Errorf("rps/burst = %v/%v, want 5/10", rl.rps, rl.burst)
	}
}

func TestRateLimiterBurstThenDeny(t *testing.T) {
	t.Parallel()

	// Negligible refill rate so the burst budget is the only allowance.
	rl := newRateLimiter(0.001, 3)

	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}

	if rl.Allow("client") {
		t.Fatal("request beyond burst should be denied")
	}

	if rl.Allow("client") {
		t.Fatal("request should stay denied while tokens are exhausted")
	}
}

func TestRateLimiterRefillAfterWait(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(100, 1)

	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}

	if rl.Allow("client") {
		t.Fatal("second immediate request should be denied")
	}

	// At 100 rps, 50ms refills well over the single token needed.
	time.Sleep(50 * time.Millisecond)

	if !rl.Allow("client") {
		t.Fatal("request after refill window should be allowed")
	}
}

func TestRateLimiterPerClientIsolation(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(0.001, 2)

	for range 2 {
		if !rl.Allow("greedy") {
			t.Fatal("greedy client should get its burst")
		}
	}

	if rl.Allow("greedy") {
		t.Fatal("greedy client should be denied after burst")
	}

	// Another client keeps its own full budget.
	for i := range 2 {
		if !rl.Allow("polite") {
			t.Fatalf("polite client request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterCleanupRemovesStaleEntries(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(10, 5)

	rl.mu.Lock()
	rl.tokens["stale"] = 1
	rl.last["stale"] = time.Now().Add(-2 * time.Hour)
	rl.tokens["recent"] = 1
	rl.last["recent"] = time.Now().Add(-time.Minute)
	rl.lastCleanup = time.Now().Add(-11 * time.Minute) // force the periodic cleanup path
	rl.mu.Unlock()

	rl.Allow("trigger")

	rl.mu.Lock()
	_, staleKept := rl.last["stale"]
	_, staleTokensKept := rl.tokens["stale"]
	_, recentKept := rl.last["recent"]
	rl.mu.Unlock()

	if staleKept || staleTokensKept {
		t.Error("entries older than one hour should be removed by cleanup")
	}

	if !recentKept {
		t.Error("recent entries should survive cleanup")
	}
}

func TestRateLimiterCleanupOnMaxEntries(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(10, 5)

	rl.mu.Lock()
	rl.maxEntries = 1
	rl.tokens["old-a"] = 1
	rl.last["old-a"] = time.Now().Add(-90 * time.Minute)
	rl.tokens["old-b"] = 1
	rl.last["old-b"] = time.Now().Add(-90 * time.Minute)
	rl.mu.Unlock()

	// len(tokens) > maxEntries triggers cleanup even though lastCleanup is recent.
	rl.Allow("trigger")

	rl.mu.Lock()
	_, aKept := rl.last["old-a"]
	_, bKept := rl.last["old-b"]
	rl.mu.Unlock()

	if aKept || bKept {
		t.Error("stale entries should be removed when the map exceeds maxEntries")
	}
}
