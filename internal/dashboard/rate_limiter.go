package dashboard

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

type rateLimiter struct {
	mu          sync.Mutex
	tokens      map[string]float64
	last        map[string]time.Time
	rps         float64
	burst       float64
	maxEntries  int
	lastCleanup time.Time
}

// newRateLimiter creates a token bucket rate limiter with the specified requests per second and burst size.
func newRateLimiter(rps, burst float64) *rateLimiter {
	if rps <= 0 {
		rps = 50
	}

	if burst <= 0 {
		burst = 100
	}

	return &rateLimiter{
		tokens:      map[string]float64{},
		last:        map[string]time.Time{},
		rps:         rps,
		burst:       burst,
		maxEntries:  10000, // Prevent unlimited memory growth
		lastCleanup: time.Now(),
	}
}

// Allow checks if a request from the given key (IP) is permitted under the rate limit.
func (rl *rateLimiter) Allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup to prevent memory leaks
	if len(rl.tokens) > rl.maxEntries || now.Sub(rl.lastCleanup) > 10*time.Minute {
		before := len(rl.tokens)
		rl.cleanup(now)
		after := len(rl.tokens)
		rl.lastCleanup = now

		if before != after {
			slog.Debug("rate_limiter.cleanup",
				"before", before,
				"after", after,
				"removed", before-after,
			)
		}

		// Warn if approaching max entries
		if after > rl.maxEntries*8/10 {
			slog.Warn("rate_limiter.high_memory",
				"entries", after,
				"max_entries", rl.maxEntries,
				"usage_percent", (after*100)/rl.maxEntries,
				"warning", "rate limiter using significant memory",
			)
		}
	}

	t := rl.tokens[key]
	last := rl.last[key]
	dt := now.Sub(last).Seconds()

	// Replenish tokens (cap at burst limit)
	t += dt * rl.rps
	if t > rl.burst {
		t = rl.burst
	}

	if t < 1.0 {
		rl.tokens[key] = t
		rl.last[key] = now

		slog.Log(context.Background(), logging.LevelTrace, "rate_limiter.denied",
			"key", key,
			"tokens", t,
		)

		return false
	}

	rl.tokens[key] = t - 1.0
	rl.last[key] = now

	slog.Log(context.Background(), logging.LevelTrace, "rate_limiter.allowed",
		"key", key,
		"tokens_remaining", t-1.0,
	)

	return true
}

// cleanup removes entries older than 1 hour to prevent memory leaks.
func (rl *rateLimiter) cleanup(now time.Time) {
	cutoff := now.Add(-time.Hour)
	for key, lastSeen := range rl.last {
		if lastSeen.Before(cutoff) {
			delete(rl.tokens, key)
			delete(rl.last, key)
		}
	}
}
