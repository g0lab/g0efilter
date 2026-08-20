//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
	"github.com/g0lab/g0efilter/agent/recovery"
	"github.com/g0lab/g0efilter/shared/actions"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, err := b.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("write log buffer: %w", err)
	}

	return n, nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

var errListenerClosed = errors.New("listener closed")

func supervisorLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}

	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func fastRetry(delay time.Duration) retryPolicy {
	return retryPolicy{initial: delay, max: delay, level: slog.LevelError}
}

func TestRetryPolicyNext(t *testing.T) {
	t.Parallel()

	fixed := retryPolicy{initial: 5 * time.Second, max: 5 * time.Second, level: slog.LevelError}
	if got := fixed.next(5 * time.Second); got != 5*time.Second {
		t.Errorf("fixed policy grew to %v", got)
	}

	backoff := retryPolicy{initial: time.Second, max: 8 * time.Second, level: slog.LevelWarn}

	tests := []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, time.Second},
		{time.Second, 2 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 8 * time.Second},
		{time.Minute, 8 * time.Second},
	}

	for _, tt := range tests {
		if got := backoff.next(tt.current); got != tt.want {
			t.Errorf("next(%v) = %v, want %v", tt.current, got, tt.want)
		}
	}
}

func TestRunServiceWithRetryDelaysAfterUnexpectedNilReturn(t *testing.T) {
	t.Parallel()

	lg, buf := supervisorLogger()

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	var calls atomic.Int64

	tracked := &group{}

	runServiceWithRetry(ctx, tracked, "dns", lg, fastRetry(50*time.Millisecond), func() error {
		calls.Add(1)

		return nil
	})

	if !tracked.wait(5 * time.Second) {
		t.Fatal("the supervised goroutine did not exit after cancellation")
	}

	got := calls.Load()

	const maxCalls = 15

	if got > maxCalls {
		t.Errorf("service restarted %d times in 250ms, want at most %d", got, maxCalls)
	}

	if got < 2 {
		t.Errorf("service ran %d times, want it to be restarted", got)
	}

	if !strings.Contains(buf.String(), "dns.exited_unexpectedly") {
		t.Errorf("an unexpected nil return was not reported: %q", buf.String())
	}
}

func TestRunServiceWithRetryRestartsAfterPanic(t *testing.T) {
	t.Parallel()

	lg, buf := supervisorLogger()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var calls atomic.Int64

	restarted := make(chan struct{})

	tracked := &group{}

	runServiceWithRetry(ctx, tracked, "https", lg, fastRetry(20*time.Millisecond), func() error {
		switch calls.Add(1) {
		case 1:
			panic("hostile connection")
		case 2:
			close(restarted)
		}

		<-ctx.Done()

		return ctx.Err()
	})

	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the service was not restarted after it panicked")
	}

	cancel()

	if !tracked.wait(5 * time.Second) {
		t.Fatal("the supervised goroutine did not exit after cancellation")
	}

	logged := buf.String()
	if !strings.Contains(logged, "https.stopped") {
		t.Errorf("the panic was not reported as a service failure: %q", logged)
	}

	if !strings.Contains(logged, recovery.ErrPanic.Error()) {
		t.Errorf("the failure was not identified as a panic: %q", logged)
	}
}

func TestRunServiceWithRetryStopsOnCancellation(t *testing.T) {
	t.Parallel()

	lg, _ := supervisorLogger()

	ctx, cancel := context.WithCancel(t.Context())

	tracked := &group{}

	runServiceWithRetry(ctx, tracked, "http", lg, fastRetry(10*time.Millisecond), func() error {
		<-ctx.Done()

		return errListenerClosed
	})

	cancel()

	if !tracked.wait(5 * time.Second) {
		t.Fatal("the supervised goroutine kept running after cancellation")
	}
}

func TestRunServiceWithRetryContainsAPanicInEveryRestart(t *testing.T) {
	t.Parallel()

	lg, _ := supervisorLogger()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	var calls atomic.Int64

	tracked := &group{}

	runServiceWithRetry(ctx, tracked, "nflog", lg, fastRetry(20*time.Millisecond), func() error {
		calls.Add(1)

		panic("always")
	})

	if !tracked.wait(5 * time.Second) {
		t.Fatal("the supervised goroutine did not exit after cancellation")
	}

	if calls.Load() < 2 {
		t.Errorf("a repeatedly panicking service was restarted %d times, want it kept alive", calls.Load())
	}
}

func TestGroupWaitJoinsTrackedGoroutines(t *testing.T) {
	t.Parallel()

	tracked := &group{}
	lg, _ := supervisorLogger()

	release := make(chan struct{})

	var finished atomic.Int64

	for range 3 {
		tracked.run(lg, "test", func() {
			<-release

			finished.Add(1)
		})
	}

	if tracked.wait(50 * time.Millisecond) {
		t.Fatal("wait reported completion while goroutines were still running")
	}

	close(release)

	if !tracked.wait(5 * time.Second) {
		t.Fatal("wait timed out on goroutines that had finished")
	}

	if finished.Load() != 3 {
		t.Errorf("%d of 3 goroutines finished", finished.Load())
	}
}

func TestGroupRunContainsPanic(t *testing.T) {
	t.Parallel()

	tracked := &group{}
	lg, buf := supervisorLogger()

	tracked.run(lg, "policy_watcher", func() { panic("boom") })

	if !tracked.wait(5 * time.Second) {
		t.Fatal("a panicking goroutine was never joined")
	}

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Errorf("panic in a tracked goroutine was not contained: %q", buf.String())
	}
}

func TestNilGroupStillRuns(t *testing.T) {
	t.Parallel()

	lg, _ := supervisorLogger()

	var tracked *group

	done := make(chan struct{})

	tracked.run(lg, "test", func() { close(done) })

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a nil group did not run the function")
	}

	if !tracked.wait(time.Millisecond) {
		t.Error("a nil group must not block shutdown")
	}
}

func TestSleepCtxReportsCancellation(t *testing.T) {
	t.Parallel()

	if !sleepCtx(t.Context(), time.Millisecond) {
		t.Error("sleepCtx reported cancellation for a live context")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if sleepCtx(ctx, time.Hour) {
		t.Error("sleepCtx waited out the delay on a canceled context")
	}
}

func freeTCPPort(t *testing.T) string {
	t.Helper()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	err = ln.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	return port
}

func reloadTestConfig(t *testing.T) config {
	t.Helper()

	return config{
		mode:            actions.ModeHTTPS,
		defaultAction:   policy.DefaultActionDeny,
		httpPort:        freeTCPPort(t),
		httpsPort:       freeTCPPort(t),
		maxConns:        defaultMaxConns,
		connMaxLifetime: defaultIdleTimeout,
	}
}

func TestRestartServicesRebindsWithoutConflict(t *testing.T) {
	t.Parallel()

	lg, buf := supervisorLogger()

	cfg := reloadTestConfig(t)

	pol := &policy.Policy{AllowDomains: []string{"example.com"}}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	svc := startServiceGroup(ctx, cfg, pol, lg)

	defer func() { svc.stop(lg) }()

	waitForListeners(t, buf, 2)

	listeners := 2

	for range 5 {
		restartServices(ctx, cfg, pol, lg, &svc)

		listeners += 2

		waitForListeners(t, buf, listeners)
	}

	for _, bad := range []string{"tcp.listen_error", "https.stopped", "http.stopped"} {
		if strings.Contains(buf.String(), bad) {
			t.Errorf("reload churn produced %s:\n%s", bad, buf.String())
		}
	}
}

func waitForListeners(t *testing.T, buf *syncBuffer, want int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(buf.String(), ".filter_listen") >= want {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("only %d of %d listeners came up:\n%s",
		strings.Count(buf.String(), ".filter_listen"), want, buf.String())
}

func TestFilterRetryRecoversFastThenBacksOff(t *testing.T) {
	t.Parallel()

	if filterRetry.initial != time.Second {
		t.Errorf("filter services retry after %v, want 1s so a transient bind failure is a short outage",
			filterRetry.initial)
	}

	delay := filterRetry.initial

	seen := make([]time.Duration, 0, 5)

	for range 5 {
		seen = append(seen, delay)
		delay = filterRetry.next(delay)
	}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	if !slices.Equal(seen, want) {
		t.Errorf("filter backoff = %v, want %v", seen, want)
	}

	if filterRetry.max != retryDelay {
		t.Errorf("filter backoff caps at %v, want %v so recovery stays responsive", filterRetry.max, retryDelay)
	}
}
