package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/shared/logging"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	cases := map[string]slog.Level{
		"TRACE":   logging.LevelTrace,
		"trace":   logging.LevelTrace,
		"DEBUG":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"WARN":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"ERROR":   slog.LevelError,
		"bogus":   slog.LevelInfo,
	}

	for in, want := range cases {
		if got := logging.ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// The tests below drive the process-global zerolog level and Shutdown's global
// hook, so they must not run in parallel with each other.

//nolint:paralleltest // mutates the process-global zerolog logger
func TestNewLogsAboveLevel(t *testing.T) {
	var buf bytes.Buffer

	lg := logging.New("info", &buf)
	lg.Info("hello.world", "foo", "bar")
	lg.Debug("debug.hidden")

	out := buf.String()
	if !strings.Contains(out, "hello.world") || !strings.Contains(out, "bar") {
		t.Fatalf("info line missing: %q", out)
	}

	if strings.Contains(out, "debug.hidden") {
		t.Fatalf("debug line should be filtered at info level: %q", out)
	}
}

// allowlisted ALLOWED/nflog events are downgraded to debug for the terminal.
//
//nolint:paralleltest // mutates the process-global zerolog logger
func TestAllowlistedIPDowngraded(t *testing.T) {
	var buf bytes.Buffer

	lg := logging.New("info", &buf)
	lg.Info("flow", "action", "ALLOWED", "component", "nflog", "destination_ip", "1.2.3.4")
	lg.Info("flow", "action", "ALLOWED", "component", "https", "http_host", "keep.example")

	out := buf.String()
	if strings.Contains(out, "1.2.3.4") {
		t.Fatalf("allowlisted nflog ALLOWED should be suppressed at info: %q", out)
	}

	if !strings.Contains(out, "keep.example") {
		t.Fatalf("non-nflog ALLOWED should still log: %q", out)
	}
}

type fakeHook struct {
	mu      sync.Mutex
	records []map[string]any
	stopped bool
}

func (f *fakeHook) Handle(_ context.Context, _ time.Time, _ string, attrs map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.records = append(f.records, attrs)
}

func (f *fakeHook) Stop(time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stopped = true
}

func (f *fakeHook) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.records)
}

// A hook receives every record, including ones below the terminal threshold.
//
//nolint:paralleltest // mutates the process-global zerolog logger and hook
func TestHookReceivesSubThresholdRecords(t *testing.T) {
	var buf bytes.Buffer

	hook := &fakeHook{}
	lg := logging.New("info", &buf, logging.WithHook(hook))

	lg.Debug("below.threshold", "action", "BLOCKED")
	lg.Info("at.threshold")

	if got := hook.count(); got != 2 {
		t.Fatalf("hook saw %d records, want 2 (incl sub-threshold)", got)
	}

	if strings.Contains(buf.String(), "below.threshold") {
		t.Fatalf("sub-threshold record should not reach the terminal: %q", buf.String())
	}
}

//nolint:paralleltest // mutates the process-global zerolog logger and hook
func TestWithAttrsCarriedToHookAndTerminal(t *testing.T) {
	var buf bytes.Buffer

	hook := &fakeHook{}
	lg := logging.New("info", &buf, logging.WithHook(hook)).With("instance", "node-1")

	lg.Info("event")

	if !strings.Contains(buf.String(), "node-1") {
		t.Fatalf("With() attr missing from terminal: %q", buf.String())
	}

	if hook.count() != 1 || hook.records[0]["instance"] != "node-1" {
		t.Fatalf("With() attr missing from hook: %+v", hook.records)
	}
}

//nolint:paralleltest // relies on the process-global registered hook
func TestShutdownStopsHook(t *testing.T) {
	hook := &fakeHook{}
	_ = logging.New("info", &bytes.Buffer{}, logging.WithHook(hook))

	logging.Shutdown(time.Second)

	if !hook.stopped {
		t.Fatal("Shutdown did not stop the registered hook")
	}
}
