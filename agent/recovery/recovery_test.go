//nolint:testpackage // Need access to internal implementation details
package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
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

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Len()
}

func newTestLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}

	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func decodeRecords(t *testing.T, buf *syncBuffer) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		var record map[string]any

		err := json.Unmarshal([]byte(line), &record)
		if err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}

		records = append(records, record)
	}

	return records
}

func firstElement(xs []int) int {
	return xs[0]
}

var errServiceStopped = errors.New("service stopped")

func TestGuardContainsPanic(t *testing.T) {
	t.Parallel()

	lg, buf := newTestLogger()

	func() {
		defer Guard(lg, "https")

		panic("boom")
	}()

	records := decodeRecords(t, buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	if records[0]["msg"] != PanicMessage {
		t.Errorf("msg = %v, want %q", records[0]["msg"], PanicMessage)
	}

	if records[0]["component"] != "https" {
		t.Errorf("component = %v, want https", records[0]["component"])
	}

	if records[0]["panic"] != "boom" {
		t.Errorf("panic = %v, want boom", records[0]["panic"])
	}

	stackValue, _ := records[0]["stack"].(string)
	if !strings.Contains(stackValue, "TestGuardContainsPanic") {
		t.Errorf("stack does not name the panicking function: %q", stackValue)
	}
}

func TestGuardIsSilentWithoutPanic(t *testing.T) {
	t.Parallel()

	lg, buf := newTestLogger()

	func() {
		defer Guard(lg, "https")
	}()

	if buf.Len() != 0 {
		t.Errorf("logged %q for a clean return", buf.String())
	}
}

func TestGuardToleratesNilLogger(t *testing.T) {
	t.Parallel()

	func() {
		defer Guard(nil, "https")

		panic("boom")
	}()
}

func TestGuardContainsNonStringPanic(t *testing.T) {
	t.Parallel()

	lg, buf := newTestLogger()

	func() {
		defer Guard(lg, "dns")

		_ = firstElement(nil)
	}()

	records := decodeRecords(t, buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	panicValue, _ := records[0]["panic"].(string)
	if !strings.Contains(panicValue, "index out of range") {
		t.Errorf("panic = %q, want the runtime error text", panicValue)
	}
}

func TestGoContainsPanic(t *testing.T) {
	t.Parallel()

	lg, buf := newTestLogger()

	Go(lg, "copy", func() { panic("boom") })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), PanicMessage) {
		time.Sleep(5 * time.Millisecond)
	}

	if !strings.Contains(buf.String(), PanicMessage) {
		t.Errorf("panic in a Go goroutine was not reported: %q", buf.String())
	}
}

func TestCallReportsWhetherItPanicked(t *testing.T) {
	t.Parallel()

	lg, buf := newTestLogger()

	if Call(lg, "policy_watcher", func() {}) {
		t.Error("Call reported a panic for a clean function")
	}

	if buf.Len() != 0 {
		t.Errorf("logged %q for a clean call", buf.String())
	}

	if !Call(lg, "policy_watcher", func() { panic("boom") }) {
		t.Error("Call did not report the panic")
	}

	if !strings.Contains(buf.String(), PanicMessage) {
		t.Errorf("panic was not reported: %q", buf.String())
	}
}

func TestCallKeepsALoopAlive(t *testing.T) {
	t.Parallel()

	lg, _ := newTestLogger()

	iterations := 0

	for i := range 5 {
		Call(lg, "learner", func() {
			iterations++

			if i == 2 {
				panic("boom")
			}
		})
	}

	if iterations != 5 {
		t.Errorf("ran %d iterations, want 5: a panic must not break the loop", iterations)
	}
}

func TestRecoveredConvertsPanicToError(t *testing.T) {
	t.Parallel()

	err := Recovered(func() error { panic("boom") })
	if err == nil {
		t.Fatal("Recovered returned nil for a panicking function")
	}

	if !errors.Is(err, ErrPanic) {
		t.Errorf("err = %v, want it to wrap ErrPanic", err)
	}

	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want the panic value included", err)
	}

	if !strings.Contains(err.Error(), "TestRecoveredConvertsPanicToError") {
		t.Errorf("err = %v, want a stack trace included", err)
	}
}

func TestRecoveredPassesThroughNormalResults(t *testing.T) {
	t.Parallel()

	err := Recovered(func() error { return errServiceStopped })
	if !errors.Is(err, errServiceStopped) {
		t.Errorf("err = %v, want the service error unchanged", err)
	}

	if errors.Is(err, ErrPanic) {
		t.Error("a normal error must not be reported as a panic")
	}

	err = Recovered(func() error { return nil })
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}
