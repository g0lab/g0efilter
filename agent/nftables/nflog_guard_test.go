//nolint:testpackage // Need access to internal implementation details
package nftables

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/agent/recovery"
)

//nolint:exhaustruct
func TestGuardNflogHookContainsPanic(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	lg := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	hook := guardNflogHook(lg, func(nflog.Attribute) int {
		panic("malformed packet")
	})

	verdict := hook(nflog.Attribute{})

	if verdict != 0 {
		t.Errorf("verdict = %d, want 0 so the stream keeps receiving", verdict)
	}

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Errorf("panic in the nflog hook was not contained: %q", buf.String())
	}

	if !strings.Contains(buf.String(), `"component":"nflog"`) {
		t.Errorf("panic was not attributed to nflog: %q", buf.String())
	}
}

//nolint:exhaustruct
func TestGuardNflogHookPassesThroughVerdicts(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.DiscardHandler)

	calls := 0
	hook := guardNflogHook(lg, func(nflog.Attribute) int {
		calls++

		return 0
	})

	for range 3 {
		if got := hook(nflog.Attribute{}); got != 0 {
			t.Errorf("verdict = %d, want 0", got)
		}
	}

	if calls != 3 {
		t.Errorf("wrapped hook ran %d times, want 3", calls)
	}
}
