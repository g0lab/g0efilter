// Package recovery is g0efilter's panic containment boundary.
package recovery

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
)

// PanicMessage is the log message every contained panic is reported under.
const PanicMessage = "panic.recovered"

// ErrPanic wraps a recovered panic so a supervisor can restart the service.
var ErrPanic = errors.New("recovered panic")

const stackBufSize = 8192

// Guard recovers a panic in the calling goroutine. Defer it directly.
func Guard(lg *slog.Logger, component string) {
	value := recover()
	if value == nil {
		return
	}

	report(lg, component, value, stack())
}

// Go runs fn in a new goroutine under Guard.
func Go(lg *slog.Logger, component string, fn func()) {
	go func() {
		defer Guard(lg, component)

		fn()
	}()
}

// Call runs fn under Guard, reporting whether it panicked.
func Call(lg *slog.Logger, component string, fn func()) bool {
	panicked := false

	func() {
		defer func() {
			value := recover()
			if value == nil {
				return
			}

			panicked = true

			report(lg, component, value, stack())
		}()

		fn()
	}()

	return panicked
}

// Recovered runs fn, converting a panic into an error.
func Recovered(fn func() error) (err error) {
	defer func() {
		value := recover()
		if value == nil {
			return
		}

		err = fmt.Errorf("%w: %v\n%s", ErrPanic, value, stack())
	}()

	return fn()
}

func report(lg *slog.Logger, component string, value any, trace string) {
	if lg == nil {
		return
	}

	lg.Error(PanicMessage,
		"component", component,
		"panic", fmt.Sprint(value),
		"stack", trace,
	)
}

func stack() string {
	buf := make([]byte, stackBufSize)
	n := runtime.Stack(buf, false)

	return string(buf[:n])
}
