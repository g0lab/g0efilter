package g0efilter

import (
	"log/slog"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/agent/recovery"
)

type group struct {
	wg sync.WaitGroup
}

func (g *group) run(lg *slog.Logger, component string, fn func()) {
	if g == nil {
		recovery.Go(lg, component, fn)

		return
	}

	g.wg.Go(func() {
		defer recovery.Guard(lg, component)

		fn()
	})
}

func (g *group) wait(timeout time.Duration) bool {
	if g == nil {
		return true
	}

	done := make(chan struct{})

	go func() {
		g.wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
