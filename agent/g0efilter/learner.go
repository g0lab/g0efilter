package g0efilter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
	"github.com/g0lab/g0efilter/agent/recovery"
)

const (
	learnFlushInterval = 2 * time.Second
	// learnerMaxSeen bounds memory and policy-file growth; past it new values are dropped.
	learnerMaxSeen = 10000
)

// learner batches domains/IPs observed in learning mode and appends them to the
// policy file. Batching keeps one file write per flush instead of one per flow,
// which also limits policy-reload churn from the file watcher.
type learner struct {
	policyPath string
	lg         *slog.Logger

	mu        sync.Mutex
	seen      map[string]struct{}
	pending   []learnEntry
	capWarned bool
}

type learnEntry struct {
	kind  string // "domain" or "ip"
	value string
}

// learnFunc adapts an optional learner to the filter.Options.OnLearn callback.
func learnFunc(l *learner) func(kind, value string) {
	if l == nil {
		return nil
	}

	return l.record
}

func newLearner(policyPath string, lg *slog.Logger) *learner {
	return &learner{
		policyPath: policyPath,
		lg:         lg,
		seen:       make(map[string]struct{}),
		pending:    nil,
	}
}

// record queues an observed value; safe to call from filter goroutines.
func (l *learner) record(kind, value string) {
	if value == "" {
		return
	}

	key := kind + ":" + value

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, dup := l.seen[key]; dup {
		return
	}

	if len(l.seen) >= learnerMaxSeen {
		if !l.capWarned {
			l.capWarned = true
			l.lg.Warn("learning.cap_reached", "max", learnerMaxSeen, "dropped", key)
		}

		return
	}

	l.seen[key] = struct{}{}
	l.pending = append(l.pending, learnEntry{kind: kind, value: value})
}

// run flushes queued entries to the policy file until the context is cancelled.
func (l *learner) run(ctx context.Context) {
	t := time.NewTicker(learnFlushInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			recovery.Call(l.lg, "learner", l.flush)

			return
		case <-t.C:
			recovery.Call(l.lg, "learner", l.flush)
		}
	}
}

func (l *learner) flush() {
	l.mu.Lock()
	batch := l.pending
	l.pending = nil
	l.mu.Unlock()

	for _, e := range batch {
		var err error

		switch e.kind {
		case "ip":
			err = policy.AppendIP(l.policyPath, e.value)
		default:
			err = policy.AppendDomain(l.policyPath, e.value)
		}

		if err != nil {
			l.lg.Warn("learning.append_failed", "kind", e.kind, "value", e.value, "err", err)

			continue
		}

		l.lg.Info("learning.learned", "kind", e.kind, "value", e.value, "path", l.policyPath)
	}
}
