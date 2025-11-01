package dashboard

import (
	"context"
	"log/slog"
	"sync"

	"github.com/g0lab/g0efilter/internal/logging"
)

type broadcaster struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

// newBroadcaster creates a new SSE broadcaster for distributing log events to connected clients.
func newBroadcaster() *broadcaster {
	return &broadcaster{clients: make(map[chan []byte]struct{})}
}

// Add registers a new SSE client and returns its message channel.
func (b *broadcaster) Add() chan []byte {
	ch := make(chan []byte, 64)

	b.mu.Lock()
	b.clients[ch] = struct{}{}
	count := len(b.clients)
	b.mu.Unlock()

	slog.Debug("broadcaster.client_added",
		"total_clients", count,
	)

	return ch
}

// Remove unregisters an SSE client and closes its channel.
func (b *broadcaster) Remove(ch chan []byte) {
	b.mu.Lock()
	delete(b.clients, ch)
	count := len(b.clients)
	b.mu.Unlock()
	close(ch)

	slog.Debug("broadcaster.client_removed",
		"total_clients", count,
	)
}

// Send broadcasts a message to all connected SSE clients, dropping messages for slow consumers.
func (b *broadcaster) Send(p []byte) {
	b.mu.RLock()

	dropped := 0
	totalClients := len(b.clients)

	if totalClients == 0 {
		b.mu.RUnlock()
		slog.Log(context.Background(), logging.LevelTrace, "broadcaster.no_clients",
			"bytes", len(p),
		)

		return
	}

	for ch := range b.clients {
		select {
		case ch <- p:
		default:
			// drop if slow consumer
			dropped++
		}
	}

	b.mu.RUnlock()

	if dropped > 0 {
		slog.Warn("broadcaster.dropped",
			"count", dropped,
			"total_clients", totalClients,
			"reason", "slow_consumer",
			"recommendation", "clients should process messages faster",
		)
	}
}
