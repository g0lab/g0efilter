package dashboard

import "context"

// LogStore defines the interface for log storage backends.
// Allows swapping between in-memory, database, or other implementations.
type LogStore interface {
	Insert(ctx context.Context, e *LogEntry) (int64, error)
	Query(ctx context.Context, q string, sinceID int64, limit int) ([]LogEntry, error)
	Clear(ctx context.Context) error
}

// EventBroadcaster defines the interface for broadcasting events to connected clients.
// Allows swapping SSE implementation or adding WebSocket support.
type EventBroadcaster interface {
	Add() chan []byte
	Remove(ch chan []byte)
	Send(p []byte)
}

// RateLimiter defines the interface for rate limiting strategies.
// Allows swapping between token bucket, sliding window, or external services.
type RateLimiter interface {
	Allow(key string) bool
}
