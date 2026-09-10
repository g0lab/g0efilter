package g0efilter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const healthDialTimeout = 2 * time.Second

// reloadGrace bounds drift before readiness fails, because kubelet projects a ConfigMap asynchronously.
const reloadGrace = 90 * time.Second

// Abstract Unix sockets need neither a writable root filesystem nor a visible TCP port.
const healthSocketPrefix = "@g0efilter-health"

// healthSocketName is per network namespace, so host-network sidecars separate on their proxy ports.
func healthSocketName(cfg config) string {
	return fmt.Sprintf("%s-%s-%s-%s", healthSocketPrefix, cfg.httpPort, cfg.httpsPort, cfg.dnsPort)
}

type runtimeHealth struct {
	mu         sync.RWMutex
	applied    string
	ports      []string
	driftSince time.Time
	rejected   bool
	unreadable bool
}

type healthSnapshot struct {
	Ports  []string `json:"ports"`
	Ready  bool     `json:"ready"`
	Reason string   `json:"reason,omitempty"`
}

// applyOK records a successful apply and clears any outstanding drift.
func (h *runtimeHealth) applyOK(cfg config, hash string) {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.applied = hash
	h.driftSince = time.Time{}
	h.rejected = false
	h.unreadable = false

	h.ports = []string{cfg.httpPort, cfg.httpsPort}
	if isDNSMode(cfg.mode) {
		h.ports = []string{cfg.dnsPort}
	}
}

// applyFailed records that the mounted policy was rejected; the previous one stays enforced.
func (h *runtimeHealth) applyFailed() {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.rejected = true
}

// readFailed starts the drift clock when the mounted policy cannot be read at all:
// the last applied rules stay in force with nothing left to compare them against.
func (h *runtimeHealth) readFailed(now time.Time) {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.unreadable = true

	if h.driftSince.IsZero() {
		h.driftSince = now
	}
}

// observe starts the drift clock the first tick the mounted policy differs from the applied one.
func (h *runtimeHealth) observe(diskHash string, now time.Time) {
	if h == nil || diskHash == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.unreadable = false

	if diskHash == h.applied {
		h.driftSince = time.Time{}
		h.rejected = false

		return
	}

	if h.driftSince.IsZero() {
		h.driftSince = now
	}
}

func (h *runtimeHealth) snapshot(now time.Time) healthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	snapshot := healthSnapshot{Ports: append([]string(nil), h.ports...), Ready: true}

	if h.driftSince.IsZero() || now.Sub(h.driftSince) <= reloadGrace {
		return snapshot
	}

	snapshot.Ready = false
	snapshot.Reason = "the mounted policy has not been applied within the reload grace period"

	switch {
	case h.unreadable:
		snapshot.Reason = "the mounted policy could not be read within the reload grace period"
	case h.rejected:
		snapshot.Reason = "the mounted policy was rejected; the previous one is still enforced"
	}

	return snapshot
}

func startHealthServer(ctx context.Context, tracked *group, cfg config, lg *slog.Logger) error {
	var lc net.ListenConfig

	socket := healthSocketName(cfg)

	listener, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("listen for health checks on %s: %w", socket, err)
	}

	tracked.run(lg, "health_shutdown", func() {
		<-ctx.Done()

		_ = listener.Close()
	})

	tracked.run(lg, "health", func() {
		serveHealth(ctx, listener, cfg.health, lg)
	})

	return nil
}

func serveHealth(ctx context.Context, listener net.Listener, h *runtimeHealth, lg *slog.Logger) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// A transient accept error must not silently retire the probe endpoint.
			if ctx.Err() != nil {
				return
			}

			lg.Warn("health.accept_failed", "err", err)

			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}

			continue
		}

		_ = conn.SetDeadline(time.Now().Add(healthDialTimeout))

		encodeErr := json.NewEncoder(conn).Encode(h.snapshot(time.Now()))
		if encodeErr != nil {
			lg.Warn("health.write_failed", "err", encodeErr)
		}

		_ = conn.Close()
	}
}

// HandleHealthcheck backs the container HEALTHCHECK and the Kubernetes probes, returning the exit code.
func HandleHealthcheck(args []string) (bool, int) {
	if len(args) < 2 || args[1] != "healthcheck" {
		return false, 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthDialTimeout)
	defer cancel()

	var dialer net.Dialer

	snapshot, err := readHealth(ctx, &dialer, healthSocketName(loadConfig()))
	if err != nil || !snapshot.Ready {
		return true, 1
	}

	for _, port := range snapshot.Ports {
		proxy, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		if dialErr != nil {
			return true, 1
		}

		_ = proxy.Close()
	}

	return true, 0
}

func readHealth(ctx context.Context, dialer *net.Dialer, socket string) (healthSnapshot, error) {
	var snapshot healthSnapshot

	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return snapshot, fmt.Errorf("dial health socket: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(healthDialTimeout))

	err = json.NewDecoder(conn).Decode(&snapshot)
	if err != nil {
		return snapshot, fmt.Errorf("decode health snapshot: %w", err)
	}

	return snapshot, nil
}
