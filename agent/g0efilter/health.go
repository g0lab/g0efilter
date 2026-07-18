package g0efilter

import (
	"context"
	"net"
	"strings"
	"time"
)

const healthDialTimeout = 2 * time.Second

// HandleHealthcheck runs the `healthcheck` subcommand (used by the container
// HEALTHCHECK): it dials the active filter listener to confirm the proxy is up.
// Returns handled=true and the process exit code.
func HandleHealthcheck(args []string) (bool, int) {
	if len(args) < 2 || args[1] != "healthcheck" {
		return false, 0
	}

	addr := net.JoinHostPort("127.0.0.1", healthPort())

	ctx, cancel := context.WithTimeout(context.Background(), healthDialTimeout)
	defer cancel()

	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return true, 1
	}

	_ = conn.Close()

	return true, 0
}

// healthPort returns the port the active FILTER_MODE listens on.
func healthPort() string {
	switch strings.ToLower(getenvDefault("FILTER_MODE", "https")) {
	case "dns", "dns-strict":
		return getenvDefault("DNS_PORT", "65053")
	case "http":
		return getenvDefault("HTTP_PORT", "65080")
	default:
		return getenvDefault("HTTPS_PORT", "65443")
	}
}
