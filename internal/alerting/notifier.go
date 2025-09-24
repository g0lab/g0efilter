// Package alerting provides notification capabilities for security events.
// This is a separate alerting feature that can be easily removed if not needed.
package alerting

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Notifier handles sending notifications for security events.
type Notifier struct {
	host     string
	token    string
	hostname string
	client   *http.Client
	enabled  bool
}

// NewNotifier creates a new notification client.
// Returns nil if notification is not configured.
func NewNotifier() *Notifier {
	// Alerting feature - can be removed if not needed
	host := strings.TrimSpace(os.Getenv("NOTIFICATION_HOST"))
	host = strings.TrimRight(host, "/") // avoid double slashes
	token := strings.TrimSpace(os.Getenv("NOTIFICATION_KEY"))

	if host == "" || token == "" {
		return nil // Notifications disabled
	}

	hostname := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil {
			hostname = h
		} else {
			hostname = "g0efilter"
		}
	}

	return &Notifier{
		host:     host,
		token:    token,
		hostname: hostname,
		enabled:  true,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
			},
		},
	}
}

// BlockedConnectionInfo contains details about a blocked connection.
// This is part of the alerting feature.
type BlockedConnectionInfo struct {
	SourceIP        string
	SourcePort      string
	DestinationIP   string
	DestinationPort string
	Destination     string // Human-readable destination (hostname, SNI, etc.)
	Reason          string
	Component       string // dns, http, sni, etc.
}

// NotifyBlock sends a notification for a blocked connection.
// This is part of the alerting feature.
func (n *Notifier) NotifyBlock(ctx context.Context, info BlockedConnectionInfo) {
	if n == nil || !n.enabled {
		return
	}

	if info.Component == "sni" {
		info.Component = "https"
	}

	if info.Component == "filter" {
		info.Component = "tcp"
	}

	go n.sendNotification(ctx, info)
}

// Close cleans up the notifier resources.
func (n *Notifier) Close() {
	if n == nil {
		return
	}

	n.enabled = false
	if n.client != nil {
		n.client.CloseIdleConnections()
	}
}

// isIPOnlyDestination checks if the destination contains only IP information (no domain name).
func isIPOnlyDestination(destination, destinationIP, ipPort string) bool {
	return destination == "" ||
		destination == "unknown destination" ||
		destination == destinationIP ||
		destination == ipPort
}

// buildSourceString formats the source address with optional port.
func buildSourceString(sourceIP, sourcePort string) string {
	if sourcePort != "" {
		return fmt.Sprintf("%s:%s", sourceIP, sourcePort)
	}

	return sourceIP
}

// buildDestinationString formats the destination address with domain and IP information.
func buildDestinationString(info BlockedConnectionInfo) string {
	destination := info.Destination
	if info.DestinationIP != "" && info.DestinationPort != "" {
		ipPort := fmt.Sprintf("%s:%s", info.DestinationIP, info.DestinationPort)
		if isIPOnlyDestination(destination, info.DestinationIP, ipPort) {
			// No domain name available, use just IP:port
			return ipPort
		}
		// Domain name available, format as "domain (IP:port)"
		return fmt.Sprintf("%s (%s)", destination, ipPort)
	}

	return destination
}

// createNotificationRequest creates and configures the HTTP request for Gotify.
func (n *Notifier) createNotificationRequest(ctx context.Context, title, message string) (*http.Request, error) {
	vals := url.Values{}
	vals.Set("title", title)
	vals.Set("message", message)
	vals.Set("priority", "8") // High priority for security events

	endpoint := n.host + "/message"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Gotify-Key", n.token)
	req.Header.Set("User-Agent", "g0efilter/1.0")

	return req, nil
}

// sendNotification performs the actual HTTP notification.
// Alerting feature implementation.
func (n *Notifier) sendNotification(ctx context.Context, info BlockedConnectionInfo) {
	source := buildSourceString(info.SourceIP, info.SourcePort)
	destination := buildDestinationString(info)

	title := fmt.Sprintf("%s - %s Connection Blocked", n.hostname, strings.ToUpper(info.Component))
	message := fmt.Sprintf("Blocked %s connection from %s to %s. Reason: %s",
		info.Component, source, destination, info.Reason)

	req, err := n.createNotificationRequest(ctx, title, message)
	if err != nil {
		return // Silently fail - alerting shouldn't break main functionality
	}

	// Send notification
	resp, err := n.client.Do(req)
	if err != nil {
		return // Silently fail
	}

	defer func() {
		// Drain and close response body to reuse connection
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Ignore non-2xx responses silently (avoid log spam)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}
}
