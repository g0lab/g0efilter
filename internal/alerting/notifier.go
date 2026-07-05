// Package alerting provides notification capabilities for security events.
package alerting

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/netutil"
)

// Notifier handles sending notifications for security events.
type Notifier struct {
	host     string
	token    string
	hostname string
	client   *http.Client
	enabled  bool

	// Rate limiting to prevent spam
	mu            sync.RWMutex
	recentAlerts  map[string]time.Time
	backoffPeriod time.Duration

	// Ignore list to suppress notifications for specific domains
	ignoreList []string
}

// NewNotifier creates a new notification client. Returns nil if not configured.
func NewNotifier() *Notifier {
	host := strings.TrimSpace(os.Getenv("NOTIFICATION_HOST"))
	host = strings.TrimRight(host, "/")
	token := strings.TrimSpace(os.Getenv("NOTIFICATION_KEY"))

	if host == "" || token == "" {
		return nil
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

	backoffPeriod := 60 * time.Second

	if backoffEnv := strings.TrimSpace(os.Getenv("NOTIFICATION_BACKOFF_SECONDS")); backoffEnv != "" {
		seconds, err := strconv.Atoi(backoffEnv)
		if err == nil && seconds > 0 {
			backoffPeriod = time.Duration(seconds) * time.Second
		}
	}

	ignoreList := loadIgnoreList()

	return &Notifier{
		host:          host,
		token:         token,
		hostname:      hostname,
		enabled:       true,
		recentAlerts:  make(map[string]time.Time),
		backoffPeriod: backoffPeriod,
		ignoreList:    ignoreList,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// SO_MARK bypass so notifications are not blocked by our own filter
				DialContext:        netutil.MarkedDialer(10 * time.Second).DialContext,
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
			},
		},
	}
}

// loadIgnoreList reads the notification ignore list from NOTIFICATION_IGNORE_DOMAINS environment variable.
// Expects comma-separated list of domains (supports wildcards like *.example.com).
// Returns nil if not configured.
func loadIgnoreList() []string {
	ignoreDomains := strings.TrimSpace(os.Getenv("NOTIFICATION_IGNORE_DOMAINS"))
	if ignoreDomains == "" {
		return nil
	}

	parts := strings.Split(ignoreDomains, ",")
	patterns := make([]string, 0, len(parts))

	for _, domain := range parts {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		domain = strings.ToLower(domain)

		if strings.Contains(domain, " ") || strings.Contains(domain, "\t") {
			continue
		}

		patterns = append(patterns, domain)
	}

	if len(patterns) == 0 {
		return nil
	}

	return patterns
}

// BlockedConnectionInfo holds the details of a blocked connection used for alerting.
type BlockedConnectionInfo struct {
	SourceIP        string
	SourcePort      string
	DestinationIP   string
	DestinationPort string
	Destination     string // Human-readable destination (hostname, HTTPS, etc.)
	Reason          string
	Component       string // dns, http, https, etc.
}

// NotifyBlock sends an alert notification for a blocked connection, with rate limiting to prevent spam.
func (n *Notifier) NotifyBlock(ctx context.Context, info BlockedConnectionInfo) {
	if n == nil || !n.enabled {
		return
	}

	if info.Component == "filter" {
		info.Component = "tcp"
	}

	if n.isIgnored(info.Destination) {
		slog.Debug("notification.ignored",
			"component", info.Component,
			"destination", info.Destination,
			"reason", "matched ignore list",
		)

		return
	}

	if !n.shouldSendAlert(info) {
		slog.Debug("notification.rate_limited",
			"component", info.Component,
			"destination", info.Destination,
			"source_ip", info.SourceIP,
		)

		return
	}

	slog.Debug("notification.queued",
		"component", info.Component,
		"destination", info.Destination,
		"source_ip", info.SourceIP,
	)

	go n.sendNotification(ctx, info)
}

// matchesPattern checks if a destination matches a pattern (supports wildcard prefix *.domain.com).
func matchesPattern(destination, pattern string) bool {
	if destination == pattern {
		return true
	}

	// Wildcard pattern: *.example.com matches sub.example.com but not example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")

		return strings.HasSuffix(destination, suffix)
	}

	return false
}

// Close stops the notifier and releases all resources.
func (n *Notifier) Close() {
	if n == nil {
		return
	}

	n.enabled = false
	if n.client != nil {
		n.client.CloseIdleConnections()
	}

	n.mu.Lock()
	n.recentAlerts = nil
	n.mu.Unlock()
}

func (n *Notifier) isIgnored(destination string) bool {
	if len(n.ignoreList) == 0 || destination == "" {
		return false
	}

	destination = strings.ToLower(destination)

	for _, pattern := range n.ignoreList {
		if matchesPattern(destination, pattern) {
			return true
		}
	}

	return false
}

// shouldSendAlert returns false if an alert was recently sent for this connection to prevent notification spam.
func (n *Notifier) shouldSendAlert(info BlockedConnectionInfo) bool {
	// Build key using helper (keeps DNS backoff keyed by domain where possible)
	key := fmt.Sprintf("%s->%s:%s", info.SourceIP, destKeyFor(info), info.Component)

	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()

	// Clean up old entries periodically (older than 2x backoff period)
	n.cleanupOldAlerts(now)

	if lastSent, exists := n.recentAlerts[key]; exists {
		if now.Sub(lastSent) < n.backoffPeriod {
			return false
		}
	}

	n.recentAlerts[key] = now

	return true
}

// destKeyFor creates a unique key for rate limiting based on destination type (domain for DNS, IP:port otherwise).
func destKeyFor(info BlockedConnectionInfo) string {
	switch {
	case info.Component == "dns" && info.Destination != "":
		return info.Destination
	case info.DestinationIP != "" && info.DestinationPort != "":
		return fmt.Sprintf("%s:%s", info.DestinationIP, info.DestinationPort)
	case info.DestinationIP != "":
		return info.DestinationIP
	default:
		return info.Destination
	}
}

func (n *Notifier) cleanupOldAlerts(now time.Time) {
	if n.recentAlerts == nil {
		return
	}

	cleanupThreshold := now.Add(-2 * n.backoffPeriod)
	for k, lastSent := range n.recentAlerts {
		if lastSent.Before(cleanupThreshold) {
			delete(n.recentAlerts, k)
		}
	}
}

func isIPOnlyDestination(destination, destinationIP, ipPort string) bool {
	return destination == "" ||
		destination == "unknown destination" ||
		destination == destinationIP ||
		destination == ipPort
}

func buildSourceString(sourceIP, sourcePort string) string {
	if sourcePort != "" {
		return fmt.Sprintf("%s:%s", sourceIP, sourcePort)
	}

	return sourceIP
}

// buildDestinationString formats the destination, including both domain name and IP:port when available.
func buildDestinationString(info BlockedConnectionInfo) string {
	destination := info.Destination
	if info.DestinationIP != "" && info.DestinationPort != "" {
		ipPort := fmt.Sprintf("%s:%s", info.DestinationIP, info.DestinationPort)
		if isIPOnlyDestination(destination, info.DestinationIP, ipPort) {
			return ipPort
		}

		return fmt.Sprintf("%s (%s)", destination, ipPort)
	}

	return destination
}

// createNotificationRequest builds an HTTP POST request for sending a Gotify notification.
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

// sendNotification sends the blocked connection alert to the Gotify notification server.
func (n *Notifier) sendNotification(ctx context.Context, info BlockedConnectionInfo) {
	source := buildSourceString(info.SourceIP, info.SourcePort)
	destination := buildDestinationString(info)

	title := fmt.Sprintf("%s - %s Connection Blocked", n.hostname, strings.ToUpper(info.Component))
	message := fmt.Sprintf("Blocked %s connection from %s to %s. Reason: %s",
		info.Component, source, destination, info.Reason)

	req, err := n.createNotificationRequest(ctx, title, message)
	if err != nil {
		slog.Warn("notification.request_failed", "host", n.host, "err", err)

		return
	}

	slog.Debug("notification.posting", "host", n.host, "destination", info.Destination, "component", info.Component)

	resp, err := n.client.Do(req)
	if err != nil {
		slog.Warn("notification.post_failed", "host", n.host, "err", err)

		return
	}

	defer func() {
		// Drain and close response body to reuse connection
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Warn("notification.rejected", "host", n.host, "status", resp.StatusCode)

		return
	}

	slog.Debug("notification.sent", "host", n.host, "status", resp.StatusCode)
}
