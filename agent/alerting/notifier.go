// Package alerting provides notification capabilities for security events.
package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/agent/netutil"
)

// Notifier handles sending notifications for security events.
type Notifier struct {
	sender   *sender
	host     string
	hostname string
	client   *http.Client
	enabled  bool

	// Rate limiting to prevent spam
	mu            sync.RWMutex
	recentAlerts  map[string]time.Time
	backoffPeriod time.Duration

	ignoreList ignoreRules
}

// NewNotifier creates a new notification client. Returns nil if not configured.
func NewNotifier() *Notifier {
	rawURLs := parseURLs(os.Getenv("NOTIFICATION_URLS"))
	if len(rawURLs) == 0 {
		return nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// SO_MARK bypass so notifications are not blocked by our own filter
			DialContext:        netutil.MarkedDialer(10 * time.Second).DialContext,
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
	}

	backend, err := newSender(rawURLs, client)
	if err != nil {
		slog.Error("notification.config_invalid", "targets", redactAll(rawURLs), "err", err)

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

	ignoreList := compileIgnoreRules(loadIgnoreList())

	return &Notifier{
		sender:        backend,
		host:          backend.targets,
		hostname:      hostname,
		enabled:       true,
		recentAlerts:  make(map[string]time.Time),
		backoffPeriod: backoffPeriod,
		ignoreList:    ignoreList,
		client:        client,
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

	if n.isIgnored(info) {
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

func (n *Notifier) isIgnored(info BlockedConnectionInfo) bool {
	if len(n.ignoreList) == 0 {
		return false
	}

	return n.ignoreList.matches(info)
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

func (n *Notifier) sendNotification(_ context.Context, info BlockedConnectionInfo) {
	source := buildSourceString(info.SourceIP, info.SourcePort)
	destination := buildDestinationString(info)

	title := fmt.Sprintf("%s - %s Connection Blocked", n.hostname, strings.ToUpper(info.Component))
	message := fmt.Sprintf("Blocked %s connection from %s to %s. Reason: %s",
		info.Component, source, destination, info.Reason)

	slog.Debug("notification.posting", "host", n.host, "destination", info.Destination, "component", info.Component)

	err := n.sender.send(title, message)
	if err != nil {
		slog.Warn("notification.post_failed", "host", n.host, "err", err)

		return
	}

	slog.Debug("notification.sent", "host", n.host)
}
