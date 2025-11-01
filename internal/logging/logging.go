// Package logging provides logging helpers.
package logging

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/internal/alerting"
	"github.com/g0lab/g0efilter/internal/safeio"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

//nolint:gochecknoglobals // Mutex needed for thread safety
var globalLoggerMutex sync.Mutex

// setGlobalLogger sets the global zerolog.Logger.
func setGlobalLogger(zl zerolog.Logger) {
	globalLoggerMutex.Lock()
	defer globalLoggerMutex.Unlock()

	log.Logger = zl
}

const (
	// LevelTrace is below slog.LevelDebug.
	LevelTrace slog.Level = -8

	// ActionAllowed is the action string for allowed connections.
	ActionAllowed = "ALLOWED"

	defaultQueueSize         = 1024
	defaultWorkers           = 3               // number of concurrent workers
	defaultRetryTimeout      = 5 * time.Second // max time to retry a single POST
	defaultIdleConnTimeout   = 90 * time.Second
	defaultHTTPClientTimeout = 15 * time.Second
	defaultRetryWait         = 500 * time.Millisecond
	defaultRetryWaitMax      = 5 * time.Second
	defaultLogMaxSizeMB      = 100
	defaultLogMaxBackups     = 7
	defaultLogMaxAgeDays     = 28
	defaultProbeTimeout      = 5 * time.Second
	defaultStartDelay        = 5 * time.Second
)

var (
	errProbeStatus = errors.New("probe unexpected status")

	defaultPoster *poster //nolint:gochecknoglobals
)

// parseLevel converts a log level string to slog.Leveler, defaulting to INFO.
func parseLevel(s string) slog.Leveler {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default: // INFO
		return slog.LevelInfo
	}
}

// ---------- poster ----------

type poster struct {
	url          string
	apiKey       string
	q            chan []byte
	queueSize    int
	workers      int
	retryTimeout time.Duration
	httpC        *http.Client
	stop         chan struct{}
	done         chan struct{}
	wg           sync.WaitGroup
	zl           zerolog.Logger
	debug        bool
	trace        bool
	ready        chan struct{}
	startDelay   time.Duration
	// retry configuration
	retryMax     int
	retryWaitMin time.Duration
	retryWaitMax time.Duration
}

type nopLogger struct{}

// Printf implements a no-op logger for the HTTP client.
func (n *nopLogger) Printf(string, ...any) {}

// Println implements a no-op logger for the HTTP client.
func (n *nopLogger) Println(...any) {}

// shouldRetry determines if an HTTP request should be retried based on the response code or error.
func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		// Retry on network errors
		return true
	}

	if resp == nil {
		return false
	}

	// Retry on 5xx and 429, not on 4xx
	return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
}

// newPoster is a convenience wrapper for tests.
//
//nolint:unparam
func newPoster(url, apiKey string, zl zerolog.Logger, debug bool) *poster {
	return newPosterWithCtx(context.Background(), url, apiKey, zl, debug, defaultQueueSize)
}

// newPosterWithCtx creates a new HTTP poster for sending log events to a dashboard endpoint.
func newPosterWithCtx(ctx context.Context, url, apiKey string, zl zerolog.Logger, debug bool, queueSize int) *poster {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	poster := &poster{
		url:          url,
		apiKey:       apiKey,
		q:            make(chan []byte, queueSize),
		queueSize:    queueSize,
		workers:      defaultWorkers,
		retryTimeout: defaultRetryTimeout,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		zl:           zl,
		debug:        debug,
		ready:        make(chan struct{}),
	}

	tr := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	poster.httpC = &http.Client{Timeout: defaultHTTPClientTimeout, Transport: tr}

	// Configure retry settings
	poster.retryMax = 4
	poster.retryWaitMin = defaultRetryWait
	poster.retryWaitMax = defaultRetryWaitMax

	// Start worker after startup delay (default 5s)
	startDelay := defaultStartDelay

	if v := strings.TrimSpace(os.Getenv("DASHBOARD_START_DELAY")); v != "" {
		d, derr := time.ParseDuration(v)
		if derr == nil && d >= 0 {
			startDelay = d
		}
	}

	poster.startDelay = startDelay

	go poster.startWorker(ctx)

	defaultPoster = poster

	return poster
}

func (p *poster) Stop(timeout time.Duration) {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}

	if timeout <= 0 {
		<-p.done

		return
	}

	select {
	case <-p.done:
	case <-time.After(timeout):
		p.zl.Warn().Msg("dashboard: stop timeout")
	}
}

func (p *poster) Enqueue(payload []byte) {
	// Non-blocking send, drop if queue full
	select {
	case p.q <- payload:
		if p.debug {
			p.zl.Debug().Msg("dashboard: message queued")
		}
	default:
		if p.debug {
			p.zl.Debug().Msg("dashboard: queue full, dropping message")
		}
	}
}

func (p *poster) Probe(ctx context.Context) error {
	probe := map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339Nano),
		"msg":  "_dashboard_probe",
	}

	payload, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("failed to marshal probe: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create probe request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	setAPIAuthHeaders(req.Header, p.apiKey)

	resp, err := p.httpC.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute probe request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	// Read a small sample for diagnostics, then drain & close to keep the connection reusable.
	const maxProbeRead = 2 << 10 // 2KiB

	lr := io.LimitReader(resp.Body, maxProbeRead)

	sample, rerr := io.ReadAll(lr)
	if rerr != nil {
		// Log but don't fail the probe solely on sample read error.
		p.zl.Warn().Err(rerr).Msg("http.body_read_error")
	}

	drainErr := safeio.DrainAndClose(resp.Body)
	if drainErr != nil {
		p.zl.Warn().Err(drainErr).Msg("http.body_close_error")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include a tiny body hint for easier debugging.
		snip := strings.TrimSpace(string(sample))

		jvalid := json.Valid(sample)
		if jvalid {
			return fmt.Errorf("%w %d (body=json)", errProbeStatus, resp.StatusCode)
		}

		if snip != "" {
			return fmt.Errorf("%w %d (body=%q)", errProbeStatus, resp.StatusCode, snip)
		}

		return fmt.Errorf("%w %d", errProbeStatus, resp.StatusCode)
	}

	return nil
}

// setAPIAuthHeaders sets both API key headers.
func setAPIAuthHeaders(headers http.Header, apiKey string) {
	if apiKey == "" {
		return
	}

	headers.Set("X-Api-Key", apiKey)
	headers.Set("Authorization", "Bearer "+apiKey)
}

func (p *poster) handlePostPayload(ctx context.Context, payload []byte) {
	if p.debug {
		p.zl.Debug().Int("payload_size", len(payload)).Str("url", p.url).Msg("dashboard.posting")
	}

	// TRACE: log the exact body being sent (truncated)
	if p.trace {
		logTraceBody(p.zl, p.url, payload)
	}

	// Create context with timeout for retry loop
	retryCtx, cancel := context.WithTimeout(ctx, p.retryTimeout)
	defer cancel()

	// Retry loop with exponential backoff
	backoffDuration := p.retryWaitMin

	for {
		select {
		case <-retryCtx.Done():
			// Timeout or cancellation - give up
			p.zl.Warn().Str("url", p.url).Msg("dashboard: giving up after timeout")

			return
		default:
			success := p.attemptPost(ctx, payload)
			if success {
				return
			}

			// Log that we're going to retry
			if p.debug {
				p.zl.Debug().Str("url", p.url).Msg("dashboard: posting failed, will retry")
			}

			// Wait with exponential backoff
			time.Sleep(addJitter(backoffDuration))

			// Increase backoff up to max
			if backoffDuration < p.retryWaitMax {
				backoffDuration *= 2
				if backoffDuration > p.retryWaitMax {
					backoffDuration = p.retryWaitMax
				}
			}
		}
	}
}

// addJitter adds random factor (0.5 to 1.0) to duration.
func addJitter(d time.Duration) time.Duration {
	jitterBig, err := rand.Int(rand.Reader, big.NewInt(500)) // 0-499
	if err != nil {
		return d // Fallback if random generation fails
	}

	jitter := 0.5 + float64(jitterBig.Int64())/1000.0 // 0.5 to 0.999

	return time.Duration(float64(d) * jitter)
}

func (p *poster) attemptPost(ctx context.Context, payload []byte) bool {
	// Create new request for each attempt with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		p.zl.Error().Err(err).Msg("dashboard: build request error")

		return true // Don't retry on request creation errors
	}

	req.Header.Set("Content-Type", "application/json")
	setAPIAuthHeaders(req.Header, p.apiKey)

	resp, err := p.httpC.Do(req)

	// Check if we should retry
	if !shouldRetry(resp, err) {
		return p.handleFinalResponse(resp, err)
	}

	// Log retry info
	if err != nil {
		p.zl.Debug().Err(err).Msg("dashboard: post attempt failed")
	} else if resp != nil {
		p.zl.Debug().Int("status", resp.StatusCode).Msg("dashboard: post attempt failed with status")
		_ = resp.Body.Close()
	}

	return false // Continue retrying
}

func (p *poster) handleFinalResponse(resp *http.Response, err error) bool {
	if err != nil {
		p.zl.Error().Err(err).Msg("dashboard: post error")

		return true
	}

	if resp != nil {
		defer func() { _ = resp.Body.Close() }()

		logPosterResponse(p.zl, resp, p.trace)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			p.zl.Warn().Int("status", resp.StatusCode).Str("url", p.url).
				Msg("dashboard: unexpected status when posting logs")
		}
	}

	return true
}

func logTraceBody(zl zerolog.Logger, url string, body []byte) {
	const maxBody = 8 << 10 // 8KiB
	if len(body) > maxBody {
		body = append(append([]byte{}, body[:maxBody]...), []byte("...(truncated)")...)
	}

	ev := zl.Trace().Str("url", url)
	if json.Valid(body) {
		ev = ev.RawJSON("body", body)
	} else {
		ev = ev.Str("body", string(body))
	}

	ev.Msg("dashboard.post body")
}

func logPosterResponse(zl zerolog.Logger, resp *http.Response, trace bool) {
	if !trace {
		// Not tracing: just drain & close
		drainErr := safeio.DrainAndClose(resp.Body)
		if drainErr != nil {
			zl.Warn().Err(drainErr).Msg("http.body_close_error")
		}

		return
	}

	// Read a small response sample for trace logs, then drain & close for keep-alive reuse
	const maxRead = 8 << 10

	lr := io.LimitReader(resp.Body, maxRead)

	rb, rerr := io.ReadAll(lr)
	if rerr != nil {
		// If the server used chunked/gzip, read errors can indicate truncation/tamper.
		zl.Warn().Err(rerr).Msg("http.body_read_error")
	}

	drainErr := safeio.DrainAndClose(resp.Body)
	if drainErr != nil {
		zl.Warn().Err(drainErr).Msg("http.body_close_error")
	}

	ev := zl.Trace().Int("status", resp.StatusCode)
	if json.Valid(rb) {
		ev = ev.RawJSON("resp_body", rb)
	} else {
		ev = ev.Str("resp_body", string(rb))
	}

	ev.Msg("dashboard.post resp")
}

func (p *poster) worker(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case payload := <-p.q:
			p.handlePostPayload(ctx, payload)
		case <-p.stop:
			return
		}
	}
}

func (p *poster) startWorker(ctx context.Context) {
	if p.startDelay > 0 {
		t := time.NewTimer(p.startDelay)
		defer t.Stop()

		select {
		case <-t.C:
		case <-p.stop:
			close(p.done)

			return
		}
	}

	close(p.ready) // signal that shipping is beginning

	// Start worker pool
	p.wg.Add(p.workers)

	for range p.workers {
		go p.worker(ctx)
	}

	// Wait for all workers to finish
	p.wg.Wait()
	close(p.done)
}

// ---------- zerolog bridge as a slog.Handler ----------

// zerologHandler implements slog.Handler using zerolog.
type zerologHandler struct {
	zl        zerolog.Logger
	termLevel slog.Level
	poster    *poster
	hostname  string
	version   string
	notifier  *alerting.Notifier
}

func (z *zerologHandler) Enabled(_ context.Context, l slog.Level) bool {
	// Short-circuit terminal logs below threshold, but still handle records if poster is configured
	return l >= z.termLevel || z.poster != nil
}

func toZerologLevel(l slog.Level) zerolog.Level {
	if l == LevelTrace {
		return zerolog.TraceLevel
	}

	switch l {
	case slog.LevelDebug:
		return zerolog.DebugLevel
	case slog.LevelInfo:
		return zerolog.InfoLevel
	case slog.LevelWarn:
		return zerolog.WarnLevel
	case slog.LevelError:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// Canonical keys the dashboard accepts.
var dashboardKeys = []string{ //nolint:gochecknoglobals
	"component", "source_ip", "source_port",
	"destination_ip", "destination_port",
	"protocol", "policy_hit", "payload_len",
	"https", "http_host", "host", // HTTP
	"qname", "qtype", "rcode", // DNS
	"reason", "note", // context
	"src", "dst", // 5-tuple strings
	"hostname", "flow_id", "version",
}

func (z *zerologHandler) Handle(ctx context.Context, record slog.Record) error {
	// Collect attrs into a flat map
	attrs := make(map[string]any, record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()

		return true
	})

	// Adjust log level for IP-based ALLOWED events (allowlisted IPs)
	logLevel := record.Level
	if isAllowlistedIP(attrs) {
		logLevel = slog.LevelDebug
	}

	// Terminal output: only if record level >= configured threshold
	if logLevel >= z.termLevel {
		logToTerminal(z.zl, logLevel, record.Message, attrs)
	}

	// Ship action events to the dashboard if configured
	if z.poster != nil {
		shipToDashboard(z.poster, z.hostname, z.version, record.Time, record.Message, attrs)
	}

	// Alerting feature - send notifications for BLOCKED events
	if z.notifier != nil {
		handleBlockedAlert(ctx, z.notifier, attrs)
	}

	return nil
}

func logToTerminal(zl zerolog.Logger, level slog.Level, msg string, attrs map[string]any) {
	zlvl := toZerologLevel(level)
	ev := zl.WithLevel(zlvl)

	for key, value := range attrs {
		switch val := value.(type) {
		case string:
			ev = ev.Str(key, val)
		case int:
			ev = ev.Int(key, val)
		case int64:
			ev = ev.Int64(key, val)
		case float64:
			ev = ev.Float64(key, val)
		case bool:
			ev = ev.Bool(key, val)
		case time.Time:
			ev = ev.Time(key, val)
		case error:
			ev = ev.Err(val)
		default:
			ev = ev.Interface(key, val)
		}
	}

	ev.Msg(msg)
}

// shouldShipToDashboard determines if an event should be sent to the dashboard.
func shouldShipToDashboard(attrs map[string]any) bool {
	act := extractAction(attrs)

	// Only ship BLOCKED and ALLOWED actions
	// REDIRECTED stays in console logs only (debug level)
	if act != "BLOCKED" && act != ActionAllowed {
		return false
	}

	// Skip ALLOWED actions from nftables (allowlisted IPs with component=nflog)
	// Keep ALLOWED from HTTPS/HTTP/DNS filters (domain matches with wildcards)
	if act == ActionAllowed {
		component := ""
		if v, ok := attrs["component"]; ok {
			component = strings.ToLower(fmt.Sprint(v))
		}
		// Skip nflog (nftables IP-based allows)
		if component == "nflog" {
			return false
		}
	}

	return true
}

// extractAction extracts the action string from attributes.
func extractAction(attrs map[string]any) string {
	if v, ok := attrs["action"]; ok {
		return strings.ToUpper(fmt.Sprint(v))
	}

	return ""
}

// isAllowlistedIP checks if an event is an ALLOWED action for an allowlisted IP (from nftables).
func isAllowlistedIP(attrs map[string]any) bool {
	act := extractAction(attrs)

	if act != ActionAllowed {
		return false
	}

	// Check if this is an IP-based allow (component=nflog from nftables)
	component := ""
	if v, ok := attrs["component"]; ok {
		component = strings.ToLower(fmt.Sprint(v))
	}

	// nflog component indicates IP-based allow from nftables
	return component == "nflog"
}

func shipToDashboard(
	poster *poster, hostname string, version string, rTime time.Time, rMsg string, attrs map[string]any,
) {
	if !shouldShipToDashboard(attrs) {
		return
	}

	payload := buildDashboardPayload(hostname, version, rTime, rMsg, extractAction(attrs), attrs)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		poster.zl.Error().Err(err).Msg("dashboard: marshal error")

		return
	}

	// In your dashboard logging code
	select {
	case poster.q <- payloadBytes:
		// Message queued
	default:
		// Queue full, drop message and continue
		poster.zl.Warn().Msg("dashboard.queue_full")
	}
}

// handleBlockedAlert processes BLOCKED events and sends notifications.
func handleBlockedAlert(ctx context.Context, notifier *alerting.Notifier, attrs map[string]any) {
	if notifier == nil {
		return
	}

	// Check if this is a BLOCKED event
	act := ""
	if v, ok := attrs["action"]; ok {
		act = strings.ToUpper(fmt.Sprint(v))
	}

	if act != "BLOCKED" {
		return
	}

	// Extract detailed connection information
	info := alerting.BlockedConnectionInfo{
		SourceIP:        extractStringAttr(attrs, "source_ip"),
		SourcePort:      extractStringAttr(attrs, "source_port"),
		DestinationIP:   extractStringAttr(attrs, "destination_ip"),
		DestinationPort: extractStringAttr(attrs, "destination_port"),
		Destination:     buildDestinationString(attrs),
		Component:       extractStringAttr(attrs, "component"),
	}

	// Extract reason
	info.Reason = extractStringAttr(attrs, "reason")
	if info.Reason == "" {
		info.Reason = extractStringAttr(attrs, "note")
	}

	if info.Reason == "" {
		info.Reason = "blocked by policy"
	}

	// Default component if not specified
	if info.Component == "" {
		info.Component = "filter"
	}

	// Send notification
	notifier.NotifyBlock(ctx, info)
}

// extractStringAttr safely extracts a string attribute.
func extractStringAttr(attrs map[string]any, key string) string {
	if v, ok := attrs[key]; ok && v != nil {
		return fmt.Sprint(v)
	}

	return ""
}

// buildDestinationString creates a human-readable destination string.
func buildDestinationString(attrs map[string]any) string {
	// Try domain names first (HTTPS, hostname, DNS query name)
	if https := extractStringAttr(attrs, "https"); https != "" {
		return https
	}

	if host := extractStringAttr(attrs, "http_host"); host != "" {
		return host
	}

	if host := extractStringAttr(attrs, "host"); host != "" {
		return host
	}

	if qname := extractStringAttr(attrs, "qname"); qname != "" {
		return qname
	}

	// Fallback to dst field (IP:port) or individual IP components
	if dst := extractStringAttr(attrs, "dst"); dst != "" {
		return dst
	}

	destIP := extractStringAttr(attrs, "destination_ip")

	destPort := extractStringAttr(attrs, "destination_port")
	if destIP != "" {
		if destPort != "" {
			return net.JoinHostPort(destIP, destPort)
		}

		return destIP
	}

	return "unknown destination"
}

func getCanonicalTime(attrs map[string]any, fallback time.Time) string {
	// Canonical event time (prefer producer-supplied)
	if t, ok := attrs["time"]; ok && fmt.Sprint(t) != "" {
		return fmt.Sprint(t)
	}

	if t, ok := attrs["timestamp"]; ok && fmt.Sprint(t) != "" {
		return fmt.Sprint(t)
	}

	if t, ok := attrs["event_time"]; ok && fmt.Sprint(t) != "" {
		return fmt.Sprint(t)
	}

	return fallback.Format(time.RFC3339Nano)
}

func normalizeAttributeKeys(attrs map[string]any) {
	// Normalise synonyms to canonical names
	if v, ok := attrs["client_ip"]; ok {
		attrs["source_ip"] = v
	}

	if v, ok := attrs["dst_ip"]; ok {
		attrs["destination_ip"] = v
	}

	if v, ok := attrs["dst_port"]; ok {
		attrs["destination_port"] = v
	}
	// HTTP host: allow either key; prefer explicit http_host, else host.
	if _, ok := attrs["http_host"]; !ok {
		if v, ok := attrs["host"]; ok && fmt.Sprint(v) != "" {
			attrs["http_host"] = v
		}
	}
}

// buildDashboardPayload constructs a payload map for dashboard logging.
//
//nolint:cyclop
func buildDashboardPayload(
	hostname string, version string, rTime time.Time, rMsg, act string, attrs map[string]any,
) map[string]any {
	payload := map[string]any{
		"producer_time": rTime.Format(time.RFC3339Nano),
		"msg":           rMsg,
		"action":        act,
		"time":          getCanonicalTime(attrs, rTime),
	}

	// Normalize attribute keys to canonical names
	normalizeAttributeKeys(attrs)

	// Ensure hostname included if available
	if hostname != "" {
		if _, ok := attrs["hostname"]; !ok || fmt.Sprint(attrs["hostname"]) == "" {
			payload["hostname"] = hostname
		}
	}

	// Include client version if available
	if version != "" {
		if _, ok := attrs["version"]; !ok || fmt.Sprint(attrs["version"]) == "" {
			payload["version"] = version
		}
	}

	// Copy canonical fields if present
	for _, key := range dashboardKeys {
		if val, ok := attrs[key]; ok && val != nil && fmt.Sprint(val) != "" {
			payload[key] = val
		}
	}

	return payload
}

func (z *zerologHandler) WithAttrs(a []slog.Attr) slog.Handler {
	// Extend logger context with attrs
	logger := z.zl

	for _, attr := range a {
		switch val := attr.Value.Any().(type) {
		case string:
			logger = logger.With().Str(attr.Key, val).Logger()
		case int:
			logger = logger.With().Int(attr.Key, val).Logger()
		case time.Time:
			logger = logger.With().Time(attr.Key, val).Logger()
		case error:
			logger = logger.With().Err(val).Logger()
		default:
			logger = logger.With().Interface(attr.Key, val).Logger()
		}
	}

	return &zerologHandler{
		zl:        logger,
		termLevel: z.termLevel,
		poster:    z.poster,
		hostname:  z.hostname,
		version:   z.version,
		notifier:  z.notifier,
	}
}

func (z *zerologHandler) WithGroup(name string) slog.Handler {
	_ = name // groups ignored

	return z
}

// ---------- constructors ----------

// initializeDashboardPoster sets up the dashboard HTTP poster with configuration from environment.
func initializeDashboardPoster(ctx context.Context, dhost string, zl zerolog.Logger, lvl slog.Level) *poster {
	// Add http:// prefix if needed
	if !strings.HasPrefix(dhost, "http://") && !strings.HasPrefix(dhost, "https://") {
		dhost = "http://" + dhost
	}

	durl := strings.TrimRight(dhost, "/") + "/api/v1/logs"
	dapi := strings.TrimSpace(os.Getenv("DASHBOARD_API_KEY"))
	debugEnabled := lvl <= slog.LevelDebug
	traceEnabled := lvl <= LevelTrace

	// Parse queue size from environment
	queueSize := parseQueueSize(zl)

	poster := newPosterWithCtx(ctx, durl, dapi, zl, debugEnabled, queueSize)
	poster.trace = traceEnabled

	// Fire a probe once initialized
	go func() {
		<-poster.ready

		err := poster.Probe(ctx)
		if err != nil {
			zl.Warn().Err(err).Str("url", durl).Msg("dashboard: probe error")
		} else {
			zl.Info().Str("url", durl).Msg("dashboard: probe ok")
		}
	}()

	return poster
}

// parseQueueSize reads and validates DASHBOARD_QUEUE_SIZE from environment.
func parseQueueSize(zl zerolog.Logger) int {
	queueSize := defaultQueueSize
	qsizeStr := strings.TrimSpace(os.Getenv("DASHBOARD_QUEUE_SIZE"))

	if qsizeStr == "" {
		return queueSize
	}

	var parsed int

	n, err := fmt.Sscanf(qsizeStr, "%d", &parsed)

	if err != nil || n != 1 || parsed <= 0 {
		zl.Warn().Str("value", qsizeStr).Msg("invalid DASHBOARD_QUEUE_SIZE, using default")

		return defaultQueueSize
	}

	return parsed
}

// NewWithContext builds a slog.Logger backed by zerolog.
//
//nolint:cyclop,funlen
func NewWithContext(ctx context.Context, level string, out io.Writer, version string) *slog.Logger {
	// Writer (stdout or file)
	writer := out
	if logFile := strings.TrimSpace(os.Getenv("LOG_FILE")); logFile != "" {
		writer = &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    defaultLogMaxSizeMB,
			MaxBackups: defaultLogMaxBackups,
			MaxAge:     defaultLogMaxAgeDays,
			Compress:   true,
		}
	}

	// Console writer for human-readable output
	cw := zerolog.ConsoleWriter{Out: writer, TimeFormat: time.RFC3339}
	zl := zerolog.New(cw).With().Timestamp().Logger()

	hostname := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil {
			hostname = strings.TrimSpace(h)
		}
	}

	// Global zerolog level (affects libraries using zerolog)
	lvlStr := strings.TrimSpace(level)
	if lvlStr == "" {
		lvlStr = os.Getenv("LOG_LEVEL")
	}

	var zlvl zerolog.Level

	switch strings.ToUpper(lvlStr) {
	case "TRACE":
		zlvl = zerolog.TraceLevel
	case "DEBUG":
		zlvl = zerolog.DebugLevel
	case "INFO":
		zlvl = zerolog.InfoLevel
	case "WARN", "WARNING":
		zlvl = zerolog.WarnLevel
	case "ERROR":
		zlvl = zerolog.ErrorLevel
	default:
		zlvl = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zlvl)

	// Optional: wire global logger for libraries
	setGlobalLogger(zl)

	// Dashboard poster
	lvl := parseLevel(lvlStr).Level()

	var poster *poster

	dhost := strings.TrimSpace(os.Getenv("DASHBOARD_HOST"))
	if dhost != "" {
		poster = initializeDashboardPoster(ctx, dhost, zl, lvl)
	}

	// Initialize alerting feature (optional)
	// This can be easily removed if alerting is not needed
	notifier := alerting.NewNotifier()

	// Bridge into slog
	h := &zerologHandler{zl: zl, termLevel: lvl, poster: poster, hostname: hostname, version: version, notifier: notifier}

	return slog.New(h)
}

// NewFromEnv creates a logger from environment variables.
func NewFromEnv() *slog.Logger {
	return NewWithContext(context.Background(), os.Getenv("LOG_LEVEL"), os.Stdout, "")
}

// New returns a logger with the provided level.
func New(l string) *slog.Logger {
	return NewWithContext(context.Background(), l, os.Stdout, "")
}

// Shutdown stops the default poster and waits up to timeout.
func Shutdown(timeout time.Duration) {
	if defaultPoster != nil {
		defaultPoster.Stop(timeout)
	}
}
