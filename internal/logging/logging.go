// Package logging provides application logging helpers.
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
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/alerting"
	"github.com/g0lab/g0efilter/internal/safeio"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	actionRedirected = "REDIRECTED"
	// LevelTrace defines a trace-level log severity, lower than slog.LevelDebug.
	LevelTrace slog.Level = -8

	defaultQueueSize         = 1024
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
	url        string
	apiKey     string
	q          chan []byte
	httpC      *http.Client
	stop       chan struct{}
	done       chan struct{}
	zl         zerolog.Logger
	debug      bool
	trace      bool
	ready      chan struct{}
	startDelay time.Duration
	// retry configuration
	retryMax     int
	retryWaitMin time.Duration
	retryWaitMax time.Duration
}

type nopLogger struct{}

func (n *nopLogger) Printf(string, ...any) {}
func (n *nopLogger) Println(...any)        {}

// shouldRetry returns true if we should retry the request based on the response or error.
func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		// Retry on network errors
		return true
	}

	if resp == nil {
		return false
	}

	// Retry on 5xx server errors and 429 (rate limited), but not on 4xx client errors
	return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
}

// exponentialBackoffWithJitter calculates the wait time for retry attempt.
func exponentialBackoffWithJitter(attempt int, minWait, maxWait time.Duration) time.Duration {
	if attempt == 0 {
		return minWait
	}

	// Calculate exponential backoff: minWait * 2^attempt
	backoff := time.Duration(float64(minWait) * math.Pow(2, float64(attempt)))

	// Cap at maximum wait time
	if backoff > maxWait {
		backoff = maxWait
	}

	// Add jitter (random factor between 0.5 and 1.0)
	// Use crypto/rand for security compliance
	jitterBig, err := rand.Int(rand.Reader, big.NewInt(500)) // 0-499
	if err != nil {
		// Fallback to no jitter if random generation fails
		return backoff
	}

	jitter := 0.5 + float64(jitterBig.Int64())/1000.0 // 0.5 to 0.999

	return time.Duration(float64(backoff) * jitter)
}

// newPoster is a convenience wrapper retained for tests; production uses newPosterWithCtx.
//
//nolint:unparam // apiKey repetition occurs only in tests; in production a real key flows via environment
func newPoster(url, apiKey string, zl zerolog.Logger, debug bool) *poster {
	return newPosterWithCtx(context.Background(), url, apiKey, zl, debug)
}

func newPosterWithCtx(ctx context.Context, url, apiKey string, zl zerolog.Logger, debug bool) *poster {
	poster := &poster{
		url:    url,
		apiKey: apiKey,
		q:      make(chan []byte, defaultQueueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		zl:     zl,
		debug:  debug,
		ready:  make(chan struct{}),
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

	// Start the worker after a small startup delay (DASHBOARD_START_DELAY, default 5s)
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
	select {
	case p.q <- payload:
	default:
		p.zl.Warn().Msg("dashboard: queue full, dropping log")
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
	p.worker(ctx)  // closes p.done when it exits
}

// setAPIAuthHeaders de-duplicates setting both API key headers everywhere.
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

	// Retry loop with exponential backoff
	for attempt := 0; attempt <= p.retryMax; attempt++ {
		success := p.attemptPost(ctx, payload, attempt)
		if success {
			return
		}

		// Don't wait after the last attempt
		if attempt < p.retryMax {
			p.waitBeforeRetry(attempt)
		}
	}

	// All retries exhausted
	p.zl.Error().Int("max_retries", p.retryMax).Str("url", p.url).
		Msg("dashboard: all retry attempts exhausted")
}

func (p *poster) attemptPost(ctx context.Context, payload []byte, attempt int) bool {
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

	// Log retry attempt
	p.logRetryAttempt(err, resp, attempt)

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

func (p *poster) logRetryAttempt(err error, resp *http.Response, attempt int) {
	if err != nil {
		p.zl.Debug().Err(err).Int("attempt", attempt+1).Int("max_retries", p.retryMax).
			Msg("dashboard: post attempt failed, will retry")
	} else if resp != nil {
		p.zl.Debug().Int("status", resp.StatusCode).Int("attempt", attempt+1).Int("max_retries", p.retryMax).
			Msg("dashboard: post attempt failed with status, will retry")
		_ = resp.Body.Close()
	}
}

func (p *poster) waitBeforeRetry(attempt int) {
	waitTime := exponentialBackoffWithJitter(attempt, p.retryWaitMin, p.retryWaitMax)
	if p.debug {
		p.zl.Debug().Dur("wait_time", waitTime).Int("attempt", attempt+1).
			Msg("dashboard: waiting before retry")
	}

	time.Sleep(waitTime)
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
	defer close(p.done)

	for {
		select {
		case payload := <-p.q:
			p.handlePostPayload(ctx, payload)
		case <-p.stop:
			// drain remaining items quickly
			for {
				select {
				case <-p.q:
					// dropped during shutdown
				default:
					return
				}
			}
		}
	}
}

// ---------- zerolog bridge as a slog.Handler ----------

// zerologHandler implements slog.Handler using zerolog.
// Includes optional alerting feature for BLOCKED events.
type zerologHandler struct {
	zl        zerolog.Logger
	termLevel slog.Level
	poster    *poster
	hostname  string
	notifier  *alerting.Notifier // alerting feature - can be removed if not needed
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
// Note: include both "host" and "http_host" so either can be shipped without extra mapping.
var dashboardKeys = []string{ //nolint:gochecknoglobals
	"component", "source_ip", "source_port",
	"destination_ip", "destination_port",
	"protocol", "policy_hit", "payload_len",
	"sni", "http_host", "host", // HTTP
	"qname", "qtype", "rcode", // DNS
	"reason", "note", // context (blocked reason / sinkhole etc.)
	"src", "dst", // 5-tuple strings
	"hostname", "flow_id",
}

func (z *zerologHandler) Handle(ctx context.Context, record slog.Record) error {
	// Collect attrs into a flat map
	attrs := make(map[string]any, record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()

		return true
	})

	// Terminal output: only if record level >= configured threshold
	if record.Level >= z.termLevel {
		logToTerminal(z.zl, record.Level, record.Message, attrs)
	}

	// Ship action events to the dashboard if configured
	if z.poster != nil {
		shipToDashboard(z.poster, z.hostname, record.Time, record.Message, attrs)
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

func shipToDashboard(
	poster *poster, hostname string, rTime time.Time, rMsg string, attrs map[string]any,
) {
	act := ""

	if v, ok := attrs["action"]; ok {
		act = strings.ToUpper(fmt.Sprint(v))
	}

	if act != "BLOCKED" && act != actionRedirected && act != "ALLOWED" {
		return
	}

	payload := buildDashboardPayload(hostname, rTime, rMsg, act, attrs)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		poster.zl.Error().Err(err).Msg("dashboard: marshal error")

		return
	}

	poster.Enqueue(payloadBytes)
}

// handleBlockedAlert processes BLOCKED events and sends notifications.
// This is part of the alerting feature.
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
// Alerting feature helper function.
func extractStringAttr(attrs map[string]any, key string) string {
	if v, ok := attrs[key]; ok && v != nil {
		return fmt.Sprint(v)
	}

	return ""
}

// buildDestinationString creates a human-readable destination string.
// Alerting feature helper function.
func buildDestinationString(attrs map[string]any) string {
	// Try domain names first (SNI, hostname, DNS query name)
	if sni := extractStringAttr(attrs, "sni"); sni != "" {
		return sni
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

func buildDashboardPayload(
	hostname string, rTime time.Time, rMsg, act string, attrs map[string]any,
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
		notifier:  z.notifier,
	}
}

func (z *zerologHandler) WithGroup(name string) slog.Handler {
	_ = name // groups ignored

	return z
}

// ---------- constructors ----------

// NewWithContext builds a slog.Logger backed by zerolog for terminal/file output.
// 'format' and 'addSource' are kept for API compatibility; terminal/file output is console,
// and JSON is used only for API shipping via the poster.
//
//nolint:cyclop,funlen
func NewWithContext(ctx context.Context, level, format string, out io.Writer, addSource bool) *slog.Logger {
	_ = format
	_ = addSource

	// Writer (stdout or file, depending on LOG_FILE)
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
	log.Logger = zl

	// Dashboard poster
	lvl := parseLevel(lvlStr).Level()

	var poster *poster

	if dhost := strings.TrimSpace(os.Getenv("DASHBOARD_HOST")); dhost != "" {
		if !strings.HasPrefix(dhost, "http://") && !strings.HasPrefix(dhost, "https://") {
			dhost = "http://" + dhost
		}

		durl := strings.TrimRight(dhost, "/") + "/ingest"
		dapi := strings.TrimSpace(os.Getenv("DASHBOARD_API_KEY"))
		debugEnabled := lvl <= slog.LevelDebug
		traceEnabled := lvl <= LevelTrace

		poster = newPosterWithCtx(ctx, durl, dapi, zl, debugEnabled)
		poster.trace = traceEnabled

		// Fire a probe once initialised
		go func() {
			<-poster.ready

			err := poster.Probe(ctx)
			if err != nil {
				zl.Warn().Err(err).Str("url", durl).Msg("dashboard: probe error")
			} else {
				zl.Info().Str("url", durl).Msg("dashboard: probe ok")
			}
		}()
	}

	// Initialize alerting feature (optional)
	// This can be easily removed if alerting is not needed
	notifier := alerting.NewNotifier()

	// Bridge into slog
	h := &zerologHandler{zl: zl, termLevel: lvl, poster: poster, hostname: hostname, notifier: notifier}

	return slog.New(h)
}

// NewWithFormat builds a slog.Logger using defaults, delegating to NewWithContext with a background context.
func NewWithFormat(level, format string, out io.Writer, addSource bool) *slog.Logger {
	return NewWithContext(context.Background(), level, format, out, addSource)
}

// NewFromEnv creates a logger configured from environment variables.
func NewFromEnv() *slog.Logger {
	return NewWithFormat(os.Getenv("LOG_LEVEL"), os.Getenv("LOG_FORMAT"), os.Stdout, false)
}

// New returns a logger with the provided level string.
func New(l string) *slog.Logger { return NewWithFormat(l, "json", os.Stdout, false) }

// Shutdown stops the default poster (if any) and waits up to the provided timeout.
func Shutdown(timeout time.Duration) {
	if defaultPoster != nil {
		defaultPoster.Stop(timeout)
	}
}
