// Package logging provides application logging helpers.
//
//nolint:gci,gofumpt
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"g0filter/internal/safeio"
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
	client     *retryablehttp.Client
	httpC      *http.Client
	stop       chan struct{}
	done       chan struct{}
	zl         zerolog.Logger
	debug      bool
	trace      bool
	ready      chan struct{}
	startDelay time.Duration
}

type retryLogger struct {
	zl  zerolog.Logger
	lvl zerolog.Level
}

func (r *retryLogger) Printf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	r.logMsg(msg)
}

func (r *retryLogger) Println(v ...any) { r.Printf("%s", fmt.Sprint(v...)) }

func (r *retryLogger) logMsg(msg string) {
	switch r.lvl {
	case zerolog.NoLevel, zerolog.InfoLevel, zerolog.Disabled:
		r.zl.Info().Msg(msg)
	case zerolog.TraceLevel:
		r.zl.Trace().Msg(msg)
	case zerolog.DebugLevel:
		r.zl.Debug().Msg(msg)
	case zerolog.WarnLevel:
		r.zl.Warn().Msg(msg)
	case zerolog.ErrorLevel:
		r.zl.Error().Msg(msg)
	case zerolog.FatalLevel:
		r.zl.Fatal().Msg(msg)
	case zerolog.PanicLevel:
		r.zl.Panic().Msg(msg)
	default:
		r.zl.Info().Msg(msg)
	}
}

type nopLogger struct{}

func (n *nopLogger) Printf(string, ...any) {}
func (n *nopLogger) Println(...any)        {}

func newPoster(url, apiKey string, zl zerolog.Logger, debug bool) *poster {
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

	rc := retryablehttp.NewClient()
	rc.RetryMax = 4
	rc.RetryWaitMin = defaultRetryWait
	rc.RetryWaitMax = defaultRetryWaitMax
	rc.Backoff = retryablehttp.DefaultBackoff
	rc.HTTPClient = poster.httpC

	if debug {
		rc.Logger = &retryLogger{zl: zl, lvl: zerolog.DebugLevel}
	} else {
		rc.Logger = &nopLogger{}
	}

	poster.client = rc

	// Start the worker after a small startup delay (DASHBOARD_START_DELAY, default 5s)
	startDelay := defaultStartDelay

	if v := strings.TrimSpace(os.Getenv("DASHBOARD_START_DELAY")); v != "" {
		d, derr := time.ParseDuration(v)
		if derr == nil && d >= 0 {
			startDelay = d
		}
	}

	poster.startDelay = startDelay

	go poster.startWorker()

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

func (p *poster) Probe() error {
	probe := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"level": "INFO",
		"msg":   "_dashboard_probe",
	}

	payload, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("failed to marshal probe: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
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

func (p *poster) startWorker() {
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
	p.worker()     // closes p.done when it exits
}

// setAPIAuthHeaders de-duplicates setting both API key headers everywhere.
func setAPIAuthHeaders(headers http.Header, apiKey string) {
	if apiKey == "" {
		return
	}

	headers.Set("X-Api-Key", apiKey)
	headers.Set("Authorization", "Bearer "+apiKey)
}

func (p *poster) handlePostPayload(payload []byte) {
	if p.debug {
		p.zl.Debug().Int("payload_size", len(payload)).Str("url", p.url).Msg("dashboard.posting")
	}

	// TRACE: log the exact body being sent (truncated)
	if p.trace {
		logTraceBody(p.zl, p.url, payload)
	}

	rreq, err := retryablehttp.NewRequest(http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		p.zl.Error().Err(err).Msg("dashboard: build request error")

		return
	}

	rreq.Header.Set("Content-Type", "application/json")
	setAPIAuthHeaders(rreq.Header, p.apiKey)

	resp, err := p.client.Do(rreq)
	if err != nil {
		p.zl.Error().Err(err).Msg("dashboard: post error")

		return
	}

	defer func() { _ = resp.Body.Close() }()

	logPosterResponse(p.zl, resp, p.trace)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		p.zl.Warn().Int("status", resp.StatusCode).Str("url", p.url).
			Msg("dashboard: unexpected status when posting logs")

		return
	}
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

func (p *poster) worker() {
	defer close(p.done)

	for {
		select {
		case payload := <-p.q:
			p.handlePostPayload(payload)
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

type zerologHandler struct {
	zl        zerolog.Logger
	termLevel slog.Level
	poster    *poster
	hostname  string
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

func (z *zerologHandler) Handle(_ context.Context, record slog.Record) error {
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
		shipToDashboard(z.poster, z.hostname, record.Time, record.Level, record.Message, attrs)
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
	poster *poster, hostname string, rTime time.Time, rLevel slog.Level, rMsg string, attrs map[string]any,
) {
	act := ""

	if v, ok := attrs["action"]; ok {
		act = strings.ToUpper(fmt.Sprint(v))
	}

	if act != "BLOCKED" && act != actionRedirected && act != "ALLOWED" {
		return
	}

	payload := buildDashboardPayload(hostname, rTime, rLevel, rMsg, act, attrs)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		poster.zl.Error().Err(err).Msg("dashboard: marshal error")

		return
	}

	poster.Enqueue(payloadBytes)
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
	hostname string, rTime time.Time, rLevel slog.Level, rMsg, act string, attrs map[string]any,
) map[string]any {
	payload := map[string]any{
		"producer_time": rTime.Format(time.RFC3339Nano),
		"level":         rLevel.String(),
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

	return &zerologHandler{zl: logger, termLevel: z.termLevel, poster: z.poster, hostname: z.hostname}
}

func (z *zerologHandler) WithGroup(name string) slog.Handler {
	_ = name // groups ignored

	return z
}

// ---------- constructors ----------

// NewWithFormat builds a slog.Logger backed by zerolog for terminal/file output.
// 'format' and 'addSource' are kept for API compatibility; terminal/file output is console,
// and JSON is used only for API shipping via the poster.
//
//nolint:cyclop,funlen
func NewWithFormat(level, format string, out io.Writer, addSource bool) *slog.Logger {
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

		poster = newPoster(durl, dapi, zl, debugEnabled)
		poster.trace = traceEnabled

		// Fire a probe once initialised
		go func() {
			<-poster.ready

			err := poster.Probe()
			if err != nil {
				zl.Warn().Err(err).Str("url", durl).Msg("dashboard: probe error")
			} else {
				zl.Info().Str("url", durl).Msg("dashboard: probe ok")
			}
		}()
	}

	// Bridge into slog
	h := &zerologHandler{zl: zl, termLevel: lvl, poster: poster, hostname: hostname}

	return slog.New(h)
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
