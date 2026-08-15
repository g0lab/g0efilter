// Package telemetry ships filter decision events to the dashboard and raises
// alerts. It plugs into shared/logging as a Hook.
package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/agent/alerting"
	"github.com/g0lab/g0efilter/agent/kubeevents"
	"github.com/g0lab/g0efilter/agent/metrics"
	"github.com/g0lab/g0efilter/agent/netutil"
	"github.com/g0lab/g0efilter/agent/recovery"
	"github.com/g0lab/g0efilter/agent/safeio"
	"github.com/g0lab/g0efilter/shared/actions"
	"github.com/g0lab/g0efilter/shared/logging"
	"github.com/rs/zerolog"
)

const (
	keyAction          = "action"
	keyComponent       = "component"
	keyHostname        = "hostname"
	keyHost            = "host"
	keyDestinationPort = "destination_port"
	keyTime            = "time"

	defaultQueueSize         = 1024
	defaultWorkers           = 3
	defaultRetryTimeout      = 5 * time.Second
	defaultIdleConnTimeout   = 90 * time.Second
	defaultHTTPClientTimeout = 15 * time.Second
	defaultRetryWait         = 500 * time.Millisecond
	defaultRetryWaitMax      = 5 * time.Second
	defaultProbeTimeout      = 5 * time.Second
	defaultStartDelay        = 5 * time.Second
)

var errProbeStatus = errors.New("probe unexpected status")

// Shipper implements logging.Hook: it forwards decision events to the dashboard
// poster, raises alerts, and records Kubernetes Events for alert-flagged events.
type Shipper struct {
	poster    *poster
	notifier  *alerting.Notifier
	kubeevent *kubeevents.Recorder
	metrics   *metrics.Metrics
	hostname  string
	version   string
}

// NewFromEnv builds the agent telemetry hook: it ships to the dashboard when
// DASHBOARD_HOST is set, alerts when NOTIFICATION_URLS is, records Kubernetes
// Events when KUBE_EVENTS is, and counts verdicts when METRICS_ADDR is. A nil hook
// means none are configured (terminal-only logging). The returned registry is nil
// unless metrics are enabled, and is what the caller serves.
//
//nolint:ireturn // deliberate seam: a nil Hook means terminal-only logging.
func NewFromEnv(
	ctx context.Context,
	out io.Writer,
	level slog.Level,
	version string,
) (logging.Hook, *metrics.Metrics) {
	cw := zerolog.ConsoleWriter{Out: out, TimeFormat: time.RFC3339}
	zl := zerolog.New(cw).With().Timestamp().Logger()

	hostname := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil {
			hostname = strings.TrimSpace(h)
		}
	}

	var p *poster

	if dhost := strings.TrimSpace(os.Getenv("DASHBOARD_HOST")); dhost != "" {
		p = initializeDashboardPoster(ctx, dhost, zl, level)
	}

	notifier := alerting.NewNotifier() // nil unless NOTIFICATION_URLS is set

	recorder := kubeevents.NewFromEnv(slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level})))

	var registry *metrics.Metrics

	if strings.TrimSpace(os.Getenv("METRICS_ADDR")) != "" {
		registry = metrics.New()
	}

	if p == nil && notifier == nil && recorder == nil && registry == nil {
		return nil, nil // nothing to ship, alert, record or count; terminal-only logging
	}

	return &Shipper{
		poster:    p,
		notifier:  notifier,
		kubeevent: recorder,
		metrics:   registry,
		hostname:  hostname,
		version:   version,
	}, registry
}

// Handle ships the record to the dashboard and alerts as configured.
func (s *Shipper) Handle(ctx context.Context, recordTime time.Time, msg string, attrs map[string]any) {
	if msg == recovery.PanicMessage {
		s.metrics.RecordPanic(extractStringAttr(attrs, keyComponent))

		return
	}

	act := extractAction(attrs)

	if s.poster != nil && act != "" {
		s.ship(recordTime, msg, act, attrs)
	}

	if act != "" {
		s.metrics.RecordConnection(extractStringAttr(attrs, keyComponent), act)
	}

	if !shouldAlert(attrs) {
		return
	}

	s.metrics.RecordDenial(extractStringAttr(attrs, keyComponent), blockReason(attrs))

	if s.notifier != nil {
		handleBlockedAlert(ctx, s.notifier, attrs)
	}

	s.kubeevent.RecordBlock(ctx, kubeevents.Denial{
		Component:   extractStringAttr(attrs, keyComponent),
		Destination: buildDestinationString(attrs),
		Reason:      blockReason(attrs),
		SourceIP:    extractStringAttr(attrs, "source_ip"),
	})
}

// RecordPolicyError reports a rejected policy reload as a Kubernetes Event.
func (s *Shipper) RecordPolicyError(ctx context.Context, cause error) {
	if s == nil {
		return
	}

	s.kubeevent.RecordPolicyError(ctx, cause)
}

// Stop drains and stops the dashboard poster.
func (s *Shipper) Stop(timeout time.Duration) {
	if s.poster != nil {
		s.poster.Stop(timeout)
	}
}

func (s *Shipper) ship(rTime time.Time, msg, act string, attrs map[string]any) {
	if !shouldShipToDashboard(act, attrs) {
		return
	}

	payload := buildDashboardPayload(s.hostname, s.version, rTime, msg, act, attrs)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.poster.zl.Error().Err(err).Msg("dashboard: marshal error")

		return
	}

	select {
	case s.poster.q <- payloadBytes:
	default:
		s.poster.zl.Warn().Msg("dashboard.queue_full")
	}
}

func extractAction(attrs map[string]any) string {
	if v, ok := attrs[keyAction]; ok {
		return strings.ToUpper(fmt.Sprint(v))
	}

	return ""
}

// shouldShipToDashboard reports whether an event is shipped. Only BLOCKED,
// ALLOWED and AUDIT go up; ALLOWED events from nftables (allowlisted IPs,
// component=nflog) stay in console logs only.
func shouldShipToDashboard(act string, attrs map[string]any) bool {
	if act != actions.ActionBlocked && act != actions.ActionAllowed && act != actions.ActionAudit {
		return false
	}

	if act == actions.ActionAllowed {
		if v, ok := attrs[keyComponent]; ok && strings.EqualFold(fmt.Sprint(v), "nflog") {
			return false
		}
	}

	return true
}

// shouldAlert reports whether a record is an enforcement event that warrants a
// notification. Producers mark these with alert=true.
func shouldAlert(attrs map[string]any) bool {
	if v, ok := attrs[actions.KeyAlert]; ok {
		b, _ := v.(bool)

		return b
	}

	return false
}

// Canonical keys the dashboard accepts.
//
//nolint:gochecknoglobals
var dashboardKeys = []string{
	"component", "source_ip", "source_port",
	"destination_ip", "destination_port",
	"protocol", "policy_hit", "payload_len",
	"https", "http_host", "host", // HTTP
	"qname", "qtype", "rcode", // DNS
	"reason", "note", // context
	"src", "dst", // 5-tuple strings
	"hostname", "flow_id", "version",
}

func getCanonicalTime(attrs map[string]any, fallback time.Time) string {
	if t, ok := attrs[keyTime]; ok && fmt.Sprint(t) != "" {
		return fmt.Sprint(t)
	}

	return fallback.Format(time.RFC3339Nano)
}

func normalizeAttributeKeys(attrs map[string]any) {
	if v, ok := attrs["client_ip"]; ok {
		attrs["source_ip"] = v
	}

	if v, ok := attrs["dst_ip"]; ok {
		attrs["destination_ip"] = v
	}

	if v, ok := attrs["dst_port"]; ok {
		attrs[keyDestinationPort] = v
	}
	// HTTP host: prefer explicit http_host, else host.
	if _, ok := attrs["http_host"]; !ok {
		if v, ok := attrs[keyHost]; ok && fmt.Sprint(v) != "" {
			attrs["http_host"] = v
		}
	}
}

//nolint:cyclop
func buildDashboardPayload(
	hostname, version string, rTime time.Time, rMsg, act string, attrs map[string]any,
) map[string]any {
	payload := map[string]any{
		"producer_time": rTime.Format(time.RFC3339Nano),
		"msg":           rMsg,
		keyAction:       act,
		keyTime:         getCanonicalTime(attrs, rTime),
	}

	// Clone attrs to avoid mutating the caller's map.
	norm := make(map[string]any, len(attrs))
	maps.Copy(norm, attrs)
	normalizeAttributeKeys(norm)

	if hostname != "" {
		if _, ok := norm[keyHostname]; !ok || fmt.Sprint(norm[keyHostname]) == "" {
			payload[keyHostname] = hostname
		}
	}

	if version != "" {
		if _, ok := norm["version"]; !ok || fmt.Sprint(norm["version"]) == "" {
			payload["version"] = version
		}
	}

	for _, key := range dashboardKeys {
		if val, ok := norm[key]; ok && val != nil && fmt.Sprint(val) != "" {
			payload[key] = val
		}
	}

	return payload
}

// handleBlockedAlert builds and sends a notification for an alert-flagged event.
func handleBlockedAlert(ctx context.Context, notifier *alerting.Notifier, attrs map[string]any) {
	info := alerting.BlockedConnectionInfo{
		SourceIP:        extractStringAttr(attrs, "source_ip"),
		SourcePort:      extractStringAttr(attrs, "source_port"),
		DestinationIP:   extractStringAttr(attrs, "destination_ip"),
		DestinationPort: extractStringAttr(attrs, keyDestinationPort),
		Destination:     buildDestinationString(attrs),
		Component:       extractStringAttr(attrs, keyComponent),
	}

	info.Reason = blockReason(attrs)

	if info.Component == "" {
		info.Component = "filter"
	}

	notifier.NotifyBlock(ctx, info)
}

// blockReason prefers an explicit reason, then a note, then a generic fallback.
func blockReason(attrs map[string]any) string {
	if reason := extractStringAttr(attrs, "reason"); reason != "" {
		return reason
	}

	if note := extractStringAttr(attrs, "note"); note != "" {
		return note
	}

	return "blocked by policy"
}

func extractStringAttr(attrs map[string]any, key string) string {
	if v, ok := attrs[key]; ok && v != nil {
		return fmt.Sprint(v)
	}

	return ""
}

func buildDestinationString(attrs map[string]any) string {
	for _, key := range []string{"https", "http_host", keyHost, "qname", "dst"} {
		if v := extractStringAttr(attrs, key); v != "" {
			return v
		}
	}

	destIP := extractStringAttr(attrs, "destination_ip")
	if destIP == "" {
		return "unknown destination"
	}

	if destPort := extractStringAttr(attrs, keyDestinationPort); destPort != "" {
		return net.JoinHostPort(destIP, destPort)
	}

	return destIP
}

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
	retryMax     int
	retryWaitMin time.Duration
	retryWaitMax time.Duration
}

func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}

	if resp == nil {
		return false
	}

	return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
}

// newPoster is a convenience wrapper for tests.
func newPoster(url, apiKey string, zl zerolog.Logger, debug bool) *poster {
	return newPosterWithCtx(context.Background(), url, apiKey, zl, debug, defaultQueueSize)
}

func newPosterWithCtx(ctx context.Context, url, apiKey string, zl zerolog.Logger, debug bool, queueSize int) *poster {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	p := &poster{
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
		// SO_MARK bypass so shipping to the dashboard is not itself filtered.
		DialContext:           netutil.MarkedDialer(defaultHTTPClientTimeout).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	p.httpC = &http.Client{Timeout: defaultHTTPClientTimeout, Transport: tr}
	p.retryMax = 4
	p.retryWaitMin = defaultRetryWait
	p.retryWaitMax = defaultRetryWaitMax

	startDelay := defaultStartDelay

	if v := strings.TrimSpace(os.Getenv("DASHBOARD_START_DELAY")); v != "" {
		d, derr := time.ParseDuration(v)
		if derr == nil && d >= 0 {
			startDelay = d
		}
	}

	p.startDelay = startDelay

	go p.startWorker(ctx)

	return p
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
	// Non-blocking send, drop if queue full.
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
		keyTime: time.Now().UTC().Format(time.RFC3339Nano),
		"msg":   "_dashboard_probe",
	}

	payload, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("failed to marshal probe: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext( //nolint:gosec // G704: URL from config, not user input
		ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create probe request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	setAPIAuthHeaders(req.Header, p.apiKey)

	resp, err := p.httpC.Do(req) //nolint:gosec // G107: URL from config
	if err != nil {
		return fmt.Errorf("failed to execute probe request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	drainErr := safeio.DrainAndClose(resp.Body)
	if drainErr != nil {
		p.zl.Warn().Err(drainErr).Msg("http.body_close_error")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: %d", errProbeStatus, resp.StatusCode)
	}

	return nil
}

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

	if p.trace {
		logTraceBody(p.zl, p.url, payload)
	}

	retryCtx, cancel := context.WithTimeout(ctx, p.retryTimeout)
	defer cancel()

	backoffDuration := p.retryWaitMin

	for {
		select {
		case <-retryCtx.Done():
			p.zl.Warn().Str("url", p.url).Msg("dashboard: giving up after timeout")

			return
		default:
			if p.attemptPost(retryCtx, payload) {
				return
			}

			if p.debug {
				p.zl.Debug().Str("url", p.url).Msg("dashboard: posting failed, will retry")
			}

			time.Sleep(addJitter(backoffDuration))

			if backoffDuration < p.retryWaitMax {
				backoffDuration *= 2
				if backoffDuration > p.retryWaitMax {
					backoffDuration = p.retryWaitMax
				}
			}
		}
	}
}

// addJitter adds a random factor (0.5 to 1.0) to duration.
func addJitter(d time.Duration) time.Duration {
	jitterBig, err := rand.Int(rand.Reader, big.NewInt(500))
	if err != nil {
		return d
	}

	jitter := 0.5 + float64(jitterBig.Int64())/1000.0

	return time.Duration(float64(d) * jitter)
}

func (p *poster) attemptPost(ctx context.Context, payload []byte) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		p.zl.Error().Err(err).Msg("dashboard: build request error")

		return true // Don't retry on request creation errors.
	}

	req.Header.Set("Content-Type", "application/json")
	setAPIAuthHeaders(req.Header, p.apiKey)

	resp, err := p.httpC.Do(req)

	if !shouldRetry(resp, err) {
		return p.handleFinalResponse(resp, err)
	}

	if err != nil {
		p.zl.Debug().Err(err).Msg("dashboard: post attempt failed")
	} else if resp != nil {
		p.zl.Debug().Int("status", resp.StatusCode).Msg("dashboard: post attempt failed with status")
		_ = resp.Body.Close()
	}

	return false // Continue retrying.
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

	truncated := false

	if len(body) > maxBody {
		body = body[:maxBody]
		truncated = true
	}

	ev := zl.Trace().Str("url", url).Bool("truncated", truncated)
	if json.Valid(body) {
		ev = ev.RawJSON("body", body)
	} else {
		ev = ev.Str("body", string(body))
	}

	ev.Msg("dashboard.post body")
}

func logPosterResponse(zl zerolog.Logger, resp *http.Response, trace bool) {
	if !trace {
		drainErr := safeio.DrainAndClose(resp.Body)
		if drainErr != nil {
			zl.Warn().Err(drainErr).Msg("http.body_close_error")
		}

		return
	}

	const maxRead = 8 << 10

	rb, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if rerr != nil {
		// Chunked/gzip read errors can indicate truncation/tamper.
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

	close(p.ready) // Signal that shipping is beginning.

	p.wg.Add(p.workers)

	for range p.workers {
		go p.worker(ctx)
	}

	p.wg.Wait()
	close(p.done)
}

// initializeDashboardPoster sets up the dashboard HTTP poster from environment.
func initializeDashboardPoster(ctx context.Context, dhost string, zl zerolog.Logger, level slog.Level) *poster {
	if !strings.HasPrefix(dhost, "http://") && !strings.HasPrefix(dhost, "https://") {
		dhost = "http://" + dhost
	}

	durl := strings.TrimRight(dhost, "/") + "/api/v1/logs"
	dapi := strings.TrimSpace(os.Getenv("DASHBOARD_API_KEY"))

	p := newPosterWithCtx(ctx, durl, dapi, zl, level <= slog.LevelDebug, parseQueueSize(zl))
	p.trace = level <= logging.LevelTrace

	go func() {
		<-p.ready

		err := p.Probe(ctx)
		if err != nil {
			zl.Warn().Err(err).Str("url", durl).Msg("dashboard: probe error")
		} else {
			zl.Info().Str("url", durl).Msg("dashboard: probe ok")
		}
	}()

	return p
}

// parseQueueSize reads and validates DASHBOARD_QUEUE_SIZE from environment.
func parseQueueSize(zl zerolog.Logger) int {
	qsizeStr := strings.TrimSpace(os.Getenv("DASHBOARD_QUEUE_SIZE"))
	if qsizeStr == "" {
		return defaultQueueSize
	}

	var parsed int

	n, err := fmt.Sscanf(qsizeStr, "%d", &parsed)
	if err != nil || n != 1 || parsed <= 0 {
		zl.Warn().Str("value", qsizeStr).Msg("invalid DASHBOARD_QUEUE_SIZE, using default")

		return defaultQueueSize
	}

	return parsed
}
