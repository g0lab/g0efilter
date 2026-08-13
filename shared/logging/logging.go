// Package logging provides a zerolog-backed slog logger with human-readable
// terminal output. Side channels beyond the terminal (dashboard shipping,
// alerting) are provided by an optional Hook.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/shared/actions"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// LevelTrace is below slog.LevelDebug.
const LevelTrace slog.Level = -8

const (
	keyAction    = "action"
	keyComponent = "component"

	defaultLogMaxSizeMB  = 100
	defaultLogMaxBackups = 7
	defaultLogMaxAgeDays = 28
)

//nolint:gochecknoglobals // Mutex guards the process-wide zerolog logger.
var globalLoggerMutex sync.Mutex

//nolint:gochecknoglobals // Registered hook stopped by Shutdown.
var (
	defaultHook     Hook
	defaultHookMu   sync.Mutex
	defaultRecorder *decisionRecorder
)

// Hook observes every log record for side effects beyond terminal output, such
// as shipping to a dashboard or alerting. A nil hook means terminal only.
type Hook interface {
	Handle(ctx context.Context, recordTime time.Time, msg string, attrs map[string]any)
	Stop(timeout time.Duration)
}

// Option configures the logger.
type Option func(*options)

type options struct {
	hook           Hook
	decisionWriter io.Writer
}

// WithHook attaches a Hook that receives every record. Passing a nil hook is a
// no-op (terminal-only logging).
func WithHook(h Hook) Option {
	return func(o *options) { o.hook = h }
}

// WithDecisionWriter writes enforcement decisions as JSON Lines. It is mainly
// useful to embedders and tests; DECISION_LOG_FILE configures the same output.
func WithDecisionWriter(w io.Writer) Option {
	return func(o *options) { o.decisionWriter = w }
}

type decisionRecorder struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

func (d *decisionRecorder) record(recordTime time.Time, level slog.Level, msg string, attrs map[string]any) error {
	action := extractAction(attrs)
	if action != actions.ActionAllowed && action != actions.ActionBlocked && action != actions.ActionAudit {
		return nil
	}

	event := make(map[string]any, len(attrs)+4)
	event["time"] = recordTime.UTC().Format(time.RFC3339Nano)
	event["level"] = level.String()
	event["event"] = msg

	for key, value := range attrs {
		if key != "time" && key != "level" && key != "event" {
			event[key] = value
		}
	}

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode decision record: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err = d.writer.Write(append(line, '\n'))
	if err != nil {
		return fmt.Errorf("write decision record: %w", err)
	}

	return nil
}

func setGlobalLogger(zl zerolog.Logger) {
	globalLoggerMutex.Lock()
	defer globalLoggerMutex.Unlock()

	log.Logger = zl
}

// ParseLevel maps a level name to its slog.Level (default INFO).
func ParseLevel(s string) slog.Level {
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

// zerologHandler implements slog.Handler using zerolog for terminal output and
// forwards each record to an optional Hook.
type zerologHandler struct {
	zl        zerolog.Logger
	termLevel slog.Level
	hook      Hook
	recorder  *decisionRecorder
	baseAttrs map[string]any // attributes from With() calls
}

func (z *zerologHandler) Enabled(_ context.Context, l slog.Level) bool {
	// Deliver sub-threshold records too when a hook or the decision log needs them.
	return l >= z.termLevel || z.hook != nil || z.recorder != nil
}

func (z *zerologHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]any, len(z.baseAttrs)+record.NumAttrs())
	maps.Copy(attrs, z.baseAttrs)

	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()

		return true
	})

	// IP-based ALLOWED events (allowlisted IPs from nftables) are noisy; keep
	// them off the terminal unless debugging.
	logLevel := record.Level
	if isAllowlistedIP(extractAction(attrs), attrs) {
		logLevel = slog.LevelDebug
	}

	if logLevel >= z.termLevel {
		logToTerminal(z.zl, logLevel, record.Message, attrs)
	}

	if z.hook != nil {
		z.hook.Handle(ctx, record.Time, record.Message, attrs)
	}

	if z.recorder != nil {
		err := z.recorder.record(record.Time, record.Level, record.Message, attrs)
		if err != nil {
			// slog discards handler errors, so a lost decision is only visible if it
			// is reported on the terminal instead.
			z.zl.Error().Str("event", "decision_log.write_failed").Err(err).Send()

			return err
		}
	}

	return nil
}

func extractAction(attrs map[string]any) string {
	if v, ok := attrs[keyAction]; ok {
		return strings.ToUpper(strings.TrimSpace(toString(v)))
	}

	return ""
}

func isAllowlistedIP(act string, attrs map[string]any) bool {
	if act != actions.ActionAllowed {
		return false
	}

	if v, ok := attrs[keyComponent]; ok {
		return strings.EqualFold(toString(v), "nflog")
	}

	return false
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}

	return ""
}

func logToTerminal(zl zerolog.Logger, level slog.Level, msg string, attrs map[string]any) {
	ev := zl.WithLevel(toZerologLevel(level))

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

func (z *zerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	logger := z.zl

	newBaseAttrs := make(map[string]any, len(z.baseAttrs)+len(attrs))
	maps.Copy(newBaseAttrs, z.baseAttrs)

	for _, attr := range attrs {
		val := attr.Value.Any()
		newBaseAttrs[attr.Key] = val

		switch v := val.(type) {
		case string:
			logger = logger.With().Str(attr.Key, v).Logger()
		case int:
			logger = logger.With().Int(attr.Key, v).Logger()
		case time.Time:
			logger = logger.With().Time(attr.Key, v).Logger()
		case error:
			logger = logger.With().Err(v).Logger()
		default:
			logger = logger.With().Interface(attr.Key, v).Logger()
		}
	}

	return &zerologHandler{
		zl:        logger,
		termLevel: z.termLevel,
		hook:      z.hook,
		recorder:  z.recorder,
		baseAttrs: newBaseAttrs,
	}
}

func (z *zerologHandler) WithGroup(_ string) slog.Handler {
	return z // groups ignored
}

// New builds a slog.Logger backed by zerolog. Output goes to out unless LOG_FILE
// is set, in which case a rotating file is used. Pass WithHook to attach a Hook.
func New(level string, out io.Writer, opts ...Option) *slog.Logger {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

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

	cw := zerolog.ConsoleWriter{Out: writer, TimeFormat: time.RFC3339}
	zl := zerolog.New(cw).With().Timestamp().Logger()

	lvlStr := strings.TrimSpace(level)
	if lvlStr == "" {
		lvlStr = os.Getenv("LOG_LEVEL")
	}

	lvl := ParseLevel(lvlStr)

	zerolog.SetGlobalLevel(toZerologLevel(lvl))
	setGlobalLogger(zl)

	if cfg.hook != nil {
		setDefaultHook(cfg.hook)
	}

	recorder := newDecisionRecorder(cfg.decisionWriter)

	defaultHookMu.Lock()
	previous := defaultRecorder
	defaultRecorder = recorder
	defaultHookMu.Unlock()

	closeRecorder(previous)

	return slog.New(&zerologHandler{
		zl:        zl,
		termLevel: lvl,
		hook:      cfg.hook,
		recorder:  recorder,
		baseAttrs: make(map[string]any),
	})
}

func newDecisionRecorder(writer io.Writer) *decisionRecorder {
	if writer != nil {
		return &decisionRecorder{writer: writer}
	}

	path := strings.TrimSpace(os.Getenv("DECISION_LOG_FILE"))
	if path == "" {
		return nil
	}

	file := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    defaultLogMaxSizeMB,
		MaxBackups: defaultLogMaxBackups,
		MaxAge:     defaultLogMaxAgeDays,
		Compress:   true,
	}

	return &decisionRecorder{writer: file, closer: file}
}

// NewFromEnv creates a terminal logger from LOG_LEVEL.
func NewFromEnv() *slog.Logger {
	return New(os.Getenv("LOG_LEVEL"), os.Stdout)
}

func setDefaultHook(h Hook) {
	defaultHookMu.Lock()
	defer defaultHookMu.Unlock()

	defaultHook = h
}

// Shutdown stops the registered hook (if any) and waits up to timeout.
func Shutdown(timeout time.Duration) {
	defaultHookMu.Lock()
	h := defaultHook
	recorder := defaultRecorder
	defaultHookMu.Unlock()

	if h != nil {
		h.Stop(timeout)
	}

	closeRecorder(recorder)
}

func closeRecorder(recorder *decisionRecorder) {
	if recorder == nil || recorder.closer == nil {
		return
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	_ = recorder.closer.Close()
}
