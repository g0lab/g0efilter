package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/discord"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/slack"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/teams"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/telegram"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/email/smtp"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/gotify"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/ntfy"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/pushover"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/specialized/generic"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

const sendTimeout = 30 * time.Second

var (
	errUnsupportedService = errors.New("unsupported notification service")
	errInvalidURL         = errors.New("invalid notification url")
)

// Importing shoutrrr's router would link every service it ships; these are the ones we support.
//
//nolint:gochecknoglobals // read-only scheme registry
var services = map[string]func() types.Service{
	"discord":  func() types.Service { return &discord.Service{} },
	"generic":  func() types.Service { return &generic.Service{} },
	"gotify":   func() types.Service { return &gotify.Service{} },
	"ntfy":     func() types.Service { return &ntfy.Service{} },
	"pushover": func() types.Service { return &pushover.Service{} },
	"slack":    func() types.Service { return &slack.Service{} },
	"smtp":     func() types.Service { return &smtp.Service{} },
	"teams":    func() types.Service { return &teams.Service{} },
	"telegram": func() types.Service { return &telegram.Service{} },
}

// sender fans one alert out to every service in NOTIFICATION_URLS.
type sender struct {
	rawURLs []string
	client  *http.Client
	dial    types.DialContextFunc
	targets string
}

// newSender skips URLs it cannot use, so a service dropped in an upgrade does not
// silence the others. It fails only when no URL is usable.
func newSender(rawURLs []string, client *http.Client, dial types.DialContextFunc) (*sender, error) {
	s := &sender{client: client, dial: dial}

	var errs []error

	for _, raw := range rawURLs {
		_, err := s.service(raw)
		if err != nil {
			slog.Error("notification.target_invalid", "err", err)

			errs = append(errs, err)

			continue
		}

		s.rawURLs = append(s.rawURLs, raw)
	}

	if len(s.rawURLs) == 0 {
		return nil, fmt.Errorf("create notification sender: %w", errors.Join(errs...))
	}

	s.targets = redactAll(s.rawURLs)

	return s, nil
}

// service builds a fresh instance per send: ntfy appends its Title header to a
// client-lifetime header map, so a reused instance grows every request.
func (s *sender) service(raw string) (types.Service, error) {
	serviceURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errInvalidURL, redact(raw))
	}

	service, serviceURL, err := resolveService(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", redact(raw), err)
	}

	err = service.Initialize(serviceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", redact(raw), err)
	}

	// Without the marked client and dialer each service dials unmarked and the filter blocks its own alerts.
	if setter, ok := service.(types.HTTPClientSetter); ok && s.client != nil {
		setter.SetHTTPClient(s.client)
	}

	if setter, ok := service.(types.DialContextSetter); ok && s.dial != nil {
		setter.SetDialContext(s.dial)
	}

	return service, nil
}

// resolveService maps a scheme, or a custom "service+https" URL, to an uninitialised service.
func resolveService(serviceURL *url.URL) (types.Service, *url.URL, error) {
	scheme, _, custom := strings.Cut(strings.ToLower(serviceURL.Scheme), "+")

	newService, ok := services[scheme]
	if !ok {
		return nil, nil, fmt.Errorf("%w %q, use one of: %s", errUnsupportedService, scheme, supportedSchemes())
	}

	service := newService()
	if !custom {
		return service, serviceURL, nil
	}

	customService, ok := service.(types.CustomURLService)
	if !ok {
		return nil, nil, fmt.Errorf("%w %q", errUnsupportedService, serviceURL.Scheme)
	}

	serviceURL, err := customService.GetServiceURLFromCustom(serviceURL)
	if err != nil {
		return nil, nil, fmt.Errorf("convert custom url: %w", err)
	}

	return service, serviceURL, nil
}

// send fails only when every service failed.
func (s *sender) send(ctx context.Context, title, message string) error {
	errs := make([]error, len(s.rawURLs))

	var wg sync.WaitGroup

	for i, raw := range s.rawURLs {
		wg.Go(func() {
			errs[i] = s.sendOne(ctx, raw, title, message)
			if errs[i] != nil {
				slog.Warn("notification.target_failed", "target", redact(raw), "err", errs[i])
			}
		})
	}

	wg.Wait()

	failed := slices.DeleteFunc(errs, func(err error) bool { return err == nil })
	if len(failed) > 0 && len(failed) == len(s.rawURLs) {
		return fmt.Errorf("send notification: %w", errors.Join(failed...))
	}

	return nil
}

func (s *sender) sendOne(ctx context.Context, raw, title, message string) error {
	service, err := s.service(raw)
	if err != nil {
		return err
	}

	// No SetLevel: gotify and ntfy reject a "level" param and fail the send.
	params := types.Params{}
	params.SetTitle(title)

	ctx, cancel := context.WithTimeout(ctx, sendBudget(service, &params))
	defer cancel()

	// Only smtp takes a context; any other send is abandoned at the deadline
	// and ends on the HTTP client's own timeout.
	done := make(chan error, 1)

	go func() {
		if contextSender, ok := service.(types.ContextSender); ok {
			done <- contextSender.SendContext(ctx, message, &params)
		} else {
			done <- service.Send(message, &params)
		}
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err != nil {
		return fmt.Errorf("%s: %w", service.GetID(), err)
	}

	return nil
}

// sendBudget honors a longer budget a service reports, such as an smtp URL's timeout.
func sendBudget(service types.Service, params *types.Params) time.Duration {
	if reporter, ok := service.(types.ServiceTimeout); ok {
		return max(sendTimeout, reporter.ServiceTimeout(params))
	}

	return sendTimeout
}

func supportedSchemes() string {
	return strings.Join(slices.Sorted(maps.Keys(services)), ", ")
}

// parseURLs splits on whitespace, not commas: telegram lists its chats with commas.
func parseURLs(raw string) []string {
	return strings.Fields(raw)
}

// redact drops the token, which sits in userinfo, path or query by backend.
func redact(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}

	return parsed.Scheme + "://" + parsed.Host
}

func redactAll(rawURLs []string) string {
	targets := make([]string, 0, len(rawURLs))

	for _, raw := range rawURLs {
		targets = append(targets, redact(raw))
	}

	return strings.Join(targets, " ")
}
