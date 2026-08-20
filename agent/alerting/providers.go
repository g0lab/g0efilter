package alerting

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/nicholas-fedor/shoutrrr"
	"github.com/nicholas-fedor/shoutrrr/pkg/router"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// sender fans one alert out to every service in NOTIFICATION_URLS.
type sender struct {
	router  *router.ServiceRouter
	targets string
}

func newSender(rawURLs []string, client *http.Client) (*sender, error) {
	// Not CreateSender: without the injected client each service dials unmarked and the filter blocks its own alerts.
	serviceRouter, err := shoutrrr.CreateSenderWithOptions(types.SenderOptions{
		HTTPClient: client,
		Timeout:    0,
	}, rawURLs...)
	if err != nil {
		return nil, fmt.Errorf("create notification sender: %w", err)
	}

	return &sender{router: serviceRouter, targets: redactAll(rawURLs)}, nil
}

// send fails only when every service failed.
func (s *sender) send(title, message string) error {
	// No SetLevel: gotify and ntfy reject a "level" param and fail the send.
	params := types.Params{}
	params.SetTitle(title)

	results := s.router.Send(message, &params)

	sendErrs := []error{}

	for _, err := range results {
		if err == nil {
			continue
		}

		if targetErr, ok := errors.AsType[*types.TargetError](err); ok {
			slog.Warn("notification.target_failed", "target", targetErr.URL, "err", targetErr.Err)
		}

		sendErrs = append(sendErrs, err)
	}

	if len(sendErrs) > 0 && len(sendErrs) == len(results) {
		return fmt.Errorf("send notification: %w", errors.Join(sendErrs...))
	}

	return nil
}

// parseURLs splits on whitespace, not commas: telegram lists its chats with commas.
func parseURLs(raw string) []string {
	return strings.Fields(raw)
}

// redactAll drops the token, which sits in userinfo, path or query by backend.
func redactAll(rawURLs []string) string {
	targets := make([]string, 0, len(rawURLs))

	for _, raw := range rawURLs {
		parsed, err := url.Parse(raw)
		if err != nil {
			targets = append(targets, "invalid-url")

			continue
		}

		targets = append(targets, parsed.Scheme+"://"+parsed.Host)
	}

	return strings.Join(targets, " ")
}
