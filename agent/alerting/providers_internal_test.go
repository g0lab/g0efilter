package alerting

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   \n ", nil},
		{"single", "ntfy://ntfy.sh/topic", []string{"ntfy://ntfy.sh/topic"}},
		{
			"space separated",
			"ntfy://ntfy.sh/topic gotify://host/Aaa.bbb.ccc.ddd",
			[]string{"ntfy://ntfy.sh/topic", "gotify://host/Aaa.bbb.ccc.ddd"},
		},
		{
			"newline separated",
			"ntfy://ntfy.sh/topic\ngotify://host/Aaa.bbb.ccc.ddd",
			[]string{"ntfy://ntfy.sh/topic", "gotify://host/Aaa.bbb.ccc.ddd"},
		},
		{
			// Telegram lists its chats with commas, so they must not split URLs.
			"commas stay inside a url",
			"telegram://12345:token@telegram?chats=111,222",
			[]string{"telegram://12345:token@telegram?chats=111,222"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parseURLs(tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("parseURLs(%q) = %v, want %v", tt.raw, got, tt.want)
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseURLs(%q)[%d] = %q, want %q", tt.raw, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRedactAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		urls []string
		want string
	}{
		{"gotify token in path", []string{"gotify://host/Aaa.bbb.ccc.ddd"}, "gotify://host"},
		{"telegram token in userinfo", []string{"telegram://12345:secret@telegram?chats=1"}, "telegram://telegram"},
		{"ntfy credentials", []string{"ntfy://user:pass@ntfy.sh/topic"}, "ntfy://ntfy.sh"},
		{
			"multiple",
			[]string{"gotify://host/Aaa.bbb.ccc.ddd", "ntfy://ntfy.sh/topic"},
			"gotify://host ntfy://ntfy.sh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := redactAll(tt.urls)
			if got != tt.want {
				t.Errorf("redactAll(%v) = %q, want %q", tt.urls, got, tt.want)
			}

			for _, secret := range []string{"Aaa.bbb.ccc.ddd", "secret", "pass"} {
				if strings.Contains(got, secret) {
					t.Errorf("redactAll(%v) leaked %q in %q", tt.urls, secret, got)
				}
			}
		})
	}
}

func TestNewSenderRejectsUnknownScheme(t *testing.T) {
	t.Parallel()

	_, err := newSender([]string{"carrier-pigeon://roost/token"}, http.DefaultClient, nil)
	if err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}

// Issue #110: the host never resolves, so only the injected, marked client can deliver.
//
//nolint:tparallel,paralleltest // The subtests share one server and one channel.
func TestSenderUsesInjectedClient(t *testing.T) {
	t.Parallel()

	reached := make(chan string, 4)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}}

	tests := []struct {
		name string
		url  string
	}{
		{"gotify", "gotify://notify.invalid/Aaa.bbb.ccc.ddd?disabletls=yes"},
		{"ntfy", "ntfy://notify.invalid/g0efilter?scheme=http"},
		{"generic", "generic+http://notify.invalid/hook"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := newSender([]string{tt.url}, client, nil)
			if err != nil {
				t.Fatalf("newSender: %v", err)
			}

			err = sender.send(t.Context(), "Blocked", "example.com")
			if err != nil {
				t.Fatalf("send: %v", err)
			}

			select {
			case <-reached:
			default:
				t.Fatal("the notification never reached the server, so the injected client was bypassed")
			}
		})
	}
}

func TestSenderFanOut(t *testing.T) {
	t.Parallel()

	hits := make(chan struct{}, 8)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits <- struct{}{}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	sender, err := newSender([]string{
		"gotify://" + host + "/Aaa.bbb.ccc.ddd?disabletls=yes",
		"ntfy://" + host + "/g0efilter?scheme=http",
	}, server.Client(), nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if len(hits) != 2 {
		t.Errorf("expected both services to be notified, got %d deliveries", len(hits))
	}
}

// One dead backend must not suppress an alert that another one delivered.
func TestSenderToleratesPartialFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	sender, err := newSender([]string{
		"ntfy://" + host + "/g0efilter?scheme=http",
		"ntfy://127.0.0.1:1/dead?scheme=http",
	}, server.Client(), nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if err != nil {
		t.Errorf("a partial failure must not be reported as a failure: %v", err)
	}
}

func TestSenderReportsTotalFailure(t *testing.T) {
	t.Parallel()

	sender, err := newSender([]string{"ntfy://127.0.0.1:1/dead?scheme=http"}, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if err == nil {
		t.Fatal("expected an error when every service failed")
	}
}

func TestNewSenderRejectsDroppedService(t *testing.T) {
	t.Parallel()

	_, err := newSender([]string{"xmpp://user:pass@example.com/?toaddresses=a@example.com"}, http.DefaultClient, nil)
	if !errors.Is(err, errUnsupportedService) {
		t.Fatalf("expected errUnsupportedService, got %v", err)
	}
}

// An upgrade that drops a service must not silence the supported ones beside it.
func TestNewSenderSkipsUnsupportedService(t *testing.T) {
	t.Parallel()

	reached := make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached <- struct{}{}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	sender, err := newSender([]string{
		"xmpp://user:pass@example.com/?toaddresses=a@example.com",
		"ntfy://" + host + "/g0efilter?scheme=http",
	}, server.Client(), nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	if sender.targets != "ntfy://"+host {
		t.Errorf("targets = %q, want only the ntfy target", sender.targets)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case <-reached:
	default:
		t.Fatal("the supported service was not notified")
	}
}

// generic has no SendContext, so only the send budget can cut off a hung endpoint,
// and the fan-out must not hold the healthy target's alert behind it.
func TestSenderCutsOffAStalledTarget(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stalled.Close()
	defer close(release)

	reached := make(chan struct{}, 1)

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached <- struct{}{}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer healthy.Close()

	sender, err := newSender([]string{
		"generic+http://" + strings.TrimPrefix(stalled.URL, "http://") + "/hook",
		"ntfy://" + strings.TrimPrefix(healthy.URL, "http://") + "/g0efilter?scheme=http",
	}, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()

	err = sender.send(ctx, "Blocked", "example.com")
	if err != nil {
		t.Fatalf("the healthy target delivered, so send must succeed: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("send took %v after a 100ms deadline", elapsed)
	}

	select {
	case <-reached:
	default:
		t.Fatal("the healthy target was not notified")
	}
}

// The old router waited as long as a service asked; a short fixed budget would cut
// off an smtp server the operator gave longer.
func TestSenderHonorsALongerSMTPTimeout(t *testing.T) {
	t.Parallel()

	remaining := make(chan time.Duration, 1)

	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		remaining <- time.Until(deadline)

		return nil, errDialed
	}

	sender, err := newSender([]string{
		"smtp://mail.example.com:587/?fromaddress=a@example.com&toaddresses=b@example.com&auth=None&timeout=2m",
	}, http.DefaultClient, dial)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	_ = sender.send(t.Context(), "Blocked", "example.com")

	if got := <-remaining; got <= sendTimeout {
		t.Errorf("smtp dial had %v left, want the configured 2m", got)
	}
}

// Regression: a reused ntfy service appended one Title header per alert.
func TestSenderBareNtfyURLRepeatedSends(t *testing.T) {
	t.Parallel()

	titles := make(chan []string, 4)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		titles <- r.Header.Values("Title")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	sender, err := newSender([]string{"ntfy://" + host + "/mytopic?scheme=http"}, server.Client(), nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	for range 3 {
		err = sender.send(t.Context(), "Blocked", "example.com")
		if err != nil {
			t.Fatalf("send: %v", err)
		}

		got := <-titles
		if len(got) != 1 || got[0] != "Blocked" {
			t.Fatalf("Title headers = %q, want exactly [Blocked]", got)
		}
	}
}

func TestSenderGenericCustomURL(t *testing.T) {
	t.Parallel()

	reached := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	sender, err := newSender([]string{"generic+http://" + host + "/hook"}, server.Client(), nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if path := <-reached; path != "/hook" {
		t.Errorf("webhook path = %q, want /hook", path)
	}
}

var errDialed = errors.New("dialed through injected dialer")

// smtp skips the HTTP client, so the marked dialer is its only way past the filter.
func TestSenderSMTPUsesInjectedDialer(t *testing.T) {
	t.Parallel()

	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errDialed
	}

	sender, err := newSender([]string{
		"smtp://mail.example.com:587/?fromaddress=a@example.com&toaddresses=b@example.com&auth=None",
	}, http.DefaultClient, dial)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send(t.Context(), "Blocked", "example.com")
	if !errors.Is(err, errDialed) {
		t.Fatalf("expected the injected dialer to be used, got %v", err)
	}
}

func TestNewSenderAcceptsPushover(t *testing.T) {
	t.Parallel()

	_, err := newSender([]string{"pushover://shoutrrr:apptoken@userkey/?devices=phone"}, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
}
