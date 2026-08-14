package alerting

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	_, err := newSender([]string{"carrier-pigeon://roost/token"}, http.DefaultClient)
	if err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}

// A shoutrrr service that ignores the injected client would dial unmarked and
// have its own notification blocked by the filter, which is issue #110.
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

	host := strings.TrimPrefix(server.URL, "http://")

	tests := []struct {
		name string
		url  string
	}{
		{"gotify", "gotify://" + host + "/Aaa.bbb.ccc.ddd?disabletls=yes"},
		{"ntfy", "ntfy://" + host + "/g0efilter?scheme=http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := newSender([]string{tt.url}, server.Client())
			if err != nil {
				t.Fatalf("newSender: %v", err)
			}

			err = sender.send("Blocked", "example.com")
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
	}, server.Client())
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send("Blocked", "example.com")
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
	}, server.Client())
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send("Blocked", "example.com")
	if err != nil {
		t.Errorf("a partial failure must not be reported as a failure: %v", err)
	}
}

func TestSenderReportsTotalFailure(t *testing.T) {
	t.Parallel()

	sender, err := newSender([]string{"ntfy://127.0.0.1:1/dead?scheme=http"}, http.DefaultClient)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}

	err = sender.send("Blocked", "example.com")
	if err == nil {
		t.Fatal("expected an error when every service failed")
	}
}
