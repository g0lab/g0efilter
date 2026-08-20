package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

const dashboardTimeout = 15 * time.Second

// Response is a typed dashboard API response. Keeping the status, headers and
// decoded body together replaces grepping raw JSON for substrings.
type Response[T any] struct {
	StatusCode int
	Header     http.Header
	Body       T
	RawBody    string
}

// DashboardClient talks to the dashboard over its mapped host port.
type DashboardClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// DashboardAPI returns a client authenticated with the stack's API key.
func (s *Stack) DashboardAPI(t *testing.T) *DashboardClient {
	t.Helper()

	return s.NewDashboardClient(t, s.Config.APIKey)
}

// NewDashboardClient builds a client with its own cookie jar, so session tests
// do not leak state into each other.
func (s *Stack) NewDashboardClient(t *testing.T, apiKey string) *DashboardClient {
	t.Helper()

	return newClient(t, s.DashboardURL, apiKey)
}

func newClient(t *testing.T, baseURL, apiKey string) *DashboardClient {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	return &DashboardClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout: dashboardTimeout,
			Jar:     jar,
			// Redirects are asserted on directly by the auth tests.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// RequestOption customizes one request.
type RequestOption func(*http.Request)

// WithHeader sets a request header.
func WithHeader(name, value string) RequestOption {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// WithAPIKey authenticates with a machine key.
func WithAPIKey(key string) RequestOption {
	return func(r *http.Request) { r.Header.Set("X-Api-Key", key) }
}

// SameOrigin marks a mutation as same-origin, which the CSRF guard requires.
func SameOrigin() RequestOption {
	return WithHeader("Sec-Fetch-Site", "same-origin")
}

// NoAuth strips the client's default API key for unauthenticated checks.
func NoAuth() RequestOption {
	return func(r *http.Request) { r.Header.Del("X-Api-Key") }
}

// Do issues a request and decodes the JSON body into T when there is one.
func Do[T any](t *testing.T, c *DashboardClient, method, path string, body any, opts ...RequestOption) Response[T] {
	t.Helper()

	var reader io.Reader

	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request body: %v", err)
		}

		reader = bytes.NewReader(encoded)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dashboardTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}

	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	out := Response[T]{StatusCode: resp.StatusCode, Header: resp.Header, RawBody: string(raw)}

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		len(bytes.TrimSpace(raw)) > 0 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
		err = json.Unmarshal(raw, &out.Body)
		if err != nil {
			t.Fatalf("decode %s %s response: %v (body %q)", method, path, err, raw)
		}
	}

	return out
}

// Status issues a request and returns only the status code.
func (c *DashboardClient) Status(t *testing.T, method, path string, body any, opts ...RequestOption) int {
	t.Helper()

	return Do[json.RawMessage](t, c, method, path, body, opts...).StatusCode
}

// Text issues a request and returns the raw body, for HTML and SSE.
func (c *DashboardClient) Text(t *testing.T, method, path string, opts ...RequestOption) Response[json.RawMessage] {
	t.Helper()

	return Do[json.RawMessage](t, c, method, path, nil, opts...)
}

// APIRoot is the dashboard API prefix.
const (
	APIRoot = "/api/v1"
)

// UnblockRequest asks the dashboard to allow a domain or IP on one agent.
type UnblockRequest struct {
	Type           string `json:"type"`
	Value          string `json:"value"`
	TargetHostname string `json:"target_hostname,omitempty"`
}

// UnblockResponse is one unblock record.
type UnblockResponse struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	TargetHostname string `json:"target_hostname"`
}

// UnblockStatus is the pending/completed view of unblock requests.
type UnblockStatus struct {
	Pending   []UnblockResponse `json:"pending"`
	Completed []UnblockResponse `json:"completed"`
}

// LogEntry mirrors the dashboard's log record. The list endpoint returns a bare
// JSON array of these, not an envelope.
type LogEntry struct {
	ID              int64  `json:"id,omitempty"`
	Message         string `json:"msg"`
	Action          string `json:"action,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	HTTPS           string `json:"https,omitempty"`
	HTTPHost        string `json:"http_host,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Src             string `json:"src,omitempty"`
	Dst             string `json:"dst,omitempty"`
	Raw             string `json:"-"`
}

// APIKeyCreated is a newly minted machine key. The secret is returned once, at
// the top level; the key's metadata is nested alongside it.
type APIKeyCreated struct {
	Key    string `json:"key"`
	APIKey struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		Prefix string `json:"prefix"`
	} `json:"api_key"`
}

// Logs queries shipped logs.
func (c *DashboardClient) Logs(t *testing.T, query string, opts ...RequestOption) []LogEntry {
	t.Helper()

	return c.LogsResponse(t, query, opts...).Body
}

// LogsResponse queries shipped logs and retains the response metadata.
func (c *DashboardClient) LogsResponse(
	t *testing.T, query string, opts ...RequestOption,
) Response[[]LogEntry] {
	t.Helper()

	path := APIRoot + "/logs?limit=500"
	if query != "" {
		path += "&q=" + url.QueryEscape(query)
	}

	return Do[[]LogEntry](t, c, http.MethodGet, path, nil, opts...)
}

// WaitForLog polls until a log entry matching the query is queryable, since
// shipping is asynchronous.
func (c *DashboardClient) WaitForLog(t *testing.T, query string, timeout time.Duration) []LogEntry {
	t.Helper()

	var found []LogEntry

	Eventually(t, timeout, time.Second, func() (bool, string) {
		entries := c.Logs(t, query)
		if len(entries) > 0 {
			found = entries

			return true, ""
		}

		return false, "no log entries for " + query
	})

	return found
}
