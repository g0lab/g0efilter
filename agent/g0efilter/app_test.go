//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestGetenvDefault(t *testing.T) {
	tests := []struct {
		name string
		key  string
		def  string
		set  bool
		val  string
		want string
	}{
		{name: "unset", key: "TEST_UNSET_VAR", def: "default", want: "default"},
		{name: "set", key: "TEST_SET_VAR", def: "default", set: true, val: "env", want: "env"},
		{name: "empty uses default", key: "TEST_EMPTY_VAR", def: "default", set: true, val: "", want: "default"},
		{name: "whitespace uses default", key: "TEST_WS_VAR", def: "default", set: true, val: "   ", want: "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(tt.key, tt.val)
			}

			got := getenvDefault(tt.key, tt.def)
			if got != tt.want {
				t.Fatalf("getenvDefault(%q, %q) = %q, want %q", tt.key, tt.def, got, tt.want)
			}
		})
	}
}

func TestParseDurationDefault(t *testing.T) {
	t.Parallel()

	fallback := 42 * time.Second

	tests := []struct {
		name string
		in   string
		want time.Duration
	}{
		{name: "valid", in: "5s", want: 5 * time.Second},
		{name: "valid minutes", in: "2m", want: 2 * time.Minute},
		{name: "invalid", in: "nope", want: fallback},
		{name: "empty", in: "", want: fallback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parseDurationDefault(tt.in, fallback)
			if got != tt.want {
				t.Fatalf("parseDurationDefault(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("HOSTNAME", "")

	want := config{
		policyPath:          "/app/policy.yaml",
		httpPort:            "65080",
		httpsPort:           "65443",
		dnsPort:             "65053",
		logLevel:            "INFO",
		logFile:             "",
		hostname:            "",
		mode:                "https",
		defaultAction:       "deny",
		learningMode:        false,
		learner:             nil,
		dnsHardening:        true,
		enableRemoteUnblock: false,
		dashboardHost:       "",
		dashboardAPIKey:     "",
		unblockPollInterval: 10 * time.Second,
		notificationHost:    "",
		notificationKey:     "",
	}

	got := loadConfig()
	if got != want {
		t.Fatalf("loadConfig() defaults:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestLoadConfigCustomValues(t *testing.T) {
	t.Setenv("POLICY_PATH", "/custom/policy.yaml")
	t.Setenv("HTTP_PORT", "9080")
	t.Setenv("HTTPS_PORT", "9443")
	t.Setenv("DNS_PORT", "5353")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("LOG_FILE", "/var/log/g0efilter.log")
	t.Setenv("HOSTNAME", "test-host")
	t.Setenv("FILTER_MODE", "DNS")
	t.Setenv("DEFAULT_ACTION", "ALLOW")
	t.Setenv("LEARNING_MODE", "true")
	t.Setenv("DNS_HARDENING", "false")
	t.Setenv("ENABLE_REMOTE_UNBLOCK", "true")
	t.Setenv("DASHBOARD_HOST", "dash.example.com")
	t.Setenv("DASHBOARD_API_KEY", "secret123")
	t.Setenv("UNBLOCK_POLL_INTERVAL", "30s")
	t.Setenv("NOTIFICATION_HOST", "notify.example.com")
	t.Setenv("NOTIFICATION_KEY", "nkey456")

	want := config{
		policyPath:          "/custom/policy.yaml",
		httpPort:            "9080",
		httpsPort:           "9443",
		dnsPort:             "5353",
		logLevel:            "DEBUG",
		logFile:             "/var/log/g0efilter.log",
		hostname:            "test-host",
		mode:                "dns",
		defaultAction:       "allow",
		learningMode:        true,
		learner:             nil,
		dnsHardening:        false,
		enableRemoteUnblock: true,
		dashboardHost:       "dash.example.com",
		dashboardAPIKey:     "secret123",
		unblockPollInterval: 30 * time.Second,
		notificationHost:    "notify.example.com",
		notificationKey:     "nkey456",
	}

	got := loadConfig()
	if got != want {
		t.Fatalf("loadConfig() custom:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestShouldWatchPolicy(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct
	if !shouldWatchPolicy(config{learningMode: false}) {
		t.Error("policy watcher should run when not in learning mode")
	}

	//nolint:exhaustruct
	if shouldWatchPolicy(config{learningMode: true}) {
		t.Error("policy watcher should be disabled in learning mode (reloads have no effect)")
	}
}

func writeTestPolicyFile(t *testing.T, path string) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte("allowlist:\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolvePolicyPath(t *testing.T) {
	lg := slog.New(slog.DiscardHandler)

	tests := []struct {
		name         string
		withDefault  bool
		withFallback bool
		explicitEnv  bool
		wantFallback bool
	}{
		{"explicit POLICY_PATH wins even when missing", false, true, true, false},
		{"default kept when present", true, false, false, false},
		{"fallback used when default missing", false, true, false, true},
		{"default wins when both exist", true, true, false, false},
		{"default kept when neither exists", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			defaultPath := filepath.Join(dir, "policy.yaml")
			fallbackPath := filepath.Join(dir, "policy", "policy.yaml")

			if tt.withDefault {
				writeTestPolicyFile(t, defaultPath)
			}

			if tt.withFallback {
				writeTestPolicyFile(t, fallbackPath)
			}

			if tt.explicitEnv {
				t.Setenv("POLICY_PATH", defaultPath)
			} else {
				t.Setenv("POLICY_PATH", "")
			}

			want := defaultPath
			if tt.wantFallback {
				want = fallbackPath
			}

			got := resolvePolicyPath(config{policyPath: defaultPath}, fallbackPath, lg) //nolint:exhaustruct
			if got.policyPath != want {
				t.Errorf("policyPath = %q, want %q", got.policyPath, want)
			}
		})
	}
}

func TestLoadConfigFilterModeTrimsAndLowercases(t *testing.T) {
	t.Setenv("FILTER_MODE", "  HtTpS  ")
	t.Setenv("HOSTNAME", "")

	got := loadConfig()
	if got.mode != "https" {
		t.Fatalf("loadConfig().mode = %q, want %q", got.mode, "https")
	}
}

func TestNormalizeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   config
		want string
	}{
		{name: "dns ok", in: config{mode: "dns"}, want: "dns"},
		{name: "https ok", in: config{mode: "https"}, want: "https"},
		{name: "invalid defaults to https", in: config{mode: "nope"}, want: "https"},
		{name: "empty defaults to https", in: config{mode: ""}, want: "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeMode(tt.in, discardLogger())
			if got.mode != tt.want {
				t.Fatalf("normalizeMode().mode = %q, want %q", got.mode, tt.want)
			}
		})
	}
}

func TestValidatePortsHTTPSConflict(t *testing.T) {
	t.Parallel()

	cfg := config{
		mode:      "https",
		httpPort:  "8080",
		httpsPort: "8080",
	}

	err := validatePorts(cfg, discardLogger())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, errPortConflict) {
		t.Fatalf("expected errors.Is(..., %v) true, got %v", errPortConflict, err)
	}
}

func TestValidatePortsOK(t *testing.T) {
	t.Parallel()

	tests := []config{
		{mode: "https", httpPort: "8080", httpsPort: "8443"},
		{mode: "dns", dnsPort: "53", httpPort: "53", httpsPort: "53"},
	}

	for _, cfg := range tests {
		t.Run(cfg.mode, func(t *testing.T) {
			t.Parallel()

			err := validatePorts(cfg, discardLogger())
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestFileSHA256HexEmptyOrWhitespaceReturnsError(t *testing.T) {
	t.Parallel()

	paths := []string{"", "   ", "\n\t  "}
	for _, p := range paths {
		t.Run(strings.ReplaceAll(p, "\n", "\\n"), func(t *testing.T) {
			t.Parallel()

			_, err := fileSHA256Hex(p)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", p)
			}
		})
	}
}

func TestFileSHA256HexMatchesSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	content := []byte("hello\n")

	err := os.WriteFile(p, content, 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := fileSHA256Hex(" \t" + p + "\n")
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestFileSHA256HexChangesWhenContentChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(p, []byte("a\n"), 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h1, err := fileSHA256Hex(p)
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	err = os.WriteFile(p, []byte("b\n"), 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h2, err := fileSHA256Hex(p)
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	if h1 == h2 {
		t.Fatalf("expected hash to change, but both were %q", h1)
	}
}

func TestSendLatestKeepsMostRecent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ch := make(chan policyUpdate, 1)

	//nolint:exhaustruct
	upd1 := policyUpdate{hash: "h1", pol: &policy.Policy{AllowDomains: []string{"a"}, AllowIPs: []string{"1.1.1.1"}}}
	//nolint:exhaustruct
	upd2 := policyUpdate{hash: "h2", pol: &policy.Policy{AllowDomains: []string{"b"}, AllowIPs: []string{"2.2.2.2"}}}

	sendLatest(ctx, ch, upd1)
	sendLatest(ctx, ch, upd2)

	got := <-ch
	if got.hash != "h2" {
		t.Fatalf("expected latest hash %q, got %q", "h2", got.hash)
	}
}

func TestHandleVersionFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"--version", []string{"app", "--version"}, true},
		{"version", []string{"app", "version"}, true},
		{"-V", []string{"app", "-V"}, true},
		{"-v", []string{"app", "-v"}, true},
		{"no args", []string{"app"}, false},
		{"empty", []string{}, false},
		{"other flag", []string{"app", "--help"}, false},
		{"version not first", []string{"app", "run", "--version"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := HandleVersionFlag(tt.args, "1.0.0", "2025-01-01", "abc123")
			if got != tt.want {
				t.Errorf("HandleVersionFlag(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsInodeUnlinkedNonexistentPath(t *testing.T) {
	t.Parallel()

	err := isInodeUnlinked("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

func TestIsInodeUnlinkedLinkedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(p, []byte("test"), 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	err = isInodeUnlinked(p)
	if !errors.Is(err, errInodeLinked) {
		t.Fatalf("expected errInodeLinked for existing file, got %v", err)
	}
}

func TestIsInodeUnlinkedUnlinkedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	f, err := os.CreateTemp(dir, "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	defer func() {
		closeErr := f.Close()
		if closeErr != nil {
			t.Errorf("close temp file: %v", closeErr)
		}
	}()

	p := f.Name()

	// Remove the directory entry - lstat will fail (ENOENT), not return nlink=0
	err = os.Remove(p)
	if err != nil {
		t.Fatalf("remove temp file: %v", err)
	}

	// Once removed, lstat fails (non-nil error, not errInodeLinked)
	err = isInodeUnlinked(p)
	if err == nil {
		t.Fatal("expected error for removed path, got nil")
	}

	if errors.Is(err, errInodeLinked) {
		t.Fatalf("expected lstat error, not errInodeLinked; got %v", err)
	}
}

func TestFetchPendingUnblocksSuccess(t *testing.T) {
	t.Parallel()

	want := []unblockRequest{
		{ID: "1", Type: "domain", Value: "example.com"},
		{ID: "2", Type: "ip", Value: "1.2.3.4"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/unblocks" {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(unblockResponse{Pending: want})
	}))
	defer srv.Close()

	cfg := config{dashboardHost: srv.URL}
	client := &http.Client{Timeout: 5 * time.Second}

	got, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err != nil {
		t.Fatalf("fetchPendingUnblocks: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("got %d unblocks, want %d", len(got), len(want))
	}

	for i, u := range got {
		if u.ID != want[i].ID || u.Type != want[i].Type || u.Value != want[i].Value {
			t.Errorf("unblock[%d] = %+v, want %+v", i, u, want[i])
		}
	}
}

func TestFetchPendingUnblocksEmptyResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(unblockResponse{Pending: nil})
	}))
	defer srv.Close()

	cfg := config{dashboardHost: srv.URL}
	client := &http.Client{Timeout: 5 * time.Second}

	got, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err != nil {
		t.Fatalf("fetchPendingUnblocks: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestFetchPendingUnblocksNonOKStatus(t *testing.T) {
	t.Parallel()

	tests := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	}

	for _, code := range tests {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()

			cfg := config{dashboardHost: srv.URL}
			client := &http.Client{Timeout: 5 * time.Second}

			_, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
			if !errors.Is(err, errUnexpectedHTTPStatus) {
				t.Fatalf("expected errUnexpectedHTTPStatus for %d, got %v", code, err)
			}
		})
	}
}

func TestFetchPendingUnblocksMalformedJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	cfg := config{dashboardHost: srv.URL}
	client := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestFetchPendingUnblocksAPIKey(t *testing.T) {
	t.Parallel()

	const wantKey = "secret-api-key"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != wantKey {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		_ = json.NewEncoder(w).Encode(unblockResponse{})
	}))
	defer srv.Close()

	cfg := config{dashboardHost: srv.URL, dashboardAPIKey: wantKey}
	client := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err != nil {
		t.Fatalf("fetchPendingUnblocks with valid API key: %v", err)
	}
}

func TestFetchPendingUnblocksHostnameQueryParam(t *testing.T) {
	t.Parallel()

	const wantHostname = "node-42"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hostname") != wantHostname {
			http.Error(w, "missing hostname", http.StatusBadRequest)

			return
		}

		_ = json.NewEncoder(w).Encode(unblockResponse{})
	}))
	defer srv.Close()

	cfg := config{dashboardHost: srv.URL, hostname: wantHostname}
	client := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err != nil {
		t.Fatalf("fetchPendingUnblocks with hostname: %v", err)
	}
}

func TestFetchPendingUnblocksNetworkError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close() // immediately close so the port is refused

	cfg := config{dashboardHost: srv.URL}
	client := &http.Client{Timeout: 500 * time.Millisecond}

	_, err := fetchPendingUnblocks(context.Background(), client, srv.URL, cfg, discardLogger())
	if err == nil {
		t.Fatal("expected error for refused connection, got nil")
	}
}

func TestFetchPendingUnblocksContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)

		_ = json.NewEncoder(w).Encode(unblockResponse{})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := config{dashboardHost: srv.URL}
	client := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchPendingUnblocks(ctx, client, srv.URL, cfg, discardLogger())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
