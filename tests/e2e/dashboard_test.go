package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

// adminPassword and adminHash are an intentionally public, test-only credential.
const (
	adminPassword = "e2e-password"
	adminHash     = `$2a$10$0AQE1U75HW8UmpeVt5sWBeH73zpoPC6pTZ3ZBUHiuvInqYLmOTEx6`
)

func TestPhase14Dashboard(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("dashboard phase runs once, in the https lane (got %s)", mode)
	}

	cfg := harness.BaselineConfig(t, mode)
	cfg.AuthMode = "session"
	cfg.AdminHash = adminHash
	cfg.CookieSecure = false
	cfg.FleetEnabled = true
	cfg.CORSOrigin = "https://ui.example"

	s := harness.StartStack(t, cfg)

	anon := s.NewDashboardClient(t, "")
	session := s.NewDashboardClient(t, "")

	t.Run("PublicSurface", func(t *testing.T) { dashPublicSurface(t, anon) })
	t.Run("Unauthenticated", func(t *testing.T) { dashUnauthenticated(t, anon, s.DashboardURL) })
	t.Run("CORS", func(t *testing.T) { dashCORS(t, anon) })
	t.Run("Login", func(t *testing.T) { dashLogin(t, session) })

	var machineKey, keyID string

	t.Run("APIKeys", func(t *testing.T) { machineKey, keyID = dashAPIKeys(t, session) })
	t.Run("Ingestion", func(t *testing.T) { dashIngestion(t, session, machineKey) })
	t.Run("SSE", func(t *testing.T) { dashSSE(t, s) })
	t.Run("Fleet", func(t *testing.T) { dashFleet(t, session, machineKey) })
	t.Run("Persistence", func(t *testing.T) { dashPersistence(t, s, session, machineKey) })
	t.Run("Browser", func(t *testing.T) { dashBrowser(t, s) })
	t.Run("Revocation", func(t *testing.T) { dashRevocation(t, session, machineKey, keyID) })
	t.Run("Logout", func(t *testing.T) { dashLogout(t, session) })
}

func dashPublicSurface(t *testing.T, c *harness.DashboardClient) {
	t.Helper()

	health := c.Text(t, http.MethodGet, "/health")
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", health.StatusCode)
	}

	for _, header := range []string{"Content-Security-Policy", "X-Request-ID"} {
		if health.Header.Get(header) == "" {
			t.Errorf("health response missing %s", header)
		}
	}

	if got := health.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	login := c.Text(t, http.MethodGet, "/login.html")
	if !strings.Contains(login.RawBody, "g0efilter dashboard - login") {
		t.Fatal("login page not served")
	}

	asset := regexp.MustCompile(`/assets/[^" ]*\.js`).FindString(login.RawBody)
	if asset == "" {
		t.Fatal("login page has no JavaScript asset")
	}

	if code := c.Status(t, http.MethodGet, asset, nil); code != http.StatusOK {
		t.Errorf("login asset %s returned %d, want 200 (it must be public)", asset, code)
	}
}

func dashUnauthenticated(t *testing.T, c *harness.DashboardClient, baseURL string) {
	t.Helper()

	if code := c.LogsResponse(t, "").StatusCode; code != http.StatusUnauthorized {
		t.Errorf("unauthenticated logs returned %d, want 401", code)
	}

	page := c.Text(t, http.MethodGet, "/", harness.WithHeader("Accept", "text/html"))
	if page.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated UI returned %d, want 302", page.StatusCode)
	}

	if got := page.Header.Get("Location"); got != baseURL+"/login.html" && got != "/login.html" {
		t.Errorf("redirect Location = %q, want the login page", got)
	}
}

func dashCORS(t *testing.T, c *harness.DashboardClient) {
	t.Helper()

	resp := c.Text(t, http.MethodOptions, harness.APIRoot+"/logs",
		harness.WithHeader("Origin", "https://ui.example"),
		harness.WithHeader("Access-Control-Request-Method", "GET"))

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://ui.example" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}

	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type meBody struct {
	Username string `json:"username"`
}

func dashLogin(t *testing.T, c *harness.DashboardClient) {
	t.Helper()

	bad := c.Status(t, http.MethodPost, harness.APIRoot+"/auth/login",
		loginBody{Username: "admin", Password: "wrong"}, harness.SameOrigin())
	if bad != http.StatusUnauthorized {
		t.Errorf("bad login returned %d, want 401", bad)
	}

	ok := harness.Do[meBody](t, c, http.MethodPost, harness.APIRoot+"/auth/login",
		loginBody{Username: "admin", Password: adminPassword}, harness.SameOrigin())
	if ok.StatusCode != http.StatusOK || ok.Body.Username != "admin" {
		t.Fatalf("valid login failed: status=%d body=%s", ok.StatusCode, ok.RawBody)
	}

	me := harness.Do[meBody](t, c, http.MethodGet, harness.APIRoot+"/auth/me", nil)
	if me.Body.Username != "admin" {
		t.Fatalf("session did not authenticate: %s", me.RawBody)
	}

	if code := c.Status(t, http.MethodGet, "/", nil); code != http.StatusOK {
		t.Errorf("authenticated UI returned %d, want 200", code)
	}
}

func dashAPIKeys(t *testing.T, c *harness.DashboardClient) (string, string) {
	t.Helper()

	t.Run("cross-site mutation is rejected", func(t *testing.T) {
		code := c.Status(t, http.MethodPost, harness.APIRoot+"/apikeys",
			map[string]string{"label": "csrf-must-fail"},
			harness.WithHeader("Sec-Fetch-Site", "cross-site"))
		if code != http.StatusForbidden {
			t.Errorf("cross-site mutation returned %d, want 403", code)
		}
	})

	created := harness.Do[harness.APIKeyCreated](t, c, http.MethodPost, harness.APIRoot+"/apikeys",
		map[string]string{"label": "e2e-agent"}, harness.SameOrigin())
	if created.Body.Key == "" || created.Body.APIKey.ID == "" {
		t.Fatalf("key creation response incomplete: %s", created.RawBody)
	}

	return created.Body.Key, created.Body.APIKey.ID
}

func dashIngestion(t *testing.T, c *harness.DashboardClient, machineKey string) {
	t.Helper()

	if machineKey == "" {
		t.Skip("no machine key from the API key subtest")
	}

	// The body must be present and well-formed, or the request is rejected as
	// malformed before the content type is ever considered.
	wrongType := c.Status(t, http.MethodPost, harness.APIRoot+"/logs", json.RawMessage(`{}`),
		harness.WithAPIKey(machineKey), harness.WithHeader("Content-Type", "text/plain"))
	if wrongType != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type returned %d, want 415", wrongType)
	}

	type ingestResult struct {
		Created int `json:"created"`
	}

	ingest := harness.Do[ingestResult](t, c, http.MethodPost, harness.APIRoot+"/logs",
		map[string]string{
			"msg": "dashboard-e2e", "action": "BLOCKED",
			"hostname": "e2e-agent", "http_host": "e2e.example",
		},
		harness.WithAPIKey(machineKey))
	if ingest.Body.Created != 1 {
		t.Fatalf("log ingestion failed: status=%d body=%s", ingest.StatusCode, ingest.RawBody)
	}

	entries := c.WaitForLog(t, "dashboard-e2e", 15*time.Second)
	if len(entries) == 0 {
		t.Fatal("persisted log not queryable")
	}

	type aggregates struct {
		Events int `json:"events"`
		Totals struct {
			Blocked int `json:"blocked"`
		} `json:"totals"`
	}

	agg := harness.Do[aggregates](t, c, http.MethodGet,
		harness.APIRoot+"/aggregates?range=30d&q=e2e.example", nil)
	if agg.Body.Events != 1 || agg.Body.Totals.Blocked != 1 {
		t.Errorf("aggregate missing the event or verdict: %s", agg.RawBody)
	}
}

// dashSSE reads the event stream from the tester container: the Go client would
// block on an endpoint that never closes, and curl's --max-time handles that.
func dashSSE(t *testing.T, s *harness.Stack) {
	t.Helper()

	// curl always exits non-zero here (28, --max-time on a stream that never ends),
	// so the code is echoed into the output to keep a refusal or a 401 - which look
	// identical to a missing frame - diagnosable.
	res := s.ExecTester(t, "sh", "-c",
		"curl -sN --max-time 3 -w '\\ncurl_http=%{http_code}' -H 'X-Api-Key: "+s.Config.APIKey+"' "+
			"http://127.0.0.1:"+harness.DashboardPort+harness.APIRoot+"/events; echo \"curl_exit=$?\"")

	if !strings.Contains(res.Output, ": connected") {
		t.Errorf("SSE did not emit its connected frame: %q", res.Output)
	}
}

func dashFleet(t *testing.T, c *harness.DashboardClient, machineKey string) {
	t.Helper()

	if machineKey == "" {
		t.Skip("no machine key from the API key subtest")
	}

	type syncResult struct {
		Managed bool   `json:"managed"`
		Policy  string `json:"policy"`
	}

	syncBody := map[string]string{
		"hostname": "e2e-agent", "version": "e2e", "filter_mode": "https", "config_hash": "",
	}

	initial := harness.Do[syncResult](t, c, http.MethodPost, harness.APIRoot+"/sync",
		syncBody, harness.WithAPIKey(machineKey))
	if initial.Body.Managed {
		t.Fatalf("an unassigned instance should not be managed: %s", initial.RawBody)
	}

	type identified struct {
		ID string `json:"id"`
	}

	instances := harness.Do[[]identified](t, c, http.MethodGet, harness.APIRoot+"/fleet/instances", nil)
	if len(instances.Body) == 0 || instances.Body[0].ID == "" {
		t.Fatalf("fleet instance not recorded: %s", instances.RawBody)
	}

	group := harness.Do[identified](t, c, http.MethodPost, harness.APIRoot+"/fleet/groups",
		map[string]string{"name": "e2e-group"}, harness.SameOrigin())
	if group.Body.ID == "" {
		t.Fatalf("fleet group not created: %s", group.RawBody)
	}

	policyCode := c.Status(t, http.MethodPut,
		harness.APIRoot+"/fleet/groups/"+group.Body.ID+"/policy",
		map[string]string{"policy": "allowlist: {}", "filter_mode": "https"}, harness.SameOrigin())
	if policyCode != http.StatusOK && policyCode != http.StatusNoContent {
		t.Fatalf("group policy update returned %d", policyCode)
	}

	assignCode := c.Status(t, http.MethodPut,
		harness.APIRoot+"/fleet/instances/"+instances.Body[0].ID+"/group",
		map[string]string{"group_id": group.Body.ID}, harness.SameOrigin())
	if assignCode != http.StatusOK && assignCode != http.StatusNoContent {
		t.Fatalf("instance assignment returned %d", assignCode)
	}

	managed := harness.Do[syncResult](t, c, http.MethodPost, harness.APIRoot+"/sync",
		syncBody, harness.WithAPIKey(machineKey))
	if !managed.Body.Managed || managed.Body.Policy != "allowlist: {}" {
		t.Errorf("desired state not resolved after assignment: %s", managed.RawBody)
	}
}

func dashPersistence(t *testing.T, s *harness.Stack, c *harness.DashboardClient, machineKey string) {
	t.Helper()

	if machineKey == "" {
		t.Skip("no machine key from the API key subtest")
	}

	s.RestartDashboard(t)

	me := harness.Do[meBody](t, c, http.MethodGet, harness.APIRoot+"/auth/me", nil)
	if me.Body.Username != "admin" {
		t.Errorf("session did not survive the restart: %s", me.RawBody)
	}

	code := c.Status(t, http.MethodPost, harness.APIRoot+"/logs",
		map[string]string{"msg": "after-restart", "action": "ALLOWED"},
		harness.WithAPIKey(machineKey))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Errorf("API key did not survive the restart: status=%d", code)
	}

	if entries := c.Logs(t, "dashboard-e2e"); len(entries) == 0 {
		t.Error("log did not survive the restart")
	}

	groups := c.Text(t, http.MethodGet, harness.APIRoot+"/fleet/groups")
	if !strings.Contains(groups.RawBody, "e2e-group") {
		t.Errorf("fleet group did not survive the restart: %s", groups.RawBody)
	}
}

// dashBrowser runs the Playwright suite against this stack. Browser behavior is
// not something Go HTTP requests can stand in for, so it stays as Playwright and
// the Go test just owns the environment.
func dashBrowser(t *testing.T, s *harness.Stack) {
	t.Helper()

	if harness.Env("E2E_BROWSER", "0") != "1" {
		t.Skip("set E2E_BROWSER=1 to run the Chromium smoke test")
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	outputDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pnpm", "test:e2e")
	cmd.Dir = filepath.Join(repoRoot, "dashboard", "ui")

	cmd.Env = append(os.Environ(),
		"PLAYWRIGHT_OUTPUT_DIR="+outputDir,
		"DASHBOARD_E2E_BASE_URL="+s.DashboardURL,
		"DASHBOARD_E2E_API_KEY="+s.Config.APIKey,
		"DASHBOARD_E2E_ADMIN_PASSWORD="+adminPassword,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		t.Fatalf("Playwright failed: %v", err)
	}
}

func dashRevocation(t *testing.T, c *harness.DashboardClient, machineKey, keyID string) {
	t.Helper()

	if machineKey == "" || keyID == "" {
		t.Skip("no machine key from the API key subtest")
	}

	code := c.Status(t, http.MethodDelete, harness.APIRoot+"/apikeys/"+keyID, nil, harness.SameOrigin())
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("key revocation returned %d", code)
	}

	after := c.Status(t, http.MethodPost, harness.APIRoot+"/logs", json.RawMessage(`{}`),
		harness.WithAPIKey(machineKey))
	if after != http.StatusUnauthorized {
		t.Errorf("revoked API key returned %d, want 401", after)
	}
}

func dashLogout(t *testing.T, c *harness.DashboardClient) {
	t.Helper()

	code := c.Status(t, http.MethodPost, harness.APIRoot+"/auth/logout", nil, harness.SameOrigin())
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("logout returned %d", code)
	}

	if after := c.LogsResponse(t, "").StatusCode; after != http.StatusUnauthorized {
		t.Errorf("logged-out session returned %d, want 401", after)
	}
}
