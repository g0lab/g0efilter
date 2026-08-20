package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	agentService      = "g0efilter"
	dashboardService  = "g0efilter-dashboard"
	testerService     = "tester"
	notifySinkService = "notify-sink"

	startupTimeout  = 3 * time.Minute
	shutdownTimeout = 45 * time.Second
)

// NotifySinkURLs address the sink by service name, so reaching it needs a DNS lookup.
// Both land on /cgi-bin/message, the only path busybox httpd runs as CGI.
const NotifySinkURLs = "gotify://notify-sink:8080/cgi-bin/" + NotifySinkGotifyToken + "?disabletls=yes " +
	"ntfy://notify-sink:8080/cgi-bin/message?scheme=http"

// NotifySinkGotifyToken passes shoutrrr's Gotify format check; the sink records it.
const NotifySinkGotifyToken = "Aaa.bbb.ccc.ddd" //nolint:gosec // A test fixture, not a credential.

const notifySinkLog = "/tmp/received.txt"

// DashboardPort is the in-container port the dashboard listens on. Exported so
// tests that exec curl inside a container do not restate it.
const DashboardPort = "8081"

// Stack is a running three-container g0efilter deployment.
type Stack struct {
	Config  StackConfig
	Compose compose.ComposeStack

	Agent      *testcontainers.DockerContainer
	Dashboard  *testcontainers.DockerContainer
	Tester     *testcontainers.DockerContainer
	NotifySink *testcontainers.DockerContainer

	DashboardURL string
	PolicyFile   string

	shared        bool
	ownsPolicyDir bool

	// mu serializes tests that share this stack. Two tests writing different
	// policies to one agent would silently invalidate each other, so sharing and
	// parallelism are reconciled by handing the stack to one test at a time.
	mu sync.Mutex
	// owner is the test currently holding mu, so its subtests can re-enter.
	owner   string
	ownerMu sync.Mutex
}

//nolint:gochecknoglobals // one cache per test binary, torn down by ShutdownShared
var (
	sharedMu     sync.Mutex
	sharedStacks = map[string]*Stack{}
)

// Shared reuses an interchangeable stack until ShutdownShared runs.
// Use StartStack when a test changes stack-level state.
func Shared(t *testing.T, cfg StackConfig) *Stack {
	t.Helper()

	key := cfg.fingerprint()

	sharedMu.Lock()

	s, ok := sharedStacks[key]
	if ok {
		t.Logf("reusing shared stack (mode=%s)", cfg.Mode)
	} else {
		s = start(t, cfg, true)
		sharedStacks[key] = s
	}

	sharedMu.Unlock()

	// acquire blocks on the stack's own lock, so it must not hold sharedMu.
	s.acquire(t)

	return s
}

// ShutdownShared tears down every cached stack. Call it from TestMain after
// m.Run; shared stacks deliberately outlive the tests that started them.
func ShutdownShared() {
	sharedMu.Lock()
	defer sharedMu.Unlock()

	for key, s := range sharedStacks {
		s.down()
		delete(sharedStacks, key)
	}
}

// StartStack starts a stack dedicated to one test and tears it down afterwards.
func StartStack(t *testing.T, cfg StackConfig) *Stack {
	t.Helper()

	s := start(t, cfg, false)

	t.Cleanup(func() {
		if t.Failed() {
			s.DumpDiagnostics(t)
		}

		s.down()
	})

	return s
}

func start(t *testing.T, cfg StackConfig, shared bool) *Stack {
	t.Helper()

	ownsPolicyDir := cfg.PolicyDir == ""
	if cfg.PolicyDir == "" {
		dir, err := newPolicyDir()
		if err != nil {
			t.Fatalf("policy dir: %v", err)
		}

		cfg.PolicyDir = dir
	}

	// The agent refuses to start without a policy file, so seed one before Up.
	policyFile := filepath.Join(cfg.PolicyDir, "policy.yaml")

	err := writePolicyFile(policyFile, BaselinePolicy)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	stack, err := compose.NewDockerComposeWith(
		compose.StackIdentifier("g0efilter-e2e-"+randomID()),
		compose.WithStackFiles(composeFile(t)),
	)
	if err != nil {
		t.Fatalf("create compose stack: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	// Wait on the tester: it shares the agent's network namespace, so a health
	// check from there proves the namespace wiring and the dashboard at once.
	err = stack.
		WithEnv(cfg.composeEnv()).
		WaitForService(testerService,
			wait.ForExec([]string{"curl", "-sf", "http://127.0.0.1:" + DashboardPort + "/health"}).
				WithStartupTimeout(90*time.Second).
				WithPollInterval(time.Second)).
		Up(ctx, compose.Wait(true), compose.RemoveOrphans(true))
	if err != nil {
		t.Fatalf("start compose stack (mode=%s): %v", cfg.Mode, err)
	}

	s := &Stack{
		Config:        cfg,
		Compose:       stack,
		PolicyFile:    policyFile,
		shared:        shared,
		ownsPolicyDir: ownsPolicyDir,
	}

	s.Agent = serviceContainer(ctx, t, stack, agentService)
	s.Dashboard = serviceContainer(ctx, t, stack, dashboardService)
	s.Tester = serviceContainer(ctx, t, stack, testerService)
	s.NotifySink = serviceContainer(ctx, t, stack, notifySinkService)
	s.DashboardURL = dashboardURL(ctx, t, s.Agent)

	return s
}

func (c StackConfig) composeEnv() map[string]string {
	return map[string]string{
		"E2E_POLICY_DIR":                 c.PolicyDir,
		"FILTER_MODE":                    string(c.Mode),
		"DEFAULT_ACTION":                 c.DefaultAction,
		"LEARNING_MODE":                  strconv.FormatBool(c.LearningMode),
		"ENFORCE":                        c.Enforce,
		"API_KEY":                        c.APIKey,
		"DASHBOARD_AUTH_MODE":            c.AuthMode,
		"DASHBOARD_ADMIN_PASSWORD_HASH":  c.AdminHash,
		"DASHBOARD_COOKIE_SECURE":        strconv.FormatBool(c.CookieSecure),
		"DASHBOARD_EPHEMERAL":            strconv.FormatBool(c.Ephemeral),
		"DASHBOARD_FLEET_ENABLED":        strconv.FormatBool(c.FleetEnabled),
		"DASHBOARD_CORS_ALLOWED_ORIGINS": c.CORSOrigin,
		"NOTIFICATION_URLS":              c.NotifyURLs,
		"G0EFILTER_IMAGE":                c.AgentImage,
		"G0EFILTER_DASHBOARD_IMAGE":      c.DashboardImage,
		"E2E_TESTER_IMAGE":               c.TesterImage,
	}
}

// Shared reports whether the stack is reused.
func (s *Stack) Shared() bool {
	return s.shared
}

func serviceContainer(
	ctx context.Context, t *testing.T, stack compose.ComposeStack, name string,
) *testcontainers.DockerContainer {
	t.Helper()

	c, err := stack.ServiceContainer(ctx, name)
	if err != nil {
		t.Fatalf("service container %q: %v", name, err)
	}

	return c
}

// dashboardURL resolves the host-side address of the dashboard. The port is
// published by the agent, because the dashboard runs in the agent's network
// namespace and so cannot publish ports of its own.
func dashboardURL(ctx context.Context, t *testing.T, agent *testcontainers.DockerContainer) string {
	t.Helper()

	host, err := agent.Host(ctx)
	if err != nil {
		t.Fatalf("agent host: %v", err)
	}

	port, err := agent.MappedPort(ctx, DashboardPort+"/tcp")
	if err != nil {
		t.Fatalf("mapped dashboard port: %v", err)
	}

	return "http://" + net.JoinHostPort(host, port.Port())
}

func composeFile(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the harness source directory")
	}

	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "compose.test.yaml")

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve compose file: %v", err)
	}

	return abs
}

func randomID() string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)

	return hex.EncodeToString(buf)
}

func writePolicyFile(path string, policy string) error {
	tmp := path + ".tmp"

	err := os.WriteFile(tmp, []byte(policy), 0o666) //nolint:gosec // agent rewrites it as the container UID
	if err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	err = os.Chmod(tmp, 0o666) //nolint:gosec // override the host umask for the container UID
	if err != nil {
		return fmt.Errorf("chmod policy: %w", err)
	}

	err = os.Rename(tmp, path)
	if err != nil {
		return fmt.Errorf("replace policy: %w", err)
	}

	return nil
}

// RestartDashboard restarts the dashboard and waits for it to serve.
func (s *Stack) RestartDashboard(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := s.Dashboard.Stop(ctx, nil)
	if err != nil {
		t.Fatalf("stop dashboard: %v", err)
	}

	err = s.Dashboard.Start(ctx)
	if err != nil {
		t.Fatalf("start dashboard: %v", err)
	}

	Eventually(t, 60*time.Second, time.Second, func() (bool, string) {
		res := Exec(ctx, s.Tester, "curl", "-sf", "http://127.0.0.1:"+DashboardPort+"/health")

		return res.ExitCode == 0, "dashboard has not recovered after restart"
	})
}

// NotificationsReceived returns the sink's CGI log, or "" before the first delivery.
func (s *Stack) NotificationsReceived(t *testing.T) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := Exec(ctx, s.NotifySink, "cat", notifySinkLog)
	if res.ExitCode != 0 {
		return ""
	}

	return res.Output
}

// acquire gives t exclusive use of the stack until it finishes. Subtests of the
// current owner re-enter without blocking; anything else waits its turn.
func (s *Stack) acquire(t *testing.T) {
	t.Helper()

	s.ownerMu.Lock()
	if ownsTest(s.owner, t.Name()) {
		s.ownerMu.Unlock()

		return
	}
	s.ownerMu.Unlock()

	s.mu.Lock()

	s.ownerMu.Lock()
	s.owner = t.Name()
	s.ownerMu.Unlock()

	t.Cleanup(func() {
		if t.Failed() {
			s.DumpDiagnostics(t)
		}

		s.ownerMu.Lock()
		s.owner = ""
		s.ownerMu.Unlock()
		s.mu.Unlock()
	})
}

func ownsTest(owner, name string) bool {
	return owner != "" && (name == owner || strings.HasPrefix(name, owner+"/"))
}

func (s *Stack) down() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	_ = s.Compose.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
	s.removePolicyDir()
}

func (s *Stack) removePolicyDir() {
	if s.ownsPolicyDir {
		_ = os.RemoveAll(s.Config.PolicyDir)
	}
}
