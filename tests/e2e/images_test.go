package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

func TestPhase15EntrypointCaps(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("entrypoint-caps phase runs once, in the https lane (got %s)", mode)
	}

	image := harness.Env("G0EFILTER_IMAGE", "g0efilter:test")

	fullCaps := []string{"NET_ADMIN", "SETUID", "SETGID", "CHOWN"}

	tests := []struct {
		name      string
		caps      []string
		env       map[string]string
		user      string
		wantText  string
		wantFails bool
	}{
		{
			name:     "full caps drop to nobody and keep net_admin",
			caps:     fullCaps,
			wantText: "running as uid:gid 65534:65534 (retained cap: net_admin)",
		},
		{
			name: "missing SETUID/SETGID falls back to root with a warning",
			caps: []string{"NET_ADMIN", "CHOWN"},
			wantText: "running as root (weakens container isolation; " +
				"set ALLOW_ROOT_FALLBACK=false to fail closed)",
		},
		{
			name:      "ALLOW_ROOT_FALLBACK=false fails closed",
			caps:      []string{"NET_ADMIN", "CHOWN"},
			env:       map[string]string{"ALLOW_ROOT_FALLBACK": "false"},
			wantText:  "ALLOW_ROOT_FALLBACK=false, refusing to run as root",
			wantFails: true,
		},
		{
			// Docker's --cap-add does not make a capability effective after switching
			// to a non-root --user, so the entrypoint must abort rather than run
			// unprotected.
			name:      "pre-set non-root user without effective NET_ADMIN fails closed",
			caps:      []string{"NET_ADMIN"},
			user:      "65534:65534",
			wantText:  "CAP_NET_ADMIN missing",
			wantFails: true,
		},
		{
			name:      "non-numeric PUID is rejected before startup",
			caps:      fullCaps,
			env:       map[string]string{"PUID": "nobody"},
			wantText:  "PUID must be a non-negative integer",
			wantFails: true,
		},
		{
			name:      "missing NET_ADMIN aborts startup",
			caps:      []string{"SETUID", "SETGID", "CHOWN"},
			wantText:  "ERROR: CAP_NET_ADMIN missing",
			wantFails: true,
		},
		{
			name:     "PUID=0 stays root explicitly",
			caps:     []string{"NET_ADMIN"},
			env:      map[string]string{"PUID": "0"},
			wantText: "running as uid:gid 0:0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//nolint:exhaustruct // Binds are not needed here
			res := harness.RunOneShot(t, harness.OneShot{
				Image:  image,
				Cmd:    []string{"healthcheck"},
				Env:    tc.env,
				CapAdd: tc.caps,
				User:   tc.user,
			})

			if !res.Contains(tc.wantText) {
				t.Errorf("expected %q in output:\n%s", tc.wantText, res.Output)
			}

			if tc.wantFails && res.Succeeded() {
				t.Errorf("expected a non-zero exit, got 0:\n%s", res.Output)
			}
		})
	}
}

var (
	bcryptHash        = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$`)
	generatedPassword = regexp.MustCompile(`^[A-Za-z0-9_-]{27,}$`)
	generatedAPIKey   = regexp.MustCompile(`^g0e_[0-9a-f]{64}$`)
)

func TestPhase16DashboardCLI(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("dashboard CLI phase runs once, in the https lane (got %s)", mode)
	}

	image := harness.Env("G0EFILTER_DASHBOARD_IMAGE", "g0efilter-dashboard:test")

	t.Run("HashPassword", func(t *testing.T) { cliHashPassword(t, image) })
	t.Run("FirstStart", func(t *testing.T) { cliFirstStart(t, image) })
	t.Run("Ephemeral", func(t *testing.T) { cliEphemeral(t, image) })
	t.Run("Errors", func(t *testing.T) { cliErrors(t, image) })
}

func cliHashPassword(t *testing.T, image string) {
	t.Helper()

	const password = "container-hash-password"

	//nolint:exhaustruct // only Cmd is needed
	hashed := harness.RunOneShotStdin(t, harness.OneShot{
		Image: image,
		Cmd:   []string{"hash-password"},
	}, password+"\n")

	hash := lastLine(hashed.Output)
	if !bcryptHash.MatchString(hash) {
		t.Fatalf("hash-password returned an invalid bcrypt hash: %q (output %q)", hash, hashed.Output)
	}

	dataDir := worldWritableDir(t)

	//nolint:exhaustruct // Env defaults are supplied by the helper
	d := harness.StartDashboardContainer(t, harness.DashboardContainerSpec{
		Image:     image,
		DataBind:  dataDir,
		AdminHash: hash,
	})

	if code := loginStatus(t, d, password); code != http.StatusOK {
		t.Errorf("hash-password output did not configure login: status=%d", code)
	}

	key := d.LogField(t, "dashboard.bootstrap_api_key", "key")
	if !generatedAPIKey.MatchString(key) {
		t.Fatalf("fresh dashboard did not log a generated API key: %q", key)
	}

	if code := ingestStatus(t, d, key); code != http.StatusCreated {
		t.Errorf("generated API key did not authenticate ingestion: status=%d", code)
	}

	d.Restart(t)

	if n := d.CountLogEvent(t, "dashboard.api_key_generated"); n != 1 {
		t.Errorf("api_key_generated emitted %d times across a restart, want 1", n)
	}

	if code := ingestStatus(t, d, key); code != http.StatusCreated {
		t.Errorf("generated API key did not survive the restart: status=%d", code)
	}
}

func cliFirstStart(t *testing.T, image string) {
	t.Helper()

	dataDir := worldWritableDir(t)

	//nolint:exhaustruct // no admin hash: first start generates one
	d := harness.StartDashboardContainer(t, harness.DashboardContainerSpec{
		Image:    image,
		DataBind: dataDir,
	})

	password := d.LogField(t, "dashboard.bootstrap_admin", "password")
	key := d.LogField(t, "dashboard.bootstrap_api_key", "key")

	if !generatedPassword.MatchString(password) {
		t.Fatalf("no generated admin password in the first-start output: %q", password)
	}

	if !generatedAPIKey.MatchString(key) {
		t.Fatalf("no generated API key in the first-start output: %q", key)
	}

	if code := loginStatus(t, d, password); code != http.StatusOK {
		t.Fatalf("generated admin password did not authenticate: status=%d", code)
	}

	if code := ingestStatus(t, d, key); code != http.StatusCreated {
		t.Fatalf("generated API key did not authenticate: status=%d", code)
	}

	d.Restart(t)

	for _, event := range []string{"dashboard.admin_password_generated", "dashboard.api_key_generated"} {
		if n := d.CountLogEvent(t, event); n != 1 {
			t.Errorf("%s emitted %d times, want 1", event, n)
		}
	}

	t.Run("reset-password rotates the credential", func(t *testing.T) {
		// The CLI needs exclusive access to the database file.
		stopContainer(t, d)

		//nolint:exhaustruct // only Cmd and Binds are needed
		reset := harness.RunOneShot(t, harness.OneShot{
			Image: image,
			Cmd:   []string{"reset-password"},
			Binds: []string{dataDir + ":/app/data"},
		})

		newPassword := lastLine(reset.Output)
		if !generatedPassword.MatchString(newPassword) {
			t.Fatalf("reset-password did not print a generated password: %q", reset.Output)
		}

		//nolint:exhaustruct // no admin hash: the database now holds the credential
		restarted := harness.StartDashboardContainer(t, harness.DashboardContainerSpec{
			Image:    image,
			DataBind: dataDir,
		})

		if code := loginStatus(t, restarted, password); code != http.StatusUnauthorized {
			t.Errorf("old admin password survived the reset: status=%d", code)
		}

		if code := loginStatus(t, restarted, newPassword); code != http.StatusOK {
			t.Errorf("reset admin password did not authenticate: status=%d", code)
		}

		t.Run("revoking the last key leaves the dashboard recoverable", func(t *testing.T) {
			session := restarted.NewClient(t, "")

			code := session.Status(t, http.MethodPost, harness.APIRoot+"/auth/login",
				loginBody{Username: "admin", Password: newPassword}, harness.SameOrigin())
			if code != http.StatusOK {
				t.Fatalf("session login failed: status=%d", code)
			}

			type identified struct {
				ID string `json:"id"`
			}

			// The assertion below is about revoking the *last* key, so the listing has
			// to hold exactly the bootstrap key - otherwise a different key is deleted.
			keys := harness.Do[[]identified](t, session, http.MethodGet, harness.APIRoot+"/apikeys", nil)
			if len(keys.Body) != 1 || keys.Body[0].ID == "" {
				t.Fatalf("want exactly the bootstrap API key, got %d: %s", len(keys.Body), keys.RawBody)
			}

			del := session.Status(t, http.MethodDelete,
				harness.APIRoot+"/apikeys/"+keys.Body[0].ID, nil, harness.SameOrigin())
			if del != http.StatusOK && del != http.StatusNoContent {
				t.Fatalf("could not revoke the last active API key: status=%d", del)
			}

			if code := ingestStatus(t, restarted, key); code != http.StatusUnauthorized {
				t.Errorf("revoked API key still authenticated: status=%d", code)
			}

			restarted.Restart(t)

			if n := restarted.CountLogEvent(t, "dashboard.no_active_api_keys"); n != 1 {
				t.Errorf("no_active_api_keys emitted %d times after restart, want 1", n)
			}

			if code := loginStatus(t, restarted, newPassword); code != http.StatusOK {
				t.Errorf("login unavailable with no active API keys: status=%d", code)
			}

			// The UI must be able to mint a replacement.
			recovery := restarted.NewClient(t, "")

			code = recovery.Status(t, http.MethodPost, harness.APIRoot+"/auth/login",
				loginBody{Username: "admin", Password: newPassword}, harness.SameOrigin())
			if code != http.StatusOK {
				t.Fatalf("recovery login failed: status=%d", code)
			}

			created := harness.Do[harness.APIKeyCreated](t, recovery, http.MethodPost,
				harness.APIRoot+"/apikeys", map[string]string{"label": "ui-recovery"}, harness.SameOrigin())
			if !generatedAPIKey.MatchString(created.Body.Key) {
				t.Fatalf("UI did not return a replacement API key: %s", created.RawBody)
			}

			if code := ingestStatus(t, restarted, created.Body.Key); code != http.StatusCreated {
				t.Errorf("replacement API key did not authenticate: status=%d", code)
			}
		})
	})
}

func cliEphemeral(t *testing.T, image string) {
	t.Helper()

	//nolint:exhaustruct // no DataBind means ephemeral
	d := harness.StartDashboardContainer(t, harness.DashboardContainerSpec{
		Image:     image,
		AdminHash: adminHash,
	})

	first := d.LogField(t, "dashboard.bootstrap_api_key", "key")
	if !generatedAPIKey.MatchString(first) {
		t.Fatalf("ephemeral dashboard did not generate an API key: %q", first)
	}

	d.Restart(t)

	replacement := d.LogField(t, "dashboard.bootstrap_api_key", "key")
	if replacement == first {
		t.Fatal("ephemeral API key survived a restart")
	}

	if code := ingestStatus(t, d, first); code != http.StatusUnauthorized {
		t.Errorf("old ephemeral API key authenticated after restart: status=%d", code)
	}

	if code := ingestStatus(t, d, replacement); code != http.StatusCreated {
		t.Errorf("replacement ephemeral API key did not authenticate: status=%d", code)
	}
}

func cliErrors(t *testing.T, image string) {
	t.Helper()

	//nolint:exhaustruct // only Cmd and Env are needed
	res := harness.RunOneShot(t, harness.OneShot{
		Image: image,
		Cmd:   []string{"reset-password"},
		Env:   map[string]string{"EPHEMERAL": "true"},
	})

	if res.Succeeded() {
		t.Error("reset-password in ephemeral mode unexpectedly succeeded")
	}

	if !res.Contains("reset-password requires persistent storage") {
		t.Errorf("unclear ephemeral-mode error: %s", res.Output)
	}

	//nolint:exhaustruct // only Cmd is needed
	empty := harness.RunOneShotStdin(t, harness.OneShot{
		Image: image,
		Cmd:   []string{"hash-password"},
	}, "\n")

	if empty.Succeeded() {
		t.Error("hash-password with empty stdin unexpectedly succeeded")
	}

	if !empty.Contains("empty password on stdin") {
		t.Errorf("unclear empty-input error: %s", empty.Output)
	}
}

func loginStatus(t *testing.T, d *harness.DashboardContainer, password string) int {
	t.Helper()

	return d.NewClient(t, "").Status(t, http.MethodPost, harness.APIRoot+"/auth/login",
		loginBody{Username: "admin", Password: password}, harness.SameOrigin())
}

func ingestStatus(t *testing.T, d *harness.DashboardContainer, key string) int {
	t.Helper()

	return d.NewClient(t, "").Status(t, http.MethodPost, harness.APIRoot+"/logs",
		json.RawMessage(`{"msg":"dashboard-cli-e2e","action":"ALLOWED"}`), harness.WithAPIKey(key))
}

func stopContainer(t *testing.T, d *harness.DashboardContainer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := d.Container.Stop(ctx, nil)
	if err != nil {
		t.Fatalf("stop dashboard container: %v", err)
	}
}

// worldWritableDir is a data mount the container's non-root user can write to.
func worldWritableDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	err := os.Chmod(dir, 0o777) //nolint:gosec // shared with a container user
	if err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}

	return dir
}

// lastLine returns the final non-empty line, which is where the CLI prints the
// credential it generated.
func lastLine(output string) string {
	var last string

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			last = line
		}
	}

	return last
}
