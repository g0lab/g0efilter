package harness

import (
	"context"
	"maps"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// DashboardContainer is a standalone dashboard production container.
type DashboardContainer struct {
	Container testcontainers.Container
	BaseURL   string
	client    *DashboardClient
}

// DashboardContainerSpec configures a standalone dashboard.
type DashboardContainerSpec struct {
	Image string
	// DataBind is a host:container mount or a named volume for /app/data. Leave
	// empty to run in ephemeral mode.
	DataBind  string
	AdminHash string
	Env       map[string]string
}

// StartDashboardContainer runs the dashboard image and waits for it to serve.
func StartDashboardContainer(t *testing.T, spec DashboardContainerSpec) *DashboardContainer {
	t.Helper()

	env := map[string]string{
		"PORT":          ":" + DashboardPort,
		"AUTH_MODE":     "session",
		"COOKIE_SECURE": "false",
		"LOG_LEVEL":     "INFO",
	}

	if spec.DataBind == "" {
		env["EPHEMERAL"] = "true"
	}

	if spec.AdminHash != "" {
		env["ADMIN_PASSWORD_HASH"] = spec.AdminHash
	}

	maps.Copy(env, spec.Env)

	var binds []string
	if spec.DataBind != "" {
		binds = append(binds, spec.DataBind+":/app/data")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	//nolint:exhaustruct // only the fields this container needs
	req := testcontainers.ContainerRequest{
		Image:        spec.Image,
		Env:          env,
		ExposedPorts: []string{DashboardPort + "/tcp"},
		WaitingFor: wait.ForHTTP("/health").
			WithPort(DashboardPort + "/tcp").
			WithStartupTimeout(60 * time.Second),
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapDrop = []string{"ALL"}
			hc.ReadonlyRootfs = true
			hc.SecurityOpt = []string{"no-new-privileges"}
			hc.Binds = binds
		},
	}

	//nolint:exhaustruct // Started is the only option needed
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start dashboard container: %v", err)
	}

	d := &DashboardContainer{Container: c, BaseURL: "", client: nil}
	d.refreshURL(t)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		_ = c.Terminate(cleanupCtx)
	})

	return d
}

// Client returns an HTTP client bound to this container, with its own cookie jar.
func (d *DashboardContainer) Client(t *testing.T) *DashboardClient {
	t.Helper()

	if d.client == nil {
		d.client = newClient(t, d.BaseURL, "")
	}

	return d.client
}

// NewClient returns a fresh client, for scenarios needing a separate session.
func (d *DashboardContainer) NewClient(t *testing.T, apiKey string) *DashboardClient {
	t.Helper()

	return newClient(t, d.BaseURL, apiKey)
}

// Restart restarts the container and waits for it to serve again.
func (d *DashboardContainer) Restart(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := d.Container.Stop(ctx, nil)
	if err != nil {
		t.Fatalf("stop dashboard container: %v", err)
	}

	err = d.Container.Start(ctx)
	if err != nil {
		t.Fatalf("restart dashboard container: %v", err)
	}

	// A restarted container can be republished on a different host port.
	d.refreshURL(t)
	d.client = nil

	d.WaitHealthy(t)
}

// WaitHealthy blocks until the dashboard serves its health endpoint. It issues a
// bare request rather than going through DashboardClient, whose transport errors
// are fatal and would abort the first refused-connection poll.
func (d *DashboardContainer) WaitHealthy(t *testing.T) {
	t.Helper()

	Eventually(t, 60*time.Second, time.Second, func() (bool, string) {
		resp, err := http.Get(d.BaseURL + "/health") //nolint:noctx // Eventually bounds the wait
		if err != nil {
			return false, "dashboard not reachable yet: " + err.Error()
		}

		defer func() { _ = resp.Body.Close() }()

		return resp.StatusCode == http.StatusOK,
			"dashboard health returned " + resp.Status
	})
}

// Logs returns the container's log output with escapes stripped.
func (d *DashboardContainer) Logs(t *testing.T) string {
	t.Helper()

	return oneShotLogs(t, d.Container)
}

// LogField reads the last value of a field from a named log event, which is how
// the bootstrap credentials are surfaced.
func (d *DashboardContainer) LogField(t *testing.T, event, field string) string {
	t.Helper()

	var value string

	for line := range strings.SplitSeq(d.Logs(t), "\n") {
		if !strings.Contains(line, event) {
			continue
		}

		for kv := range strings.FieldsSeq(line) {
			key, v, ok := strings.Cut(kv, "=")
			if ok && key == field {
				value = strings.Trim(v, `"`)
			}
		}
	}

	return value
}

// CountLogEvent counts matching container log events.
func (d *DashboardContainer) CountLogEvent(t *testing.T, event string) int {
	t.Helper()

	n := 0

	for line := range strings.SplitSeq(d.Logs(t), "\n") {
		if strings.Contains(line, event) {
			n++
		}
	}

	return n
}

func (d *DashboardContainer) refreshURL(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := d.Container.Host(ctx)
	if err != nil {
		t.Fatalf("dashboard host: %v", err)
	}

	port, err := d.Container.MappedPort(ctx, DashboardPort+"/tcp")
	if err != nil {
		t.Fatalf("dashboard port: %v", err)
	}

	d.BaseURL = "http://" + net.JoinHostPort(host, port.Port())
}
