package webhook_test

import (
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	g0webhook "github.com/g0lab/g0efilter/controller/internal/webhook"
)

func revisionOf(t *testing.T, spec v1alpha1.SidecarSpec) string {
	t.Helper()

	return revisionFor(t, spec, g0webhook.Defaults{Image: testImage}, "g0efilter-web")
}

func revisionFor(t *testing.T, spec v1alpha1.SidecarSpec, defaults g0webhook.Defaults, configMap string) string {
	t.Helper()

	revision, err := g0webhook.StartupRevision(spec, defaults, configMap)
	if err != nil {
		t.Fatalf("StartupRevision() = %v", err)
	}

	return revision
}

// These reach a running sidecar through the policy document, so they must not force a restart.
func TestReloadableSettingsDoNotChangeTheStartupRevision(t *testing.T) {
	t.Parallel()

	base := revisionOf(t, v1alpha1.SidecarSpec{})

	cases := map[string]v1alpha1.SidecarSpec{
		"mode":          {Mode: "dns-strict"},
		"enforcement":   {Enforcement: "audit"},
		"dns upstreams": {DNS: v1alpha1.DNSSpec{Upstreams: []string{"10.96.0.10:53"}}},
		"dns hardening": {DNS: v1alpha1.DNSSpec{Hardening: new(bool)}},
		"dns rate qps":  {DNS: v1alpha1.DNSSpec{RateQPS: new(int32(25))}},
		"dns burst":     {DNS: v1alpha1.DNSSpec{RateBurst: new(int32(50))}},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := revisionOf(t, spec); got != base {
				t.Errorf("changing %s changed the startup revision:\ngot  %s\nwant %s", name, got, base)
			}
		})
	}
}

// These cannot be changed without recreating the container.
func TestStartupSettingsChangeTheStartupRevision(t *testing.T) {
	t.Parallel()

	base := revisionOf(t, v1alpha1.SidecarSpec{})

	cases := map[string]v1alpha1.SidecarSpec{
		"image":     {Image: "example.com/g0efilter:other"},
		"log level": {LogLevel: "DEBUG"},
		"events":    {Events: true},
		"metrics":   {Metrics: v1alpha1.MetricsSpec{Enabled: true, Port: 9090}},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := revisionOf(t, spec); got == base {
				t.Errorf("changing %s left the startup revision at %s", name, base)
			}
		})
	}
}

func TestTheStartupRevisionTracksTheConfigMap(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{}

	first := revisionFor(t, spec, g0webhook.Defaults{Image: testImage}, "g0efilter-web")
	second := revisionFor(t, spec, g0webhook.Defaults{Image: testImage}, "g0efilter-api")

	if first == second {
		t.Error("two policies mounting different ConfigMaps share a startup revision")
	}
}

// The reconciler and injector compute this independently; diverging defaults strand every pod.
func TestTheStartupRevisionDependsOnTheDefaults(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{}

	withDefault := revisionFor(t, spec, g0webhook.Defaults{Image: testImage}, "g0efilter-web")
	withOther := revisionFor(t, spec, g0webhook.Defaults{Image: "example.com/other:v1"}, "g0efilter-web")

	if withDefault == withOther {
		t.Error("the default image does not reach the startup revision")
	}
}

func TestTheStartupRevisionIsStable(t *testing.T) {
	t.Parallel()

	spec := v1alpha1.SidecarSpec{Mode: "dns", LogLevel: "DEBUG", Metrics: v1alpha1.MetricsSpec{Enabled: true, Port: 9090}}

	first := revisionOf(t, spec)

	second := revisionOf(t, spec)
	if first != second {
		t.Errorf("the startup revision is not deterministic: %s then %s", first, second)
	}
}

// The prefix lets an upgrade tell a pre-reload sidecar from a current one.
func TestTheStartupRevisionCarriesItsSchemaPrefix(t *testing.T) {
	t.Parallel()

	got := revisionOf(t, v1alpha1.SidecarSpec{})
	if len(got) < len("runtime-v1:") || got[:len("runtime-v1:")] != "runtime-v1:" {
		t.Errorf("startup revision %q does not carry the runtime-v1 prefix", got)
	}
}
