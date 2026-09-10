//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func httpsHealth(t *testing.T) *runtimeHealth {
	t.Helper()

	health := &runtimeHealth{}
	health.applyOK(config{mode: "https", httpPort: "65080", httpsPort: "65443", dnsPort: "65053"}, "hash-1")

	return health
}

func TestHealthReportsTheListenersForTheActiveMode(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mode  string
		ports []string
	}{
		"https":      {mode: "https", ports: []string{"65080", "65443"}},
		"dns":        {mode: "dns", ports: []string{"65053"}},
		"dns-strict": {mode: "dns-strict", ports: []string{"65053"}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			health := &runtimeHealth{}
			health.applyOK(config{mode: tc.mode, httpPort: "65080", httpsPort: "65443", dnsPort: "65053"}, "hash-1")

			got := health.snapshot(time.Now())
			if !got.Ready {
				t.Fatalf("snapshot after a successful apply is not ready: %q", got.Reason)
			}

			if len(got.Ports) != len(tc.ports) {
				t.Fatalf("ports = %v, want %v", got.Ports, tc.ports)
			}

			for i, port := range tc.ports {
				if got.Ports[i] != port {
					t.Errorf("ports = %v, want %v", got.Ports, tc.ports)

					break
				}
			}
		})
	}
}

// Kubelet projects a ConfigMap asynchronously, so brief drift must not evict the pod from its Service.
func TestHealthStaysReadyWhileDriftIsWithinTheGracePeriod(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("hash-2", start)

	got := health.snapshot(start.Add(reloadGrace - time.Second))
	if !got.Ready {
		t.Fatalf("readiness failed inside the grace period: %q", got.Reason)
	}
}

func TestHealthFailsOnceDriftOutlastsTheGracePeriod(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("hash-2", start)

	got := health.snapshot(start.Add(reloadGrace + time.Second))
	if got.Ready {
		t.Fatal("readiness held while the mounted policy went unapplied past the grace period")
	}

	if got.Reason == "" {
		t.Error("an unready snapshot carries no reason")
	}
}

// The drift clock must start at the first observation, not restart on each tick.
func TestHealthDoesNotRestartTheDriftClockOnRepeatedObservations(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	for offset := time.Duration(0); offset <= reloadGrace; offset += 5 * time.Second {
		health.observe("hash-2", start.Add(offset))
	}

	got := health.snapshot(start.Add(reloadGrace + time.Second))
	if got.Ready {
		t.Fatal("repeated observations reset the drift clock and hid a stuck reload")
	}
}

func TestHealthRecoversWhenTheMountedPolicyIsApplied(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("hash-2", start)
	health.applyFailed()
	health.applyOK(config{mode: "https", httpPort: "65080", httpsPort: "65443"}, "hash-2")

	got := health.snapshot(start.Add(2 * reloadGrace))
	if !got.Ready {
		t.Fatalf("readiness did not recover after the policy applied: %q", got.Reason)
	}
}

// A policy the agent rejected is more actionable than plain drift, so it is named.
func TestHealthNamesARejectedPolicy(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("hash-2", start)
	health.applyFailed()

	got := health.snapshot(start.Add(reloadGrace + time.Second))
	if got.Ready {
		t.Fatal("readiness held after the mounted policy was rejected")
	}

	if got.Reason != "the mounted policy was rejected; the previous one is still enforced" {
		t.Errorf("reason = %q, want the rejection wording", got.Reason)
	}
}

func TestHealthClearsDriftWhenTheHashMatchesAgain(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("hash-2", start)
	health.observe("hash-1", start.Add(time.Second))

	got := health.snapshot(start.Add(reloadGrace + time.Second))
	if !got.Ready {
		t.Fatalf("drift was not cleared when the mounted policy matched again: %q", got.Reason)
	}
}

func TestHealthIgnoresAnUnreadableHash(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.observe("", start)

	got := health.snapshot(start.Add(reloadGrace + time.Second))
	if !got.Ready {
		t.Fatal("an unreadable policy hash was treated as drift")
	}
}

func TestHealthMethodsToleranceForANilReceiver(t *testing.T) {
	t.Parallel()

	var health *runtimeHealth

	health.applyOK(config{mode: "https"}, "hash-1")
	health.applyFailed()
	health.observe("hash-2", time.Now())
}

func portsConfig(http, https, dns string) config {
	return config{mode: "https", httpPort: http, httpsPort: https, dnsPort: dns}
}

// Host-network sidecars share the node's namespace, so the socket separates on their proxy ports.
func TestTheHealthSocketIsUniquePerSidecar(t *testing.T) {
	t.Parallel()

	first := healthSocketName(portsConfig("65080", "65443", "65053"))
	second := healthSocketName(portsConfig("65081", "65444", "65054"))

	if first == second {
		t.Errorf("two sidecars on different ports share the socket %q", first)
	}

	if first != healthSocketName(portsConfig("65080", "65443", "65053")) {
		t.Error("the socket name is not stable, so the healthcheck could not find the server")
	}

	if !strings.HasPrefix(first, healthSocketPrefix) {
		t.Errorf("socket %q does not carry the %q prefix", first, healthSocketPrefix)
	}
}

// A test binary shares one network namespace, so this is the collision host-network sidecars hit.
func TestTwoHealthServersCoexistInOneNetworkNamespace(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tracked := &group{}

	for _, ports := range [][3]string{{"41080", "41443", "41053"}, {"41081", "41444", "41054"}} {
		cfg := portsConfig(ports[0], ports[1], ports[2])
		cfg.health = &runtimeHealth{}
		cfg.health.applyOK(cfg, "hash-1")

		err := startHealthServer(ctx, tracked, cfg, discardLogger())
		if err != nil {
			t.Fatalf("second sidecar could not bind its health socket: %v", err)
		}
	}

	cancel()

	if !tracked.wait(5 * time.Second) {
		t.Error("the health servers did not shut down")
	}
}

func TestASecondServerOnTheSamePortsIsRefused(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tracked := &group{}
	cfg := portsConfig("41090", "41453", "41063")
	cfg.health = &runtimeHealth{}

	err := startHealthServer(ctx, tracked, cfg, discardLogger())
	if err != nil {
		t.Fatalf("the first server could not bind: %v", err)
	}

	// Identical ports clash for the proxies too, so failing loudly beats an ambiguous probe.
	err = startHealthServer(ctx, tracked, cfg, discardLogger())
	if err == nil {
		t.Error("a second server on identical ports bound the same socket")
	}

	cancel()
	tracked.wait(5 * time.Second)
}

// The probe is a separate process, so it derives the name from the same environment.
func TestTheHealthcheckReachesTheRunningServer(t *testing.T) {
	t.Setenv("HTTP_PORT", "41100")
	t.Setenv("HTTPS_PORT", "41463")
	t.Setenv("DNS_PORT", "41073")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tracked := &group{}
	cfg := portsConfig("41100", "41463", "41073")
	cfg.health = &runtimeHealth{}
	cfg.health.applyOK(cfg, "hash-1")

	err := startHealthServer(ctx, tracked, cfg, discardLogger())
	if err != nil {
		t.Fatalf("start the health server: %v", err)
	}

	var dialer net.Dialer

	snapshot, err := readHealth(ctx, &dialer, healthSocketName(loadConfig()))
	if err != nil {
		t.Fatalf("the healthcheck could not reach the server it should have found: %v", err)
	}

	if !snapshot.Ready {
		t.Errorf("snapshot is not ready: %q", snapshot.Reason)
	}

	cancel()
	tracked.wait(5 * time.Second)
}

// A policy that cannot be read at all is not the same as one that matches: the last
// rules stay in force, so readiness has to fail rather than hold indefinitely.
func TestHealthFailsWhenTheMountedPolicyStaysUnreadable(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.readFailed(start)

	got := health.snapshot(start.Add(reloadGrace - time.Second))
	if !got.Ready {
		t.Fatalf("a single failed read evicted the pod inside the grace period: %q", got.Reason)
	}

	got = health.snapshot(start.Add(reloadGrace + time.Second))
	if got.Ready {
		t.Fatal("readiness held while the mounted policy stayed unreadable")
	}

	if !strings.Contains(got.Reason, "could not be read") {
		t.Errorf("reason = %q, want the unreadable policy named", got.Reason)
	}
}

// A read that recovers must clear the clock, or a transient failure would evict the pod later.
func TestHealthRecoversWhenThePolicyBecomesReadableAgain(t *testing.T) {
	t.Parallel()

	health := httpsHealth(t)
	start := time.Now()

	health.readFailed(start)
	health.observe("hash-1", start.Add(time.Second))

	got := health.snapshot(start.Add(2 * reloadGrace))
	if !got.Ready {
		t.Errorf("readiness stayed failed after the policy became readable again: %q", got.Reason)
	}
}
