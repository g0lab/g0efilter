//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"errors"
	"reflect"
	"testing"

	"github.com/g0lab/g0efilter/agent/policy"
)

func TestWithRuntimeLeavesConfigAloneWhenThePolicyCarriesNoRuntimeBlock(t *testing.T) {
	t.Parallel()

	cfg := config{mode: "dns", auditMode: true, dnsHardening: false}

	got, err := withRuntime(cfg, &policy.Policy{})
	if err != nil {
		t.Fatalf("withRuntime() = %v, want nil", err)
	}

	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("config changed without a runtime block:\ngot  %+v\nwant %+v", got, cfg)
	}
}

// A present block replaces the environment as a unit, so an unset field takes its documented default.
func TestWithRuntimeReplacesEnvironmentDefaultsAsAUnit(t *testing.T) {
	t.Parallel()

	cfg := config{mode: "dns-strict", auditMode: true, dnsHardening: false, dnsRateQPS: 40}

	got, err := withRuntime(cfg, &policy.Policy{Runtime: &policy.Runtime{}})
	if err != nil {
		t.Fatalf("withRuntime() = %v, want nil", err)
	}

	if got.mode != "https" {
		t.Errorf("mode = %q, want https", got.mode)
	}

	if got.auditMode {
		t.Error("enforcement fell back to the stale audit environment")
	}

	if !got.dnsHardening {
		t.Error("dnsHardening = false, want the default of true")
	}

	if got.dnsRateQPS != 0 {
		t.Errorf("dnsRateQPS = %d, want 0", got.dnsRateQPS)
	}
}

// A non-nil empty slice is the signal that selects resolver discovery.
func TestWithRuntimeSelectsDiscoveryWhenNoUpstreamsAreSet(t *testing.T) {
	t.Parallel()

	got, err := withRuntime(config{}, &policy.Policy{Runtime: &policy.Runtime{Mode: "dns"}})
	if err != nil {
		t.Fatalf("withRuntime() = %v, want nil", err)
	}

	if got.dnsUpstreams == nil {
		t.Fatal("dnsUpstreams is nil, which keeps the environment default instead of selecting discovery")
	}

	if len(got.dnsUpstreams) != 0 {
		t.Errorf("dnsUpstreams = %v, want empty", got.dnsUpstreams)
	}
}

func TestWithRuntimeAppliesValidSettings(t *testing.T) {
	t.Parallel()

	runtime := &policy.Runtime{
		Mode:         "dns-strict",
		Enforcement:  "audit",
		DNSUpstreams: []string{"10.96.0.10:53"},
		DNSHardening: new(bool),
		DNSRateQPS:   25,
		DNSRateBurst: 50,
	}

	got, err := withRuntime(config{}, &policy.Policy{Runtime: runtime})
	if err != nil {
		t.Fatalf("withRuntime() = %v, want nil", err)
	}

	if got.mode != "dns-strict" || !got.auditMode || got.dnsHardening {
		t.Errorf("settings not applied: %+v", got)
	}

	if !reflect.DeepEqual(got.dnsUpstreams, []string{"10.96.0.10:53"}) {
		t.Errorf("dnsUpstreams = %v, want [10.96.0.10:53]", got.dnsUpstreams)
	}

	if got.dnsRateQPS != 25 || got.dnsRateBurst != 50 {
		t.Errorf("rate limits = %d/%d, want 25/50", got.dnsRateQPS, got.dnsRateBurst)
	}
}

func TestWithRuntimeRejectsUnusableSettings(t *testing.T) {
	t.Parallel()

	cases := map[string]*policy.Runtime{
		"unknown mode":          {Mode: "transparent"},
		"unknown enforcement":   {Enforcement: "warn"},
		"negative qps":          {DNSRateQPS: -1},
		"negative burst":        {DNSRateBurst: -1},
		"upstream without port": {DNSUpstreams: []string{"10.96.0.10"}},
		"upstream without host": {DNSUpstreams: []string{":53"}},
		"upstream port zero":    {DNSUpstreams: []string{"10.96.0.10:0"}},
		"upstream port too big": {DNSUpstreams: []string{"10.96.0.10:65536"}},
		"upstream not a number": {DNSUpstreams: []string{"10.96.0.10:domain"}},
	}

	for name, runtime := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := withRuntime(config{}, &policy.Policy{Runtime: runtime})
			if !errors.Is(err, errRuntimeConfig) {
				t.Fatalf("withRuntime() = %v, want errRuntimeConfig", err)
			}
		})
	}
}

// Only https mode needs the rule; the DNS modes proxy the query under the bypass mark.
func TestClusterResolversAreAllowedOnlyWhereTheWorkloadDialsThemDirectly(t *testing.T) {
	t.Parallel()

	resolvers := []string{"10.96.0.10"}
	allowed := []string{"udp/10.96.0.10:53", "tcp/10.96.0.10:53"}

	cases := map[string]struct {
		cfg          config
		defaultAllow bool
		resolvers    []string
		want         []string
	}{
		"https default-deny": {
			cfg:       config{mode: "https", allowClusterResolver: true},
			resolvers: resolvers,
			want:      append([]string{"1.1.1.1"}, allowed...),
		},
		"dns mode proxies the query": {
			cfg:       config{mode: "dns", allowClusterResolver: true},
			resolvers: resolvers,
			want:      []string{"1.1.1.1"},
		},
		"dns-strict mode proxies the query": {
			cfg:       config{mode: "dns-strict", allowClusterResolver: true},
			resolvers: resolvers,
			want:      []string{"1.1.1.1"},
		},
		"default-allow needs no rule": {
			cfg:          config{mode: "https", allowClusterResolver: true},
			defaultAllow: true,
			resolvers:    resolvers,
			want:         []string{"1.1.1.1"},
		},
		"explicitly opted out": {
			cfg:       config{mode: "https", allowClusterResolver: false},
			resolvers: resolvers,
			want:      []string{"1.1.1.1"},
		},
		"nothing discovered": {
			cfg:       config{mode: "https", allowClusterResolver: true},
			resolvers: nil,
			want:      []string{"1.1.1.1"},
		},
		"ipv6 resolver is bracketed": {
			cfg:       config{mode: "https", allowClusterResolver: true},
			resolvers: []string{"fd00::10"},
			want:      []string{"1.1.1.1", "udp/[fd00::10]:53", "tcp/[fd00::10]:53"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := withClusterResolvers(tc.cfg, []string{"1.1.1.1"}, tc.defaultAllow, tc.resolvers, discardLogger())
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("allowIPs = %v, want %v", got, tc.want)
			}
		})
	}
}

// The policy's slice is reused across reloads, so appending in place would accumulate rules.
func TestClusterResolverAllowDoesNotMutateThePolicySlice(t *testing.T) {
	t.Parallel()

	cfg := config{mode: "https", allowClusterResolver: true}
	allowIPs := []string{"1.1.1.1"}

	withClusterResolvers(cfg, allowIPs, false, []string{"10.96.0.10"}, discardLogger())
	withClusterResolvers(cfg, allowIPs, false, []string{"10.96.0.10"}, discardLogger())

	if len(allowIPs) != 1 || allowIPs[0] != "1.1.1.1" {
		t.Errorf("the caller's slice was modified: %v", allowIPs)
	}
}
