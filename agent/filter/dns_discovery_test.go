//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"reflect"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

// A host stub resolver would forward DNS into the pod's own empty namespace, breaking every lookup.
func TestLoopbackNameserversAreNotUsedAsUpstreams(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		server string
		want   bool
	}{
		"cluster dns":      {server: "10.96.0.10", want: true},
		"ipv6 cluster dns": {server: "fd00::10", want: true},
		"systemd-resolved": {server: "127.0.0.53", want: false},
		"docker embedded":  {server: "127.0.0.11", want: false},
		"ipv6 loopback":    {server: "::1", want: false},
		"unspecified":      {server: "0.0.0.0", want: false},
		"not an address":   {server: "nameserver", want: false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := routableResolver(tc.server); got != tc.want {
				t.Errorf("routableResolver(%q) = %v, want %v", tc.server, got, tc.want)
			}
		})
	}
}

func TestResolverAddressesKeepOnlyRoutableServersAndCarryThePort(t *testing.T) {
	t.Parallel()

	cfg := &dns.ClientConfig{Servers: []string{"127.0.0.53", "10.96.0.10", "fd00::10"}, Port: "53"}

	got := resolverAddresses(cfg)
	want := []string{"10.96.0.10:53", "[fd00::10]:53"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolverAddresses() = %v, want %v", got, want)
	}
}

func TestResolverAddressesAreEmptyWhenEveryNameserverIsLoopback(t *testing.T) {
	t.Parallel()

	cfg := &dns.ClientConfig{Servers: []string{"127.0.0.53"}, Port: "53"}

	if got := resolverAddresses(cfg); len(got) != 0 {
		t.Errorf("resolverAddresses() = %v, want empty so the caller can fall back", got)
	}
}

// The cluster domain comes from the search list, so a custom domain still routes to cluster DNS.
func TestClusterSuffixesLearnTheClusterDomainFromTheSearchList(t *testing.T) {
	t.Parallel()

	search := []string{"tenant-a.svc.example.internal.", "svc.example.internal.", "example.internal."}

	got := clusterSuffixes(search)

	if !slices.Contains(got, "example.internal") {
		t.Errorf("clusterSuffixes(%v) = %v, want it to include example.internal", search, got)
	}

	for _, base := range []string{"cluster.local", "svc", "in-addr.arpa", "ip6.arpa"} {
		if !slices.Contains(got, base) {
			t.Errorf("clusterSuffixes() dropped the built-in suffix %q: %v", base, got)
		}
	}
}

func TestClusterSuffixesDoNotRepeatTheDefaultDomain(t *testing.T) {
	t.Parallel()

	got := clusterSuffixes([]string{"svc.cluster.local.", "cluster.local."})

	count := 0

	for _, suffix := range got {
		if suffix == "cluster.local" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("cluster.local appears %d times in %v, want once", count, got)
	}
}

func discoveryHandler() *dnsHandler {
	return &dnsHandler{
		upstreams:        []string{"1.1.1.1:53"},
		clusterUpstreams: []string{"10.96.0.10:53"},
		clusterSuffixes:  []string{"cluster.local", "svc", "in-addr.arpa", "ip6.arpa"},
	}
}

func TestClusterNamesResolveThroughTheClusterResolver(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		qname string
		want  []string
	}{
		"service name":      {qname: "api.tenant-a.svc.cluster.local.", want: []string{"10.96.0.10:53"}},
		"the domain itself": {qname: "cluster.local.", want: []string{"10.96.0.10:53"}},
		"reverse lookup":    {qname: "10.0.96.10.in-addr.arpa.", want: []string{"10.96.0.10:53"}},
		"ipv6 reverse":      {qname: "1.0.0.0.ip6.arpa.", want: []string{"10.96.0.10:53"}},
		"external name":     {qname: "api.example.com.", want: []string{"1.1.1.1:53"}},
		"suffix lookalike":  {qname: "notcluster.local.", want: []string{"1.1.1.1:53"}},
		"case insensitive":  {qname: "API.TENANT-A.SVC.CLUSTER.LOCAL.", want: []string{"10.96.0.10:53"}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := new(dns.Msg).SetQuestion(tc.qname, dns.TypeA)

			got := discoveryHandler().upstreamsFor(request)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("upstreamsFor(%q) = %v, want %v", tc.qname, got, tc.want)
			}
		})
	}
}

func TestUpstreamsForFallsBackWhenThereIsNoClusterResolver(t *testing.T) {
	t.Parallel()

	handler := discoveryHandler()
	handler.clusterUpstreams = nil

	request := new(dns.Msg).SetQuestion("api.tenant-a.svc.cluster.local.", dns.TypeA)

	got := handler.upstreamsFor(request)
	if !reflect.DeepEqual(got, []string{"1.1.1.1:53"}) {
		t.Errorf("upstreamsFor() = %v, want the configured upstreams", got)
	}
}

// Splitting on the question only makes sense for a single-question message.
func TestUpstreamsForIgnoresMultiQuestionMessages(t *testing.T) {
	t.Parallel()

	request := new(dns.Msg).SetQuestion("api.tenant-a.svc.cluster.local.", dns.TypeA)
	request.Question = append(request.Question, dns.Question{
		Name: "other.cluster.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})

	got := discoveryHandler().upstreamsFor(request)
	if !reflect.DeepEqual(got, []string{"1.1.1.1:53"}) {
		t.Errorf("upstreamsFor() = %v, want the configured upstreams", got)
	}
}

func TestDiscoveryIsSkippedOutsideKubernetes(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	if got := ClusterResolverIPs(); got != nil {
		t.Errorf("ClusterResolverIPs() = %v, want nil outside Kubernetes", got)
	}

	if got := discoveredUpstreams(); !reflect.DeepEqual(got, []string{dockerEmbeddedResolver}) {
		t.Errorf("discoveredUpstreams() = %v, want the Docker embedded resolver", got)
	}
}
