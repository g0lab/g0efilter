package filter

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

const dockerEmbeddedResolver = "127.0.0.11:53"

func clusterResolvers() ([]string, []string) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return nil, nil
	}

	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, nil
	}

	return resolverAddresses(cfg), clusterSuffixes(cfg.Search)
}

// ClusterResolverIPs returns the pod's resolvers; with no DNS proxy the workload dials them directly.
func ClusterResolverIPs() []string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return nil
	}

	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	servers := make([]string, 0, len(cfg.Servers))

	for _, server := range cfg.Servers {
		if routableResolver(server) {
			servers = append(servers, server)
		}
	}

	return servers
}

// routableResolver drops loopback nameservers, which would forward into the pod's own namespace.
func routableResolver(server string) bool {
	addr, err := netip.ParseAddr(server)
	if err != nil {
		return false
	}

	return !addr.IsLoopback() && !addr.IsUnspecified()
}

func resolverAddresses(cfg *dns.ClientConfig) []string {
	upstreams := make([]string, 0, len(cfg.Servers))

	for _, server := range cfg.Servers {
		if routableResolver(server) {
			upstreams = append(upstreams, net.JoinHostPort(server, cfg.Port))
		}
	}

	return upstreams
}

func clusterSuffixes(search []string) []string {
	suffixes := []string{"cluster.local", "svc", "in-addr.arpa", "ip6.arpa"}
	seen := map[string]struct{}{}

	for _, suffix := range suffixes {
		seen[suffix] = struct{}{}
	}

	for _, domain := range search {
		domain = strings.TrimSuffix(strings.ToLower(domain), ".")
		if !strings.HasPrefix(domain, "svc.") {
			continue
		}

		domain = strings.TrimPrefix(domain, "svc.")
		if _, ok := seen[domain]; ok {
			continue
		}

		seen[domain] = struct{}{}
		suffixes = append(suffixes, domain)
	}

	return suffixes
}

func discoveredUpstreams() []string {
	upstreams, _ := clusterResolvers()
	if len(upstreams) > 0 {
		return upstreams
	}

	return []string{dockerEmbeddedResolver}
}

// Routing only chooses a resolver; cluster names still pass the policy and hardening checks.
func (handler *dnsHandler) upstreamsFor(request *dns.Msg) []string {
	if len(request.Question) != 1 || len(handler.clusterUpstreams) == 0 {
		return handler.upstreams
	}

	name := strings.TrimSuffix(strings.ToLower(request.Question[0].Name), ".")

	for _, suffix := range handler.clusterSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return handler.clusterUpstreams
		}
	}

	return handler.upstreams
}
