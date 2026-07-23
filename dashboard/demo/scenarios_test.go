package demo_test

import (
	"net"
	"testing"

	"github.com/g0lab/g0efilter/dashboard/demo"
)

//nolint:cyclop // Validate every independent fixture invariant in one pass.
func TestScenariosCanonicalFixtureInvariants(t *testing.T) {
	t.Parallel()

	fixtures, err := demo.Scenarios()
	if err != nil {
		t.Fatalf("Scenarios() error = %v", err)
	}

	if fixtures.SourceSubnet == "" || len(fixtures.Clients) == 0 || len(fixtures.Destinations) == 0 {
		t.Fatalf("incomplete fixtures: %+v", fixtures)
	}

	clients := make(map[string]bool, len(fixtures.Clients))
	for _, client := range fixtures.Clients {
		if client == "" || clients[client] {
			t.Fatalf("client %q is empty or duplicated", client)
		}

		clients[client] = true
	}

	verdicts := map[string]bool{"ALLOWED": true, "BLOCKED": true, "AUDIT": true}
	components := map[string]bool{"https": true, "http": true, "dns": true, "nflog": true}

	for i, destination := range fixtures.Destinations {
		if !verdicts[destination.Verdict] {
			t.Errorf("destination %d has unsupported verdict %q", i, destination.Verdict)
		}

		if !components[destination.Component] {
			t.Errorf("destination %d has unsupported component %q", i, destination.Component)
		}

		if net.ParseIP(destination.IP) == nil {
			t.Errorf("destination %d has invalid IP %q", i, destination.IP)
		}

		if destination.Port < 0 || destination.Port > 65535 {
			t.Errorf("destination %d has invalid port %d", i, destination.Port)
		}

		if destination.Category == "" || destination.Reason == "" {
			t.Errorf("destination %d lacks category or reason: %+v", i, destination)
		}
	}
}
