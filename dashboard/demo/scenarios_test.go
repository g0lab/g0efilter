package demo_test

import (
	"net"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/dashboard/demo"
)

func TestScenariosCanonicalFixtureInvariants(t *testing.T) {
	t.Parallel()

	fixtures, err := demo.Scenarios()
	if err != nil {
		t.Fatalf("Scenarios() error = %v", err)
	}

	if fixtures.SourceSubnet == "" || len(fixtures.Clients) == 0 || len(fixtures.Destinations) == 0 {
		t.Fatalf("incomplete fixtures: %+v", fixtures)
	}

	validateClients(t, fixtures.Clients)

	for i, destination := range fixtures.Destinations {
		validateDestination(t, i, destination)
	}
}

func validateClients(t *testing.T, fixtureClients []string) {
	t.Helper()

	clients := make(map[string]bool, len(fixtureClients))
	for _, client := range fixtureClients {
		if client == "" || clients[client] {
			t.Fatalf("client %q is empty or duplicated", client)
		}

		for _, deviceLabel := range []string{"laptop", "desktop", "workstation"} {
			if strings.Contains(strings.ToLower(client), deviceLabel) {
				t.Errorf("client %q looks like an end-user device, not a workload", client)
			}
		}

		clients[client] = true
	}
}

func validateDestination(t *testing.T, index int, destination demo.Destination) {
	t.Helper()

	verdicts := map[string]bool{"ALLOWED": true, "BLOCKED": true, "AUDIT": true}
	components := map[string]bool{"https": true, "http": true, "dns": true, "nflog": true}

	if !verdicts[destination.Verdict] {
		t.Errorf("destination %d has unsupported verdict %q", index, destination.Verdict)
	}

	if !components[destination.Component] {
		t.Errorf("destination %d has unsupported component %q", index, destination.Component)
	}

	if destination.Port < 0 || destination.Port > 65535 {
		t.Errorf("destination %d has invalid port %d", index, destination.Port)
	}

	if destination.Category == "" || destination.Reason == "" {
		t.Errorf("destination %d lacks category or reason: %+v", index, destination)
	}

	validateNetworkIdentity(t, index, destination)
}

func validateNetworkIdentity(t *testing.T, index int, destination demo.Destination) {
	t.Helper()

	if destination.Component == "dns" {
		if destination.Domain == "" || destination.IP != "" || destination.Port != 0 {
			t.Errorf("DNS destination %d must contain only a domain identity: %+v", index, destination)
		}

		return
	}

	if net.ParseIP(destination.IP) == nil {
		t.Errorf("destination %d has invalid IP %q", index, destination.IP)
	}

	if destination.Component == "nflog" && destination.Domain != "" {
		t.Errorf("NFLOG destination %d must not invent a domain: %+v", index, destination)
	}
}
