package e2e_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

func TestSharedBehaviour(t *testing.T) {
	mode := harness.ModeFromEnv(t)
	stack := harness.Shared(t, harness.BaselineConfig(t, mode))

	t.Run("Phase01Baseline", func(t *testing.T) { phase01Baseline(t, stack, mode) })
	t.Run("Phase02IPv6Egress", func(t *testing.T) { phase02IPv6Egress(t, stack, mode) })
	t.Run("Phase03UnblockReload", func(t *testing.T) { phase03UnblockReload(t, stack) })
	t.Run("Phase04IPv6Unblock", func(t *testing.T) { phase04IPv6Unblock(t, stack, mode) })
	t.Run("Phase05DashboardLogs", func(t *testing.T) { phase05DashboardLogs(t, stack) })
	t.Run("Phase06Regex", func(t *testing.T) { phase06Regex(t, stack) })
	t.Run("Phase07DefaultAllow", func(t *testing.T) { phase07DefaultAllow(t, stack) })
}

func phase01Baseline(t *testing.T, s *harness.Stack, mode harness.FilterMode) {
	s.ResetPolicy(t)

	s.AssertAllowed(t, "https://github.com")
	s.AssertAllowed(t, "http://github.com")

	if mode != harness.FilterModeDNS {
		s.AssertAllowed(t, "https://1.1.1.1")
		s.AssertAllowed(t, "http://1.1.1.1")
	} else {
		t.Log("skipping IP tests in DNS mode (IPs bypass DNS filtering)")
	}

	mark := s.AgentLogMark(t)

	s.AssertBlocked(t, "https://google.com")
	s.AssertBlocked(t, "http://google.com")

	t.Run("blocks log at WARN and are alert-flagged", func(t *testing.T) {
		alert := true

		event := s.WaitForAgentEvent(t, mark, harness.EventMatcher{
			Event:  "*",
			Action: "BLOCKED",
			Alert:  &alert,
		}, 15*time.Second)

		if event.Level != "WRN" {
			t.Errorf("blocked decision logged at %s, want WRN: %s", event.Level, event.Raw)
		}

		if !strings.Contains(event.Event, ".blocked") {
			t.Errorf("unexpected event name %q for a block: %s", event.Event, event.Raw)
		}
	})

	if mode == harness.FilterModeHTTPS {
		s.AssertBlocked(t, "https://1.0.0.1")
		s.AssertBlocked(t, "http://1.0.0.1")

		t.Run("UDP/53 egress follows the IP allowlist", func(t *testing.T) {
			// https mode does not intercept DNS, so UDP/53 is gated purely on
			// destination IP: a real round-trip to the allow-listed resolver and
			// nothing at all to a blocked one.
			mark := s.AgentLogMark(t)

			s.AssertUDPDNSAnswer(t, "1.1.1.1", "github.com")
			s.AssertIPVerdictSince(t, mark, "ALLOWED", "1.1.1.1", 53, "UDP")

			s.AssertUDPDNSUnreachable(t, "1.0.0.2", "github.com")
			s.AssertIPVerdictSince(t, mark, "BLOCKED", "1.0.0.2", 53, "UDP")
		})
	}
}

func phase02IPv6Egress(t *testing.T, s *harness.Stack, mode harness.FilterMode) {
	if mode != harness.FilterModeHTTPS {
		t.Skipf("IPv6 egress phase runs in https mode only (got %s)", mode)
	}

	s.ResetPolicy(t)

	s.AssertNFTContains(t, "ip6", "g0efilter_v6", "policy drop", "ip6 filter table loaded with policy drop")
	s.AssertNFTContains(t, "ip6", "g0efilter_v6", "allow_daddr_v6", "allow_daddr_v6 set present")
	s.AssertNFTTableExists(t, "g0efilter_nat_v6")

	route := s.ExecTester(t, "sh", "-lc", "ip -6 route 2>/dev/null | grep '^default'")
	if route.ExitCode != 0 {
		t.Skip("no IPv6 default route; nftables structure was verified but egress enforcement cannot be exercised")
	}

	s.AssertBlocked(t, "https://google.com", "-6")
}

func phase03UnblockReload(t *testing.T, s *harness.Stack) {
	s.ResetPolicy(t)

	api := s.DashboardAPI(t)

	created := harness.Do[harness.UnblockResponse](t, api, http.MethodPost, harness.APIRoot+"/unblocks",
		harness.UnblockRequest{Type: "domain", Value: "google.com", TargetHostname: "host-01"})
	if created.StatusCode != http.StatusOK && created.StatusCode != http.StatusCreated {
		t.Fatalf("create unblock: status=%d body=%s", created.StatusCode, created.RawBody)
	}

	if created.Body.Status != "pending" {
		t.Fatalf("new unblock status = %q, want pending (%s)", created.Body.Status, created.RawBody)
	}

	if created.Body.ID == "" {
		t.Fatalf("no id returned: %s", created.RawBody)
	}

	t.Run("pending status carries the target hostname", func(t *testing.T) {
		status := harness.Do[harness.UnblockStatus](t, api, http.MethodGet,
			harness.APIRoot+"/unblocks/status", nil)

		found := false

		for _, p := range status.Body.Pending {
			if p.Value == "google.com" && p.TargetHostname == "host-01" {
				found = true
			}
		}

		if !found {
			t.Fatalf("google.com for host-01 not pending: %s", status.RawBody)
		}
	})

	t.Run("agent polls, applies and acknowledges", func(t *testing.T) {
		harness.Eventually(t, 90*time.Second, 2*time.Second, func() (bool, string) {
			status := harness.Do[harness.UnblockStatus](t, api, http.MethodGet,
				harness.APIRoot+"/unblocks/status", nil)

			return len(status.Body.Pending) == 0, "unblock still pending: " + status.RawBody
		})

		status := harness.Do[harness.UnblockStatus](t, api, http.MethodGet,
			harness.APIRoot+"/unblocks/status", nil)

		found := false

		for _, c := range status.Body.Completed {
			if c.Value == "google.com" && c.TargetHostname == "host-01" {
				found = true
			}
		}

		if !found {
			t.Errorf("completed entry lost its target hostname: %s", status.RawBody)
		}
	})

	s.AssertPolicyContains(t, "google.com", 30*time.Second)

	// The agent rewrote the policy itself, so wait for its own reload rather than
	// writing a new one.
	harness.Eventually(t, 45*time.Second, time.Second, func() (bool, string) {
		res := s.Curl(t, "https://google.com", 10*time.Second)

		return res.ExitCode == 0, "google.com still blocked after unblock"
	})

	s.AssertAllowed(t, "https://google.com")
	s.AssertAllowed(t, "http://google.com")

	t.Run("input validation", func(t *testing.T) {
		cases := []struct {
			name string
			body any
			path string
			want int
			opts []harness.RequestOption
		}{
			{"invalid type", harness.UnblockRequest{Type: "badtype", Value: "example.com"},
				harness.APIRoot + "/unblocks", http.StatusBadRequest, nil},
			{"invalid ip", harness.UnblockRequest{Type: "ip", Value: "not-an-ip"},
				harness.APIRoot + "/unblocks", http.StatusBadRequest, nil},
			{"unknown ack id", map[string]string{"id": "nonexistent-id"},
				harness.APIRoot + "/unblocks/ack", http.StatusNotFound, nil},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := api.Status(t, http.MethodPost, tc.path, tc.body, tc.opts...)
				if got != tc.want {
					t.Errorf("status = %d, want %d", got, tc.want)
				}
			})
		}

		t.Run("unauthenticated poll", func(t *testing.T) {
			got := api.Status(t, http.MethodGet, harness.APIRoot+"/unblocks", nil, harness.NoAuth())
			if got != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", got)
			}
		})
	})
}

func phase04IPv6Unblock(t *testing.T, s *harness.Stack, mode harness.FilterMode) {
	if mode != harness.FilterModeHTTPS {
		t.Skipf("IPv6 unblock phase runs in https mode only (got %s)", mode)
	}

	const v6 = "2606:4700:4700::1111"

	s.ResetPolicy(t)

	api := s.DashboardAPI(t)

	created := harness.Do[harness.UnblockResponse](t, api, http.MethodPost, harness.APIRoot+"/unblocks",
		harness.UnblockRequest{Type: "ip", Value: v6, TargetHostname: "host-01"})
	if created.Body.Status != "pending" || created.Body.ID == "" {
		t.Fatalf("create IPv6 unblock failed: %s", created.RawBody)
	}

	harness.Eventually(t, 90*time.Second, 2*time.Second, func() (bool, string) {
		status := harness.Do[harness.UnblockStatus](t, api, http.MethodGet,
			harness.APIRoot+"/unblocks/status", nil)

		return len(status.Body.Pending) == 0, "IPv6 unblock still pending: " + status.RawBody
	})

	s.AssertPolicyContains(t, v6, 30*time.Second)

	s.AssertNFTContains(t, "ip6", "g0efilter_v6", v6, "unblocked address in allow_daddr_v6")
	s.AssertNFTTableExists(t, "g0efilter_nat_v6")
	s.AssertNFTContains(t, "ip6", "g0efilter_v6", "icmpv6 type echo-request", "v6 filter has icmpv6 echo-request")
	s.AssertNFTContains(t, "ip6", "g0efilter_v6", "ip6 daddr @allow_daddr_v6", "v6 filter has the allow rule")

	// GitHub-hosted runners have no IPv6 egress, so only assert connectivity where
	// a default route exists.
	route := s.ExecTester(t, "sh", "-lc", "ip -6 route 2>/dev/null | grep '^default'")
	if route.ExitCode != 0 {
		t.Log("no IPv6 default route in the tester container; skipping the curl -6 check")

		return
	}

	s.AssertReachable(t, "https://["+v6+"]", "-6")
}

func phase05DashboardLogs(t *testing.T, s *harness.Stack) {
	s.ResetPolicy(t)

	api := s.DashboardAPI(t)

	s.AssertAllowed(t, "https://github.com")
	s.AssertBlocked(t, "https://google.com")

	api.WaitForLog(t, "google.com", 20*time.Second)

	all := api.Logs(t, "")
	if len(all) == 0 {
		t.Fatal("dashboard has no log entries")
	}

	t.Logf("%d log entries shipped", len(all))

	assertLogged(t, api.Logs(t, "github.com"), "github.com", "ALLOWED")
	assertLogged(t, api.Logs(t, "google.com"), "google.com", "BLOCKED")

	t.Run("entries carry the fields the UI needs", func(t *testing.T) {
		var haveAction, haveSource, haveFlow, haveProto bool

		for _, e := range all {
			haveAction = haveAction || e.Action != ""
			haveSource = haveSource || e.SourceIP != ""
			haveFlow = haveFlow || e.FlowID != ""
			haveProto = haveProto || e.Protocol == "TCP" || e.Protocol == "UDP"
		}

		if !haveAction || !haveSource || !haveFlow || !haveProto {
			t.Errorf("missing fields: action=%v source_ip=%v flow_id=%v protocol=%v",
				haveAction, haveSource, haveFlow, haveProto)
		}
	})
}

func assertLogged(t *testing.T, entries []harness.LogEntry, host, action string) {
	t.Helper()

	for _, e := range entries {
		if e.Action != action {
			continue
		}

		if strings.Contains(e.HTTPS, host) || strings.Contains(e.HTTPHost, host) ||
			strings.Contains(e.Message, host) || strings.Contains(e.Dst, host) {
			return
		}
	}

	t.Errorf("no %s entry for %s in %d results", action, host, len(entries))
}

func phase06Regex(t *testing.T, s *harness.Stack) {
	t.Run("anchored regex", func(t *testing.T) {
		s.WritePolicyAndWait(t, `allowlist:
  domains:
    - '/^(www\.)?github\.com$/'`)

		s.AssertAllowed(t, "https://github.com")
		s.AssertAllowed(t, "https://www.github.com")
		s.AssertBlocked(t, "https://api.github.com")
		s.AssertBlocked(t, "https://google.com")
	})

	t.Run("mid-name wildcard", func(t *testing.T) {
		s.WritePolicyAndWait(t, `allowlist:
  domains:
    - 'www.*.com'`)

		s.AssertAllowed(t, "https://www.github.com")
		s.AssertBlocked(t, "https://github.com")
		s.AssertBlocked(t, "https://api.github.com")
	})
}

func phase07DefaultAllow(t *testing.T, s *harness.Stack) {
	s.WritePolicyAndWait(t, `default_action: 'allow'
allowlist:
  domains:
    - 'api.github.com'
denylist:
  ips:
    - '1.0.0.1'
  domains:
    - 'github.com'
    - '*.github.com'
    - 'google.com'
    - '*.google.com'`)

	s.AssertAllowed(t, "https://example.com")

	s.AssertBlocked(t, "https://google.com")
	s.AssertBlocked(t, "http://google.com")
	s.AssertBlocked(t, "https://github.com")

	s.AssertAllowed(t, "https://api.github.com")

	s.AssertBlocked(t, "https://1.0.0.1")
}
