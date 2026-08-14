package e2e_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/tests/e2e/internal/harness"
)

func TestPhase08Learning(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.LearningConfig(t, mode))

	s.AssertReachable(t, "https://google.com")

	if mode == harness.FilterModeHTTPS {
		s.AssertReachable(t, "https://1.0.0.1")
	}

	s.AssertPolicyContains(t, "google.com", 30*time.Second)

	if mode == harness.FilterModeHTTPS {
		s.AssertPolicyContains(t, "1.0.0.1", 30*time.Second)
	}

	t.Run("learning does not churn the stack", func(t *testing.T) {
		// The learner rewrites the policy it is watching, so the watcher must be
		// disabled or every observation would trigger a reload.
		events := s.AgentEventsSince(t, harness.LogMark{})

		var disabled, applied bool

		for _, e := range events {
			switch e.Event {
			case "policy.watcher_disabled":
				disabled = true
			case "policy.applied":
				applied = true
			}
		}

		if !disabled {
			t.Error("expected policy.watcher_disabled in learning mode")
		}

		if applied {
			t.Error("learning mode triggered a policy reload")
		}
	})

	s.AssertReachable(t, "https://github.com")
}

func TestPhase09DNSStrict(t *testing.T) {
	t.Parallel()

	if mode := harness.ModeFromEnv(t); mode != harness.FilterModeDNSStrict {
		t.Skipf("dns-strict phase runs in the dns-strict lane (got %s)", mode)
	}

	s := harness.Shared(t, harness.DNSStrictConfig(t))

	s.WritePolicyAndWait(t, `---
allowlist:
  domains:
    - 'github.com'
`)

	t.Run("ruleset is default-deny with a resolved set", func(t *testing.T) {
		s.AssertNFTContains(t, "ip", "g0efilter_v4", "policy drop", "dns-strict chain is default-deny")
		s.AssertNFTContains(t, "ip", "g0efilter_v4", "resolved_allow_v4", "runtime resolved set present")
		s.AssertNFTContains(t, "ip6", "g0efilter_v6", "resolved_allow_v6", "IPv6 runtime resolved set present")
		s.AssertNFTContains(t, "ip", "g0efilter_v4", "flags timeout", "resolved set is TTL-bounded")
	})

	t.Run("resolving an allowed domain opens its addresses", func(t *testing.T) {
		s.AssertAllowed(t, "https://github.com")

		elems := s.NFTSetElements(t, "ip", "g0efilter_v4", "resolved_allow_v4")
		if len(elems) == 0 {
			t.Fatal("resolved_allow_v4 is empty after resolving an allowed domain")
		}

		for _, e := range elems {
			if e.Timeout == 0 {
				t.Errorf("resolved element %s has no timeout; it would never expire", e.Value)
			}
		}

		// Re-resolution exercises replacement of an existing timeout element,
		// rather than only the empty-set insertion path.
		s.AssertAllowed(t, "https://github.com")
	})

	t.Run("an address never resolved through the proxy is dropped", func(t *testing.T) {
		// The decisive dns-strict property: knowing the IP is not enough, because
		// only addresses seen in an allowed DNS answer are in the set.
		mark := s.AgentLogMark(t)

		s.AssertUnreachable(t, "https://1.0.0.1")
		s.AssertIPVerdictSince(t, mark, "BLOCKED", "1.0.0.1", 443, "TCP")
	})

	t.Run("a blocked domain is sinkholed and its address stays out of the set", func(t *testing.T) {
		s.AssertBlocked(t, "https://google.com")
	})

	t.Run("unconstrained IP rules cover UDP without bypassing unknown addresses", func(t *testing.T) {
		s.WritePolicyAndWait(t, `---
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'
`)

		mark := s.AgentLogMark(t)
		s.UDPProbe(t, "1.1.1.1", 443)
		s.AssertIPVerdictSince(t, mark, "ALLOWED", "1.1.1.1", 443, "UDP")

		mark = s.AgentLogMark(t)
		s.UDPProbe(t, "1.0.0.2", 443)
		s.AssertIPVerdictSince(t, mark, "BLOCKED", "1.0.0.2", 443, "UDP")
	})
}

func TestPhase10Audit(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS {
		t.Skipf("audit phase runs once, in the https lane (got %s)", mode)
	}

	s := harness.StartStack(t, harness.AuditConfig(t, mode))

	t.Run("kernel chains fail open", func(t *testing.T) {
		s.AssertNFTLacks(t, "ip", "g0efilter_v4", "policy drop", "audit ruleset must not drop")
	})

	s.AssertAllowed(t, "https://github.com")

	mark := s.AgentLogMark(t)

	s.AssertReachable(t, "https://google.com")
	s.AssertReachable(t, "https://1.0.0.1")

	s.WaitForAgentEvent(t, mark, harness.EventMatcher{Action: "AUDIT"}, 20*time.Second)

	t.Run("audit decisions reach the dashboard", func(t *testing.T) {
		api := s.DashboardAPI(t)
		entries := api.WaitForLog(t, "google.com", 20*time.Second)

		for _, e := range entries {
			if e.Action == "AUDIT" {
				return
			}
		}

		t.Errorf("no AUDIT entry for google.com in %d results", len(entries))
	})
}

func TestPhase13DNSIPAllowlist(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeDNS && mode != harness.FilterModeDNSStrict {
		t.Skipf("dns IP-allowlist phase runs in the dns lanes only (got %s)", mode)
	}

	s := harness.Shared(t, harness.BaselineConfig(t, mode))

	s.WritePolicyAndWait(t, `---
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'
`)

	t.Run("a host pointing at an allow-listed IP resolves and connects", func(t *testing.T) {
		s.AssertAllowed(t, "https://one.one.one.one")
	})

	t.Run("a dual-stack host allow-listed by IPv4 only does not false-alert", func(t *testing.T) {
		// one.one.one.one is dual-stack but only its IPv4 is allow-listed, so the
		// unmatched AAAA must sinkhole silently rather than report a block.
		mark := s.AgentLogMark(t)

		s.AssertReachable(t, "https://one.one.one.one")

		s.AssertNoAgentEvent(t, mark, harness.EventMatcher{
			Event:  "dns.blocked",
			Fields: map[string]string{"qname": "one.one.one.one"},
		}, 3*time.Second)
	})

	t.Run("a host not resolving to an allow-listed IP stays blocked", func(t *testing.T) {
		mark := s.AgentLogMark(t)

		s.AssertBlocked(t, "https://example.com")

		alert := true

		s.WaitForAgentEvent(t, mark, harness.EventMatcher{
			Event:  "dns.blocked",
			Fields: map[string]string{"qname": "example.com"},
			Alert:  &alert,
		}, 15*time.Second)
	})

	t.Run("the allow-listed IP itself still works", func(t *testing.T) {
		if mode == harness.FilterModeDNSStrict {
			s.AssertAllowed(t, "https://1.1.1.1")

			return
		}

		// Plain dns mode accepts direct-IP traffic in the kernel without logging a
		// verdict, so there is nothing to corroborate.
		s.AssertReachable(t, "https://1.1.1.1")
	})

	t.Run("removing the IP allowlist switches the behaviour off", func(t *testing.T) {
		s.WritePolicyAndWait(t, `---
allowlist:
  domains:
    - 'github.com'
`)

		s.AssertBlocked(t, "https://one.one.one.one")
	})
}

// The SO_MARK exempting the agent's own traffic covers only the connection socket,
// so DNS mode used to sinkhole the notification host's lookup and strand every alert.
func TestPhase20Notifications(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	s := harness.StartStack(t, harness.NotifyConfig(t, mode))

	s.WritePolicyAndWait(t, `---
allowlist:
  domains:
    - 'github.com'
`)

	mark := s.AgentLogMark(t)

	s.AssertBlocked(t, "https://example.com")

	t.Run("every service reaches a server the policy does not allow-list", func(t *testing.T) {
		s.WaitForAgentEvent(t, mark, harness.EventMatcher{Event: "notification.sent"}, 30*time.Second)

		harness.Eventually(t, 30*time.Second, time.Second, func() (bool, string) {
			got := s.NotificationsReceived(t)

			// gotify identifies itself by the token it puts in the query.
			gotify := strings.Contains(got, "query=token="+harness.NotifySinkGotifyToken)
			delivered := strings.Count(got, "Blocked ")

			return gotify && delivered >= 2,
				"sink recorded gotify=" + strconv.FormatBool(gotify) +
					" deliveries=" + strconv.Itoa(delivered) + ", got: " + got
		})
	})

	t.Run("no service reports a delivery failure", func(t *testing.T) {
		s.AssertNoAgentEvent(t, mark, harness.EventMatcher{Event: "notification.post_failed"}, 3*time.Second)
		s.AssertNoAgentEvent(t, mark, harness.EventMatcher{Event: "notification.target_failed"}, 3*time.Second)
	})

	t.Run("the notification host resolves instead of being sinkholed", func(t *testing.T) {
		s.AssertNoAgentEvent(t, mark, harness.EventMatcher{
			Event:  "dns.blocked",
			Fields: map[string]string{"qname": "notify-sink"},
		}, 3*time.Second)
	})
}

func TestPhase17PortConstraints(t *testing.T) {
	t.Parallel()

	mode := harness.ModeFromEnv(t)
	if mode != harness.FilterModeHTTPS && mode != harness.FilterModeDNSStrict {
		t.Skipf("port-constraint phase runs in the https and dns-strict lanes (got %s)", mode)
	}

	s := harness.Shared(t, harness.BaselineConfig(t, mode))

	t.Run("IPPortConstraints", func(t *testing.T) { phase17IPConstraints(t, s, mode) })
	t.Run("DomainPortConstraints", func(t *testing.T) {
		if mode != harness.FilterModeDNSStrict {
			t.Skip("domain port constraints require dns-strict")
		}

		phase17DomainConstraints(t, s)
	})
}

func phase17IPConstraints(t *testing.T, s *harness.Stack, mode harness.FilterMode) {
	s.WritePolicyAndWait(t, `---
allowlist:
  ips:
    - 'tcp/1.1.1.0/24:443'
`)

	s.AssertNFTContains(t, "ip", "g0efilter_v4", "allow_daddr_port_v4", "port concat set present")

	elem := s.WaitForNFTSetElement(t, "ip", "g0efilter_v4",
		"allow_daddr_port_v4", "1.1.1.0/24 . tcp . 443")
	t.Logf("constrained element present: %+v", elem)

	mark := s.AgentLogMark(t)

	s.AssertReachable(t, "https://1.1.1.1")
	s.AssertIPVerdictSince(t, mark, "ALLOWED", "1.1.1.1", 443, "TCP")

	if mode == harness.FilterModeHTTPS {
		// HTTPS mode redirects non-exempt HTTP into the host proxy, so the block
		// is corroborated by http.blocked rather than an nflog drop.
		s.AssertBlocked(t, "http://1.1.1.1")
	} else {
		mark = s.AgentLogMark(t)

		s.AssertUnreachable(t, "http://1.1.1.1")
		s.AssertIPVerdictSince(t, mark, "BLOCKED", "1.1.1.1", 80, "TCP")
	}

	if mode == harness.FilterModeDNSStrict {
		t.Run("a hostname resolving to the constrained IP is admitted by DNS", func(t *testing.T) {
			s.AssertAllowed(t, "https://one.one.one.one")
		})
	}

	t.Run("a constrained IPv6 element installs", func(t *testing.T) {
		s.WritePolicyAndWait(t, `---
allowlist:
  ips:
    - 'udp/[2606:4700:4700::1111]:53'
`)

		s.WaitForNFTSetElement(t, "ip6", "g0efilter_v6",
			"allow_daddr_port_v6", "2606:4700:4700::1111 . udp . 53")
	})

	t.Run("a bare IP entry allows every port again", func(t *testing.T) {
		s.WritePolicyAndWait(t, `---
allowlist:
  ips:
    - '1.1.1.1'
`)

		mark := s.AgentLogMark(t)

		s.AssertReachable(t, "http://1.1.1.1")
		s.AssertIPVerdictSince(t, mark, "ALLOWED", "1.1.1.1", 80, "TCP")
	})
}

func phase17DomainConstraints(t *testing.T, s *harness.Stack) {
	s.WritePolicyAndWait(t, `---
allowlist:
  domains:
    - 'tcp/github.com:443'
`)

	s.AssertAllowed(t, "https://github.com")

	resolved := s.AssertUDPDNSAnswer(t, "1.1.1.1", "github.com")
	t.Logf("github.com resolved to %s", resolved)

	s.WaitForNFTSetElement(t, "ip", "g0efilter_v4", "resolved_allow_v4_port", resolved+" . tcp . 443")

	mark := s.AgentLogMark(t)

	s.AssertReachable(t, "https://github.com", "--resolve", "github.com:443:"+resolved)
	s.AssertIPVerdictSince(t, mark, "ALLOWED", resolved, 443, "TCP")

	mark = s.AgentLogMark(t)

	s.AssertUnreachable(t, "http://github.com", "--resolve", "github.com:80:"+resolved)
	s.AssertIPVerdictSince(t, mark, "BLOCKED", resolved, 80, "TCP")

	t.Run("no unconstrained element leaks for a constrained domain", func(t *testing.T) {
		s.AssertNFTSetEmpty(t, "ip", "g0efilter_v4", "resolved_allow_v4")
	})

	t.Run("a udp constraint permits UDP and still drops TCP on that port", func(t *testing.T) {
		s.WritePolicyAndWait(t, `---
allowlist:
  domains:
    - 'udp/one.one.one.one:443'
`)

		resolved := s.AssertUDPDNSAnswer(t, "1.1.1.1", "one.one.one.one")

		mark := s.AgentLogMark(t)

		s.UDPProbe(t, resolved, 443)
		s.AssertIPVerdictSince(t, mark, "ALLOWED", resolved, 443, "UDP")

		mark = s.AgentLogMark(t)

		s.AssertUnreachable(t, "https://"+resolved)
		s.AssertIPVerdictSince(t, mark, "BLOCKED", resolved, 443, "TCP")
	})

	t.Run("an unenforceable constraint is rejected, not silently widened", func(t *testing.T) {
		mark := s.AgentLogMark(t)

		// default_action: allow relaxes the ruleset, so the constraint could not be
		// enforced; the agent must refuse the policy and keep the previous one.
		s.WritePolicy(t, `---
default_action: 'allow'
allowlist:
  domains:
    - 'tcp/github.com:443'
`)

		event := s.WaitForAgentEvent(t, mark,
			harness.EventMatcher{Event: "policy.reload_failed"}, 30*time.Second)

		if !strings.Contains(event.Raw, "unsupported domain port constraint") {
			t.Errorf("reload failed for the wrong reason: %s", event.Raw)
		}
	})
}
