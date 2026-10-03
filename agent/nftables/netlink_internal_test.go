package nftables

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	nft "github.com/google/nftables"
)

// rulesetVariants covers every ruleset shape the agent can generate.
func rulesetVariants() map[string]RulesetConfig {
	variants := map[string]RulesetConfig{
		"https empty placeholders": {HTTPSPort: 8443, HTTPPort: 8080, DNSPort: 65053, Mode: "https"},
		"adjacent and top-of-range intervals": {
			AllowV4:     []string{"10.0.0.0/25", "10.0.0.128/25", "10.0.1.0", "10.0.1.1", "128.0.0.0/1"},
			AllowV6:     []string{"fd00::/9", "fd80::/9", "::/1", "ff00::/8"},
			AllowPortV4: []string{"192.0.2.0/25 . tcp . 443", "192.0.2.128/25 . tcp . 443"},
			HTTPSPort:   8443, HTTPPort: 8080, DNSPort: 65053, Mode: "https",
		},
	}

	for _, mode := range []string{"https", "dns", "dns-strict"} {
		for _, defaultAllow := range []bool{false, true} {
			for _, audit := range []bool{false, true} {
				for _, bridge := range [][]string{nil, {"docker0", "br-*"}} {
					name := mode
					if defaultAllow {
						name += " default-allow"
					}

					if audit {
						name += " audit"
					}

					if bridge != nil {
						name += " bridge"
					}

					variants[name] = RulesetConfig{
						AllowV4:          []string{"1.1.1.1", "10.0.0.0/8"},
						AllowV6:          []string{"2001:db8::1", "fd00::/8"},
						AllowPortV4:      []string{"9.9.9.9 . tcp . 853", "192.0.2.0/24 . udp . 53"},
						AllowPortV6:      []string{"2001:db8::9 . tcp . 22"},
						DenyV4:           []string{"6.6.6.6"},
						DenyV6:           []string{"2001:db8::6"},
						HTTPSPort:        8443,
						HTTPPort:         8080,
						DNSPort:          65053,
						Mode:             mode,
						DefaultAllow:     defaultAllow,
						Audit:            audit,
						BridgeInterfaces: bridge,
					}
				}
			}
		}
	}

	return variants
}

func TestEveryGeneratedRulesetCompiles(t *testing.T) {
	t.Parallel()

	for name, cfg := range rulesetVariants() {
		conn, err := nft.New()
		if err != nil {
			t.Fatalf("nft.New: %v", err)
		}

		err = compileRuleset(conn, atomicReplacePreamble+GenerateRuleset(cfg))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// SECURITY: a statement the compiler does not understand must fail the whole
// apply; silently dropping it could turn a drop rule into nothing.
func TestCompilerRejectsUnsupportedSyntax(t *testing.T) {
	t.Parallel()

	chain := func(rule string) string {
		return "table ip t {\n    chain c {\n        type filter hook output priority filter; policy drop;\n        " +
			rule + "\n    }\n}\n"
	}

	tests := map[string]string{
		"unknown match":        chain("ip saddr 1.2.3.4 drop"),
		"trailing token":       chain("drop now"),
		"undeclared set":       chain("ip daddr @missing accept"),
		"wrong address family": chain("ip6 daddr ::1 accept"),
		"syslog log":           chain(`log prefix "x" level warn`),
		"unterminated quote":   chain(`oifname "lo accept`),
		"unknown hook":         "table ip t {\n    chain c {\n        type filter hook ingress priority filter;\n    }\n}\n",
		"unknown set type":     "table ip t {\n    set s {\n        type ether_addr\n    }\n}\n",
		"bad element":          "table ip t {\n    set s {\n        type ipv4_addr\n        elements = {1.2.3}\n    }\n}\n",
		"unclosed table":       "table ip t {\n",
		"unknown family":       "table inet t {\n}\n",
		"elements without interval flag": "table ip t {\n    set s {\n        type ipv4_addr\n" +
			"        elements = {192.0.2.1}\n    }\n}\n",
	}

	for name, ruleset := range tests {
		conn, err := nft.New()
		if err != nil {
			t.Fatalf("nft.New: %v", err)
		}

		err = compileRuleset(conn, ruleset)
		if !errors.Is(err, errRulesetSyntax) {
			t.Errorf("%s: compileRuleset() = %v, want errRulesetSyntax", name, err)
		}
	}
}

// A DNS update queued behind another operation must give up within its own budget.
//
//nolint:paralleltest // holds the process-wide ruleset lock
func TestRulesetLockWaitIsBounded(t *testing.T) {
	rulesetLock <- struct{}{}
	defer func() { <-rulesetLock }()

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	err := AddResolvedIPs(canceled, []string{"192.0.2.1"}, time.Minute, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled update while the lock is held: got %v, want context.Canceled", err)
	}

	start := time.Now()

	err = withRuleset(t.Context(), 50*time.Millisecond, 0, func(*nft.Conn) error {
		t.Error("fn ran without the ruleset lock")

		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait past the budget: got %v, want context.DeadlineExceeded", err)
	}

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("lock wait took %v with a 50ms budget", elapsed)
	}
}

type deadlineRecorder struct {
	mu        sync.Mutex
	deadlines []time.Time
	set       chan struct{}
}

func (r *deadlineRecorder) SetDeadline(deadline time.Time) error {
	r.mu.Lock()
	r.deadlines = append(r.deadlines, deadline)
	r.mu.Unlock()

	r.set <- struct{}{}

	return nil
}

// Regression: setup set the operation deadline after registering the cancellation
// callback, so a cancellation landing in between was overwritten.
func TestWatchDeadlineKeepsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	sock := &deadlineRecorder{set: make(chan struct{}, 2)}

	stop, err := watchDeadline(ctx, sock, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("watchDeadline: %v", err)
	}

	defer stop()

	for range 2 {
		select {
		case <-sock.set:
		case <-time.After(2 * time.Second):
			t.Fatal("the cancellation never reached the socket deadline")
		}
	}

	sock.mu.Lock()
	last := sock.deadlines[len(sock.deadlines)-1]
	sock.mu.Unlock()

	if last.After(time.Now()) {
		t.Errorf("final deadline %v is in the future, so a canceled operation can still complete", last)
	}
}
