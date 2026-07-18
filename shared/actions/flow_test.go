package actions_test

import (
	"testing"

	"github.com/g0lab/g0efilter/shared/actions"
)

func TestFlowIDConsistency(t *testing.T) {
	t.Parallel()

	got1 := actions.FlowID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")
	got2 := actions.FlowID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")

	if got1 != got2 {
		t.Fatalf("FlowID not deterministic: %q vs %q", got1, got2)
	}

	if len(got1) == 0 {
		t.Fatal("FlowID returned empty string")
	}
}

func TestFlowIDUniqueness(t *testing.T) {
	t.Parallel()

	type flowArgs struct {
		srcIP   string
		srcPort int
		dstIP   string
		dstPort int
		proto   string
	}

	tests := []struct {
		name string
		a    flowArgs
		b    flowArgs
	}{
		{
			"different source port",
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "tcp"},
			flowArgs{"1.1.1.1", 101, "2.2.2.2", 80, "tcp"},
		},
		{
			"different source IP",
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "tcp"},
			flowArgs{"1.1.1.2", 100, "2.2.2.2", 80, "tcp"},
		},
		{
			"different destination IP",
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "tcp"},
			flowArgs{"1.1.1.1", 100, "3.3.3.3", 80, "tcp"},
		},
		{
			"different destination port",
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "tcp"},
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 443, "tcp"},
		},
		{
			"different protocol",
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "tcp"},
			flowArgs{"1.1.1.1", 100, "2.2.2.2", 80, "udp"},
		},
		{
			"IPv4 vs IPv6",
			flowArgs{"192.168.1.1", 100, "10.0.0.1", 80, "tcp"},
			flowArgs{"::1", 100, "::2", 80, "tcp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := actions.FlowID(tt.a.srcIP, tt.a.srcPort, tt.a.dstIP, tt.a.dstPort, tt.a.proto)
			b := actions.FlowID(tt.b.srcIP, tt.b.srcPort, tt.b.dstIP, tt.b.dstPort, tt.b.proto)

			if a == b {
				t.Fatalf("expected different IDs for different inputs, both produced %q", a)
			}
		})
	}
}

func TestFlowIDProtocolCaseInsensitive(t *testing.T) {
	t.Parallel()

	lower := actions.FlowID("1.1.1.1", 100, "2.2.2.2", 80, "tcp")
	upper := actions.FlowID("1.1.1.1", 100, "2.2.2.2", 80, "TCP")
	mixed := actions.FlowID("1.1.1.1", 100, "2.2.2.2", 80, "Tcp")

	if lower != upper || lower != mixed {
		t.Fatalf("FlowID should be case-insensitive for protocol: tcp=%q, TCP=%q, Tcp=%q", lower, upper, mixed)
	}
}

func TestMarkSyntheticAndIsSyntheticRecent(t *testing.T) {
	t.Parallel()

	flowID := actions.FlowID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")

	if actions.IsSyntheticRecent(flowID) {
		t.Fatal("new flow should not be synthetic before marking")
	}

	actions.MarkSynthetic(flowID)

	if !actions.IsSyntheticRecent(flowID) {
		t.Fatal("flow should be synthetic immediately after marking")
	}
}

func TestIsSyntheticRecentUnmarkedFlow(t *testing.T) {
	t.Parallel()

	// Use a flow that has definitely never been marked
	flowID := actions.FlowID("99.99.99.99", 55555, "88.88.88.88", 44444, "udp")

	if actions.IsSyntheticRecent(flowID) {
		t.Fatal("unmarked flow should not be synthetic recent")
	}
}

func TestMarkSyntheticEmptyFlowID(t *testing.T) {
	t.Parallel()

	// Must not panic
	actions.MarkSynthetic("")
}

func TestIsSyntheticRecentEmptyFlowID(t *testing.T) {
	t.Parallel()

	if actions.IsSyntheticRecent("") {
		t.Fatal("empty flowID should not be synthetic recent")
	}
}

func TestMarkSyntheticIdempotent(t *testing.T) {
	t.Parallel()

	flowID := actions.FlowID("10.10.10.10", 1111, "20.20.20.20", 2222, "tcp")

	actions.MarkSynthetic(flowID)
	actions.MarkSynthetic(flowID)
	actions.MarkSynthetic(flowID)

	if !actions.IsSyntheticRecent(flowID) {
		t.Fatal("flow should be synthetic after multiple marks")
	}
}
