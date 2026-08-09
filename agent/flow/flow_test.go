package flow_test

import (
	"testing"

	"github.com/g0lab/g0efilter/agent/flow"
)

func TestIDConsistency(t *testing.T) {
	t.Parallel()

	got1 := flow.ID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")
	got2 := flow.ID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")

	if got1 != got2 {
		t.Fatalf("ID not deterministic: %q vs %q", got1, got2)
	}

	if len(got1) == 0 {
		t.Fatal("ID returned empty string")
	}
}

func TestIDUniqueness(t *testing.T) {
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

			a := flow.ID(tt.a.srcIP, tt.a.srcPort, tt.a.dstIP, tt.a.dstPort, tt.a.proto)
			b := flow.ID(tt.b.srcIP, tt.b.srcPort, tt.b.dstIP, tt.b.dstPort, tt.b.proto)

			if a == b {
				t.Fatalf("expected different IDs for different inputs, both produced %q", a)
			}
		})
	}
}

func TestIDProtocolCaseInsensitive(t *testing.T) {
	t.Parallel()

	lower := flow.ID("1.1.1.1", 100, "2.2.2.2", 80, "tcp")
	upper := flow.ID("1.1.1.1", 100, "2.2.2.2", 80, "TCP")
	mixed := flow.ID("1.1.1.1", 100, "2.2.2.2", 80, "Tcp")

	if lower != upper || lower != mixed {
		t.Fatalf("ID should be case-insensitive for protocol: tcp=%q, TCP=%q, Tcp=%q", lower, upper, mixed)
	}
}

func TestMarkSyntheticAndIsSyntheticRecent(t *testing.T) {
	t.Parallel()

	flowID := flow.ID("192.168.1.1", 12345, "10.0.0.1", 80, "tcp")

	if flow.IsSyntheticRecent(flowID) {
		t.Fatal("new flow should not be synthetic before marking")
	}

	flow.MarkSynthetic(flowID)

	if !flow.IsSyntheticRecent(flowID) {
		t.Fatal("flow should be synthetic immediately after marking")
	}
}

func TestIsSyntheticRecentUnmarkedFlow(t *testing.T) {
	t.Parallel()

	flowID := flow.ID("99.99.99.99", 55555, "88.88.88.88", 44444, "udp")

	if flow.IsSyntheticRecent(flowID) {
		t.Fatal("unmarked flow should not be synthetic recent")
	}
}

func TestMarkSyntheticEmptyFlowID(t *testing.T) {
	t.Parallel()

	flow.MarkSynthetic("")
}

func TestIsSyntheticRecentEmptyFlowID(t *testing.T) {
	t.Parallel()

	if flow.IsSyntheticRecent("") {
		t.Fatal("empty flowID should not be synthetic recent")
	}
}

func TestMarkSyntheticIdempotent(t *testing.T) {
	t.Parallel()

	flowID := flow.ID("10.10.10.10", 1111, "20.20.20.20", 2222, "tcp")

	flow.MarkSynthetic(flowID)
	flow.MarkSynthetic(flowID)
	flow.MarkSynthetic(flowID)

	if !flow.IsSyntheticRecent(flowID) {
		t.Fatal("flow should be synthetic after multiple marks")
	}
}
