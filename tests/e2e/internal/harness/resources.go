package harness

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// MemoryBytes reads the agent's current memory use from its cgroup, trying v2
// then v1.
func (s *Stack) MemoryBytes(t *testing.T) int64 {
	t.Helper()

	res := s.ExecAgent(t, "sh", "-c",
		"if [ -r /sys/fs/cgroup/memory.current ]; then cat /sys/fs/cgroup/memory.current; "+
			"elif [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then "+
			"cat /sys/fs/cgroup/memory/memory.usage_in_bytes; else exit 2; fi")
	if res.ExitCode != 0 {
		t.Fatalf("could not read agent memory from cgroup: exit=%d output=%q", res.ExitCode, res.Output)
	}

	return parseCgroupValue(t, res.Output, "memory")
}

// cpuUsageNanos reads cumulative CPU time from the agent's cgroup.
func (s *Stack) cpuUsageNanos(t *testing.T) int64 {
	t.Helper()

	res := s.ExecAgent(t, "sh", "-c",
		"if [ -r /sys/fs/cgroup/cpu.stat ]; then "+
			"awk '/^usage_usec/ { print $2 * 1000; found=1 } END { exit !found }' /sys/fs/cgroup/cpu.stat; "+
			"elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then cat /sys/fs/cgroup/cpuacct/cpuacct.usage; "+
			"else exit 2; fi")
	if res.ExitCode != 0 {
		t.Fatalf("could not read agent CPU from cgroup: exit=%d output=%q", res.ExitCode, res.Output)
	}

	return parseCgroupValue(t, res.Output, "cpu")
}

// IdleCPUPercent samples CPU use over a window, as a percentage of one core.
func (s *Stack) IdleCPUPercent(t *testing.T, window time.Duration) float64 {
	t.Helper()

	startCPU := s.cpuUsageNanos(t)
	startWall := time.Now()

	time.Sleep(window)

	endCPU := s.cpuUsageNanos(t)
	elapsed := time.Since(startWall)

	if elapsed <= 0 {
		t.Fatal("non-positive sampling window")
	}

	return float64(endCPU-startCPU) / float64(elapsed.Nanoseconds()) * 100
}

// AgentHealth reports whether the agent is still running and how many times it
// has restarted. A crash loop leaves traffic assertions passing, so load and
// resource phases check it explicitly.
func (s *Stack) AgentHealth(t *testing.T) (bool, int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := s.Agent.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect agent: %v", err)
	}

	return info.State.Running, info.RestartCount
}

// parseCgroupValue reads the last non-empty line as a single integer. Taking the
// last line (rather than merging every digit in the output) keeps a stray warning
// from silently fabricating a value.
func parseCgroupValue(t *testing.T, out, what string) int64 {
	t.Helper()

	var last string

	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) != "" {
			last = strings.TrimSpace(line)
		}
	}

	if last == "" {
		t.Fatalf("no %s value in cgroup output %q", what, out)
	}

	n, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		t.Fatalf("parse %s value %q from cgroup output %q: %v", what, last, out, err)
	}

	return n
}

// MiB converts bytes to mebibytes, rounding up.
func MiB(bytes int64) int64 {
	const mib = 1024 * 1024

	return (bytes + mib - 1) / mib
}
