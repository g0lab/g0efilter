package harness

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// BatchRequest describes a concurrent burst of requests.
type BatchRequest struct {
	URL         string
	Count       int
	Concurrency int
	Timeout     time.Duration
	// IPv4Only forces -4. The sandboxes these tests run in often have no IPv6
	// egress, so a dual-stack target otherwise pays curl's fallback delay on
	// every request and a tight timeout turns that into a false failure.
	IPv4Only bool
}

// BatchResult is the outcome of a burst.
type BatchResult struct {
	Attempted  int   `json:"attempted"`
	Succeeded  int   `json:"succeeded"`
	Failed     int   `json:"failed"`
	DurationMS int64 `json:"duration_ms"`
	LatencyMS  struct {
		Median int64 `json:"median"`
		P95    int64 `json:"p95"`
		Max    int64 `json:"max"`
	} `json:"latency_ms"`
}

// MixedBatchRequest describes allowed and blocked requests that start together.
type MixedBatchRequest struct {
	AllowedURL   string
	BlockedURL   string
	AllowedCount int
	BlockedCount int
	Timeout      time.Duration
	IPv4Only     bool
}

// MixedBatchResult is the outcome of a concurrent allowed/blocked workload.
type MixedBatchResult struct {
	AllowedAttempted int `json:"allowed_attempted"`
	AllowedSucceeded int `json:"allowed_succeeded"`
	BlockedAttempted int `json:"blocked_attempted"`
	BlockedSucceeded int `json:"blocked_succeeded"`
}

// RunBatch drives a burst from inside the tester container with a single exec.
// Running one docker exec per request would measure exec overhead rather than
// g0efilter, so the whole workload runs in the container and reports JSON.
func (s *Stack) RunBatch(t *testing.T, req BatchRequest) BatchResult {
	t.Helper()

	if req.Concurrency < 1 {
		req.Concurrency = 1
	}

	ipv4 := ""
	if req.IPv4Only {
		ipv4 = "-4"
	}

	// Each worker writes one line of milliseconds-and-exit-code per request; the
	// shell then reduces them to a JSON summary.
	script := `
set -u
out=$(mktemp -d)
total=` + strconv.Itoa(req.Count) + `
workers=` + strconv.Itoa(req.Concurrency) + `
[ "$workers" -gt "$total" ] && workers=$total
[ "$workers" -lt 1 ] && workers=1
per=$(( total / workers ))
extra=$(( total % workers ))
i=0
while [ $i -lt "$workers" ]; do
  nreq=$per
  [ "$i" -lt "$extra" ] && nreq=$(( nreq + 1 ))
  (
    n=0
    while [ $n -lt "$nreq" ]; do
      # curl reports its own timing; busybox date has no %N.
      t=$(curl ` + ipv4 + ` -sS --max-time ` + strconv.Itoa(curlTimeoutSeconds(req.Timeout)) + ` \
        --connect-timeout 3 -o /dev/null --write-out '%{time_total}' "$1" 2>/dev/null)
      rc=$?
      echo "${t:-0} $rc" >> "$out/w$$"
      n=$(( n + 1 ))
    done
  ) &
  i=$(( i + 1 ))
done
wait
# busybox awk has no asort, so the samples are sorted before the reduction.
cat "$out"/* 2>/dev/null | sort -n -k1 | awk '
  { ms[NR] = $1 * 1000; if ($2 == 0) ok++ }
  END {
    med = (NR > 0) ? ms[int((NR + 1) / 2)] : 0
    p95 = (NR > 0) ? ms[int((NR * 95 + 99) / 100)] : 0
    max = (NR > 0) ? ms[NR] : 0
    printf "{\"attempted\":%d,\"succeeded\":%d,\"failed\":%d,\"latency_ms\":{\"median\":%d,\"p95\":%d,\"max\":%d}}\n",
      NR, ok + 0, NR - (ok + 0), med, p95, max
  }'
rm -rf "$out"
`

	started := time.Now()
	res := s.ExecTester(t, "sh", "-c", script, "load-batch", req.URL)
	elapsed := time.Since(started)

	out := BatchResult{} //nolint:exhaustruct // populated from JSON

	line := lastJSONLine(res.Output)
	if line == "" {
		t.Fatalf("load batch produced no summary: exit=%d output=%q", res.ExitCode, res.Output)
	}

	err := json.Unmarshal([]byte(line), &out)
	if err != nil {
		t.Fatalf("decode batch summary %q: %v", line, err)
	}

	out.DurationMS = elapsed.Milliseconds()

	return out
}

// RunMixedBatch starts allowed and blocked requests together inside the tester.
// It is the load suite's coexistence check: a filter that blocks correctly only
// when no permitted work is competing would fail here.
func (s *Stack) RunMixedBatch(t *testing.T, req MixedBatchRequest) MixedBatchResult {
	t.Helper()

	if req.AllowedCount < 1 {
		t.Fatal("mixed batch requires at least one allowed request")
	}

	if req.BlockedCount < 1 {
		t.Fatal("mixed batch requires at least one blocked request")
	}

	ipv4 := ""
	if req.IPv4Only {
		ipv4 = "-4"
	}

	script := `
set -u
out=$(mktemp -d)
run_group() {
  kind=$1
  count=$2
  url=$3
  i=0
  while [ "$i" -lt "$count" ]; do
    (
      if curl ` + ipv4 + ` -sS --max-time ` + strconv.Itoa(curlTimeoutSeconds(req.Timeout)) + ` \
        --connect-timeout 3 -o /dev/null "$url" 2>/dev/null; then
        : > "$out/$kind.ok.$i"
      fi
      : > "$out/$kind.done.$i"
    ) &
    i=$(( i + 1 ))
  done
}
run_group allowed ` + strconv.Itoa(req.AllowedCount) + ` "$1"
run_group blocked ` + strconv.Itoa(req.BlockedCount) + ` "$2"
wait
count_files() {
  find "$out" -name "$1" -type f 2>/dev/null | wc -l
}
printf '{"allowed_attempted":%d,"allowed_succeeded":%d,"blocked_attempted":%d,"blocked_succeeded":%d}\n' \
  "$(count_files 'allowed.done.*')" "$(count_files 'allowed.ok.*')" \
  "$(count_files 'blocked.done.*')" "$(count_files 'blocked.ok.*')"
rm -rf "$out"
`

	res := s.ExecTester(t, "sh", "-c", script, "mixed-load", req.AllowedURL, req.BlockedURL)

	var out MixedBatchResult

	line := lastJSONLine(res.Output)
	if line == "" {
		t.Fatalf("mixed load batch produced no summary: exit=%d output=%q", res.ExitCode, res.Output)
	}

	err := json.Unmarshal([]byte(line), &out)
	if err != nil {
		t.Fatalf("decode mixed batch summary %q: %v", line, err)
	}

	return out
}

func lastJSONLine(output string) string {
	var last string

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			last = line
		}
	}

	return last
}
