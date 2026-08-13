package harness

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// decisionLogPath matches DECISION_LOG_FILE in compose.test.yaml.
const decisionLogPath = "/tmp/decisions.jsonl"

// DecisionRecords reads the agent's JSON Lines decision log. A record that does
// not parse fails the test: the file is a machine-readable audit trail, so a
// malformed line is a defect rather than something to skip over.
func (s *Stack) DecisionRecords(t *testing.T) []map[string]any {
	t.Helper()

	result := s.ExecAgent(t, "cat", decisionLogPath)
	if result.ExitCode != 0 {
		return nil
	}

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(result.Output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var record map[string]any

		err := json.Unmarshal([]byte(line), &record)
		if err != nil {
			t.Fatalf("decision log line is not JSON: %v\n%s", err, line)
		}

		records = append(records, record)
	}

	return records
}

// WaitForDecisionRecord blocks until a decision record matches, and returns it.
func (s *Stack) WaitForDecisionRecord(
	t *testing.T, match func(map[string]any) bool, timeout time.Duration,
) map[string]any {
	t.Helper()

	var found map[string]any

	seen := 0

	Eventually(t, timeout, 500*time.Millisecond, func() (bool, string) {
		records := s.DecisionRecords(t)
		seen = len(records)

		for _, record := range records {
			if match(record) {
				found = record

				return true, ""
			}
		}

		return false, "no matching decision record in " + decisionLogPath
	})

	t.Logf("matched a decision record after scanning %d records", seen)

	return found
}
