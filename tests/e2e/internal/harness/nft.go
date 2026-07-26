package harness

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const nftWaitTimeout = 15 * time.Second

// NFTText returns the output of an nft command run in the agent container.
func (s *Stack) NFTText(t *testing.T, args ...string) string {
	t.Helper()

	res := s.ExecAgent(t, append([]string{"nft"}, args...)...)
	if res.ExitCode != 0 {
		t.Fatalf("nft %v failed: exit=%d output=%q", args, res.ExitCode, res.Output)
	}

	return res.Output
}

// NFTTable lists one table.
func (s *Stack) NFTTable(t *testing.T, family, table string) string {
	t.Helper()

	return s.NFTText(t, "list", "table", family, table)
}

// AssertNFTContains requires a table to contain a pattern, retrying because a
// policy reload deletes and recreates the tables - a listing taken during that
// window can legitimately miss a set.
func (s *Stack) AssertNFTContains(t *testing.T, family, table, want, describe string) {
	t.Helper()

	Eventually(t, nftWaitTimeout, time.Second, func() (bool, string) {
		res := s.ExecAgent(t, "nft", "list", "table", family, table)

		return res.ExitCode == 0 && strings.Contains(res.Output, want), describe + ": " + want + " not found"
	})
}

// AssertNFTLacks requires a pattern to be absent from a table.
func (s *Stack) AssertNFTLacks(t *testing.T, family, table, unwanted, describe string) {
	t.Helper()

	out := s.NFTTable(t, family, table)
	if strings.Contains(out, unwanted) {
		t.Fatalf("%s: %q should be absent:\n%s", describe, unwanted, out)
	}
}

// AssertNFTTableExists requires a table to be present in the ruleset.
func (s *Stack) AssertNFTTableExists(t *testing.T, table string) {
	t.Helper()

	out := s.NFTText(t, "list", "tables")
	if !strings.Contains(out, table) {
		t.Fatalf("table %s not found in:\n%s", table, out)
	}
}

// NFTSetElement is one decoded element of an nft JSON set listing.
type NFTSetElement struct {
	Value   string
	Timeout int
}

// NFTSetElements decodes a set's elements from nft's JSON output, which is far
// more robust than matching its text rendering. A set that does not exist yet
// reads as empty so callers can poll for one the agent creates asynchronously;
// use AssertNFTSetEmpty when the set is required to be present.
func (s *Stack) NFTSetElements(t *testing.T, family, table, set string) []NFTSetElement {
	t.Helper()

	res := s.ExecAgent(t, "nft", "-j", "list", "set", family, table, set)
	if res.ExitCode != 0 {
		return nil
	}

	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}

	err := json.Unmarshal([]byte(res.Output), &doc)
	if err != nil {
		t.Fatalf("decode nft json for %s: %v (output %q)", set, err, res.Output)
	}

	var out []NFTSetElement

	for _, entry := range doc.Nftables {
		if entry.Set == nil {
			continue
		}

		for _, raw := range entry.Set.Elem {
			out = append(out, decodeSetElement(raw))
		}
	}

	return out
}

// decodeSetElement flattens the shapes nft uses for a set element: a bare
// string, {"elem":{"val":...,"timeout":n}}, or a concatenation of parts.
func decodeSetElement(raw json.RawMessage) NFTSetElement {
	var plain string
	if json.Unmarshal(raw, &plain) == nil {
		return NFTSetElement{Value: plain, Timeout: 0}
	}

	var wrapper struct {
		Elem *struct {
			Val     json.RawMessage `json:"val"`
			Timeout int             `json:"timeout"`
		} `json:"elem"`
	}

	if json.Unmarshal(raw, &wrapper) == nil && wrapper.Elem != nil {
		return NFTSetElement{Value: flattenValue(wrapper.Elem.Val), Timeout: wrapper.Elem.Timeout}
	}

	return NFTSetElement{Value: flattenValue(raw), Timeout: 0}
}

func flattenValue(raw json.RawMessage) string {
	var plain string
	if json.Unmarshal(raw, &plain) == nil {
		return plain
	}

	var concat struct {
		Concat []json.RawMessage `json:"concat"`
	}

	if json.Unmarshal(raw, &concat) == nil && len(concat.Concat) > 0 {
		parts := make([]string, 0, len(concat.Concat))
		for _, part := range concat.Concat {
			parts = append(parts, flattenValue(part))
		}

		return strings.Join(parts, " . ")
	}

	var prefix struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}

	if json.Unmarshal(raw, &prefix) == nil && prefix.Prefix != nil {
		return prefix.Prefix.Addr + "/" + strconv.Itoa(prefix.Prefix.Len)
	}

	var number int
	if json.Unmarshal(raw, &number) == nil {
		return strconv.Itoa(number)
	}

	return strings.Trim(string(raw), `"`)
}

// WaitForNFTSetElement waits for a value to appear in a set, and returns its
// remaining timeout so TTL-bounded entries can be asserted on.
func (s *Stack) WaitForNFTSetElement(t *testing.T, family, table, set, value string) NFTSetElement {
	t.Helper()

	var found NFTSetElement

	Eventually(t, nftWaitTimeout, time.Second, func() (bool, string) {
		elems := s.NFTSetElements(t, family, table, set)
		for _, e := range elems {
			if e.Value == value {
				found = e

				return true, ""
			}
		}

		return false, set + " has no element " + value
	})

	return found
}

// AssertNFTSetEmpty requires a set to exist and hold no elements. The existence
// check matters: a renamed or missing set would otherwise read as empty and pass.
func (s *Stack) AssertNFTSetEmpty(t *testing.T, family, table, set string) {
	t.Helper()

	res := s.ExecAgent(t, "nft", "-j", "list", "set", family, table, set)
	if res.ExitCode != 0 {
		t.Fatalf("listing set %s failed: exit=%d output=%q", set, res.ExitCode, res.Output)
	}

	elems := s.NFTSetElements(t, family, table, set)
	if len(elems) > 0 {
		t.Fatalf("expected %s to be empty, found %d elements: %+v", set, len(elems), elems)
	}
}
