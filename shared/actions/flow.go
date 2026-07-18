package actions

import (
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"
)

//nolint:gochecknoglobals
var recentSynthetic = struct {
	m      map[string]time.Time
	mutex  sync.Mutex
	writes int
}{m: make(map[string]time.Time)}

// suppressWindow is how long to suppress kernel nflog events after seeing a synthetic redirect.
const suppressWindow = 5 * time.Second

// pruneInterval controls how many writes between prune sweeps.
const pruneInterval = 64

// FlowID generates a deterministic hash identifier for a network flow using source, destination, and protocol.
func FlowID(sourceIP string, sourcePort int, destinationIP string, destinationPort int, proto string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(sourceIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(sourcePort)))
	_, _ = hasher.Write([]byte("->"))
	_, _ = hasher.Write([]byte(destinationIP))
	_, _ = hasher.Write([]byte(":"))
	_, _ = hasher.Write([]byte(strconv.Itoa(destinationPort)))
	_, _ = hasher.Write([]byte("|"))
	_, _ = hasher.Write([]byte(strings.ToUpper(proto)))

	return strconv.FormatUint(hasher.Sum64(), 16)
}

// MarkSynthetic records that a synthetic log event was emitted for this flow to prevent duplicate nflog events.
func MarkSynthetic(flowID string) {
	if flowID == "" {
		return
	}

	recentSynthetic.mutex.Lock()
	defer recentSynthetic.mutex.Unlock()

	recentSynthetic.m[flowID] = time.Now()
	recentSynthetic.writes++

	if recentSynthetic.writes >= pruneInterval {
		recentSynthetic.writes = 0

		cutoff := time.Now().Add(-suppressWindow * 4)
		for k, v := range recentSynthetic.m {
			if v.Before(cutoff) {
				delete(recentSynthetic.m, k)
			}
		}
	}
}

// IsSyntheticRecent returns true if a synthetic log was emitted for this flow within the suppress window.
func IsSyntheticRecent(flowID string) bool {
	if flowID == "" {
		return false
	}

	recentSynthetic.mutex.Lock()
	defer recentSynthetic.mutex.Unlock()

	if lastTime, ok := recentSynthetic.m[flowID]; ok {
		return time.Since(lastTime) <= suppressWindow
	}

	return false
}
