//nolint:paralleltest // every kernel test owns the namespace's whole ruleset
package nftables

import (
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

// Kernel tests program nftables for real, so they only run when asked, inside a
// throwaway network namespace: scripts/test-kernel.sh.
func requireKernel(t *testing.T) {
	t.Helper()

	if os.Getenv("G0EFILTER_KERNEL_TESTS") != "1" {
		t.Skip("set G0EFILTER_KERNEL_TESTS=1 in a disposable network namespace (scripts/test-kernel.sh)")
	}
}

func run(t *testing.T, stdin, name string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), name, args...) //nolint:gosec // args are test literals
	cmd.Stdin = strings.NewReader(stdin)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}

	return string(out)
}

func nftCLI(t *testing.T, stdin string, args ...string) string {
	t.Helper()

	return run(t, stdin, "nft", args...)
}

func applyForTest(t *testing.T, cfg RulesetConfig) {
	t.Helper()

	err := applyRuleset(t.Context(), atomicReplacePreamble+GenerateRuleset(cfg))
	if err != nil {
		t.Fatalf("applyRuleset: %v", err)
	}
}

// kernelState is the ruleset as nft decodes it, with set contents reduced to the
// ranges they admit so equivalent encodings compare equal.
func kernelState(t *testing.T) string {
	t.Helper()

	var listing struct {
		Nftables []map[string]map[string]any `json:"nftables"`
	}

	err := json.Unmarshal([]byte(nftCLI(t, "", "-j", "list", "ruleset")), &listing)
	if err != nil {
		t.Fatalf("decode ruleset: %v", err)
	}

	var objects []string

	for _, item := range listing.Nftables {
		for kind, object := range item {
			if kind == "metainfo" {
				continue
			}

			delete(object, "handle")

			if elements, ok := object["elem"].([]any); ok {
				object["elem"] = admittedRanges(t, elements)
			}

			encoded, err := json.Marshal(map[string]any{kind: object})
			if err != nil {
				t.Fatalf("encode %s: %v", kind, err)
			}

			objects = append(objects, string(encoded))
		}
	}

	return strings.Join(objects, "\n")
}

// admittedRanges merges set elements into sorted "fields|first-last" ranges.
func admittedRanges(t *testing.T, elements []any) []string {
	t.Helper()

	spans := make([]span, 0, len(elements))

	for _, element := range elements {
		fields := []any{element}
		if object, ok := element.(map[string]any); ok && object["concat"] != nil {
			fields, _ = object["concat"].([]any)
		}

		first, last := elementRange(t, fields[0])
		spans = append(spans, span{first: first, last: last, tail: fmt.Append(nil, fields[1:]...)})
	}

	ranges := make([]string, 0, len(spans))

	for _, merged := range unionSpans(spans) {
		ranges = append(ranges, fmt.Sprintf("%s|%s-%s", merged.tail, merged.first, merged.last))
	}

	return ranges
}

// unionSpans merges overlapping and adjacent spans that share a tail. It is kept
// apart from the compiler's own merge so the parity tests check it independently.
func unionSpans(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int {
		return cmp.Or(slices.Compare(a.tail, b.tail), a.first.Compare(b.first))
	})

	var merged []span

	for _, next := range spans {
		last := len(merged) - 1
		if last >= 0 && slices.Equal(merged[last].tail, next.tail) &&
			(!merged[last].last.Next().IsValid() || next.first.Compare(merged[last].last.Next()) <= 0) {
			if next.last.Compare(merged[last].last) > 0 {
				merged[last].last = next.last
			}

			continue
		}

		merged = append(merged, next)
	}

	return merged
}

func elementRange(t *testing.T, field any) (netip.Addr, netip.Addr) {
	t.Helper()

	entry := fmt.Sprint(field)

	if object, ok := field.(map[string]any); ok {
		if prefix, ok := object["prefix"].(map[string]any); ok {
			entry = fmt.Sprintf("%v/%v", prefix["addr"], prefix["len"])
		}

		if bounds, ok := object["range"].([]any); ok {
			first, firstErr := netip.ParseAddr(fmt.Sprint(bounds[0]))
			last, lastErr := netip.ParseAddr(fmt.Sprint(bounds[1]))

			if firstErr != nil || lastErr != nil {
				t.Fatalf("set range %v", bounds)
			}

			return first, last
		}
	}

	first, last, err := addrRange(entry)
	if err != nil {
		t.Fatalf("set element %v: %v", field, err)
	}

	return first, last
}

// The nft CLI is the reference: the kernel must admit exactly what it would install.
func TestKernelRulesetMatchesNftCLI(t *testing.T) {
	requireKernel(t)

	for name, cfg := range rulesetVariants() {
		ruleset := atomicReplacePreamble + GenerateRuleset(cfg)

		nftCLI(t, "", "flush", "ruleset")
		nftCLI(t, ruleset, "-f", "-")
		want := kernelState(t)

		nftCLI(t, "", "flush", "ruleset")

		err := applyRuleset(t.Context(), ruleset)
		if err != nil {
			t.Fatalf("%s: applyRuleset: %v", name, err)
		}

		if got := kernelState(t); got != want {
			t.Errorf("%s: kernel state differs from nft -f\n--- nft -f\n%s\n--- netlink\n%s", name, want, got)
		}
	}
}

// Random policies reach what the fixed variants cannot: overlapping, adjacent,
// duplicate and host-bit entries, which nft -f only accepts once merged into ranges.
func TestKernelRandomRulesetsMatchNftCLI(t *testing.T) {
	requireKernel(t)

	seed := uint64(time.Now().UnixNano())
	rounds := 50

	fixedSeed, err := strconv.ParseUint(os.Getenv("G0EFILTER_PARITY_SEED"), 10, 64)
	if err == nil {
		seed = fixedSeed
	}

	fixedRounds, err := strconv.Atoi(os.Getenv("G0EFILTER_PARITY_ROUNDS"))
	if err == nil {
		rounds = fixedRounds
	}

	rng := rand.New(rand.NewPCG(seed, 0)) //nolint:gosec // reproducible test inputs

	for round := range rounds {
		cfg := randomRulesetConfig(rng)

		nftCLI(t, "", "flush", "ruleset")
		nftCLI(t, atomicReplacePreamble+GenerateRuleset(mergedForNft(t, cfg)), "-f", "-")
		want := kernelState(t)

		nftCLI(t, "", "flush", "ruleset")
		applyForTest(t, cfg)

		if got := kernelState(t); got != want {
			t.Fatalf("round %d, G0EFILTER_PARITY_SEED=%d: kernel state differs from nft -f\nconfig %+v"+
				"\n--- nft -f\n%s\n--- netlink\n%s", round, seed, cfg, want, got)
		}
	}
}

func randomRulesetConfig(rng *rand.Rand) RulesetConfig {
	ports := map[int]bool{}
	for len(ports) < 3 {
		ports[1024+rng.IntN(64512)] = true
	}

	distinct := slices.Collect(maps.Keys(ports))

	cfg := RulesetConfig{
		AllowV4:      randomEntries(rng, randomV4),
		AllowV6:      randomEntries(rng, randomV6),
		DenyV4:       randomEntries(rng, randomV4),
		DenyV6:       randomEntries(rng, randomV6),
		HTTPSPort:    distinct[0],
		HTTPPort:     distinct[1],
		DNSPort:      distinct[2],
		Mode:         []string{"https", "dns", "dns-strict"}[rng.IntN(3)],
		DefaultAllow: rng.IntN(2) == 0,
		Audit:        rng.IntN(4) == 0,
	}

	if rng.IntN(3) == 0 {
		names := []string{"docker0", "br-*", "cni0", "veth*"}
		cfg.BridgeInterfaces = names[:1+rng.IntN(len(names))]
	}

	// Mirrors classifyAllow, which rejects constraints the mode cannot enforce.
	if !cfg.DefaultAllow && cfg.Mode != "dns" {
		cfg.AllowPortV4 = randomEntries(rng, func(rng *rand.Rand) string { return randomV4(rng) + randomPort(rng) })
		cfg.AllowPortV6 = randomEntries(rng, func(rng *rand.Rand) string { return randomV6(rng) + randomPort(rng) })
	}

	return cfg
}

func randomEntries(rng *rand.Rand, entry func(*rand.Rand) string) []string {
	if rng.IntN(4) == 0 {
		return nil
	}

	entries := make([]string, 1+rng.IntN(30))
	for i := range entries {
		entries[i] = entry(rng)
	}

	return entries
}

// randomV4 draws from a narrow pool so overlaps and adjacency are common, and keeps
// host bits in prefixes because policy validation allows them.
func randomV4(rng *rand.Rand) string {
	if rng.IntN(8) == 0 {
		edges := []string{"0.0.0.0", "255.255.255.255", "0.0.0.0/1", "128.0.0.0/1", "255.255.255.0/24", "0.0.0.0/0"}

		return edges[rng.IntN(len(edges))]
	}

	var raw [4]byte

	binary.BigEndian.PutUint32(raw[:], 0x0a000000|rng.Uint32N(1024))

	addr := netip.AddrFrom4(raw)
	if rng.IntN(2) == 0 {
		return addr.String()
	}

	return netip.PrefixFrom(addr, 16+rng.IntN(17)).String()
}

func randomV6(rng *rand.Rand) string {
	if rng.IntN(8) == 0 {
		edges := []string{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/1", "8000::/1", "ff00::/8", "::/0"}

		return edges[rng.IntN(len(edges))]
	}

	raw := [16]byte{0: 0xfd}

	binary.BigEndian.PutUint32(raw[12:], rng.Uint32N(1024))

	addr := netip.AddrFrom16(raw)
	if rng.IntN(2) == 0 {
		return addr.String()
	}

	return netip.PrefixFrom(addr, 104+rng.IntN(25)).String()
}

func randomPort(rng *rand.Rand) string {
	return fmt.Sprintf(" . %s . %d", []string{"tcp", "udp"}[rng.IntN(2)], []int{1, 22, 53, 443, 65535}[rng.IntN(5)])
}

// mergedForNft rewrites every set as the disjoint ranges nft -f accepts.
func mergedForNft(t *testing.T, cfg RulesetConfig) RulesetConfig {
	t.Helper()

	for _, entries := range []*[]string{
		&cfg.AllowV4, &cfg.AllowV6, &cfg.AllowPortV4, &cfg.AllowPortV6, &cfg.DenyV4, &cfg.DenyV6,
	} {
		*entries = nftRanges(t, *entries)
	}

	return cfg
}

func nftRanges(t *testing.T, entries []string) []string {
	t.Helper()

	spans := make([]span, 0, len(entries))

	for _, entry := range entries {
		addr, tail, _ := strings.Cut(entry, " . ")

		first, last, err := addrRange(addr)
		if err != nil {
			t.Fatalf("entry %q: %v", entry, err)
		}

		spans = append(spans, span{first: first, last: last, tail: []byte(tail)})
	}

	ranges := make([]string, 0, len(spans))

	for _, merged := range unionSpans(spans) {
		element := merged.first.String()
		if merged.first != merged.last {
			element += "-" + merged.last.String()
		}

		if len(merged.tail) > 0 {
			element += " . " + string(merged.tail)
		}

		ranges = append(ranges, element)
	}

	return ranges
}

// trafficNet routes the documentation prefixes to a dummy interface, where an
// accepted packet vanishes and one dropped on output fails the send with EPERM.
func trafficNet(t *testing.T) {
	t.Helper()

	run(t, "", "sh", "-c", `ip link show g0test >/dev/null 2>&1 && exit 0
		ip link add g0test type dummy && ip link set g0test up &&
		ip addr add 198.51.100.1/24 dev g0test && ip route add 192.0.2.0/24 dev g0test &&
		ip addr add 2001:db8:1::1/64 dev g0test nodad && ip route add 2001:db8::/64 dev g0test`)
}

func expectTraffic(t *testing.T, ip string, port int, allowed bool) {
	t.Helper()

	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "udp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}

	_, err = conn.Write([]byte("probe"))
	_ = conn.Close()

	switch {
	case allowed && err != nil:
		t.Errorf("udp %s was blocked: %v", addr, err)
	case !allowed && !errors.Is(err, syscall.EPERM):
		t.Errorf("udp %s was not dropped (err %v)", addr, err)
	}
}

func httpsPolicy(allowV4 ...string) RulesetConfig {
	return RulesetConfig{
		AllowV4:     allowV4,
		AllowV6:     []string{"2001:db8::10"},
		AllowPortV4: []string{"192.0.2.20 . udp . 53"},
		HTTPSPort:   18443,
		HTTPPort:    18080,
		DNSPort:     65053,
		Mode:        "https",
	}
}

func TestKernelTrafficFollowsPolicy(t *testing.T) {
	requireKernel(t)
	trafficNet(t)
	applyForTest(t, httpsPolicy("192.0.2.10"))

	expectTraffic(t, "192.0.2.10", 9, true)
	expectTraffic(t, "192.0.2.99", 9, false)
	expectTraffic(t, "192.0.2.20", 53, true)
	expectTraffic(t, "192.0.2.20", 54, false)
	expectTraffic(t, "2001:db8::10", 9, true)
	expectTraffic(t, "2001:db8::99", 9, false)

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:18443")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", "192.0.2.99:443")
	if err != nil {
		t.Fatalf("https to an unlisted address was not redirected to the proxy: %v", err)
	}

	_ = conn.Close()
}

func TestKernelRejectedReplacementKeepsThePreviousPolicy(t *testing.T) {
	requireKernel(t)
	trafficNet(t)
	applyForTest(t, httpsPolicy("192.0.2.10"))

	broken := atomicReplacePreamble + GenerateRuleset(httpsPolicy("192.0.2.99")) +
		"table ip g0efilter_broken {\n    chain c {\n        jump missing\n    }\n}\n"

	err := applyRuleset(t.Context(), broken)
	if err == nil {
		t.Fatal("the kernel accepted a jump to a missing chain")
	}

	expectTraffic(t, "192.0.2.10", 9, true)
	expectTraffic(t, "192.0.2.99", 9, false)
}

func TestKernelReloadReplacesEveryManagedTable(t *testing.T) {
	requireKernel(t)
	nftCLI(t, "", "flush", "ruleset")

	applyForTest(t, rulesetVariants()["dns-strict bridge"])
	applyForTest(t, httpsPolicy("203.0.113.9"))

	listing := nftCLI(t, "", "list", "ruleset")

	for _, stale := range []string{"g0efilter_bridge", "resolved_allow", "10.0.0.0/8", "9.9.9.9"} {
		if strings.Contains(listing, stale) {
			t.Errorf("reload left %q behind:\n%s", stale, listing)
		}
	}
}

// nft -f rejects overlapping intervals; the agent merges them so such a policy applies.
func TestKernelOverlappingAllowEntriesApply(t *testing.T) {
	requireKernel(t)
	trafficNet(t)

	cfg := httpsPolicy("192.0.2.10", "192.0.2.0/28", "192.0.2.8/29")
	cfg.AllowPortV4 = []string{"192.0.2.40 . udp . 53", "192.0.2.32/29 . udp . 53"}
	applyForTest(t, cfg)

	expectTraffic(t, "192.0.2.15", 9, true)
	expectTraffic(t, "192.0.2.16", 9, false)
	expectTraffic(t, "192.0.2.33", 53, true)
	expectTraffic(t, "192.0.2.40", 54, false)
}

// Large sets exceed netlink's 16-bit attribute length and the default socket buffers.
func TestKernelLargePolicyApplies(t *testing.T) {
	requireKernel(t)
	trafficNet(t)

	cfg := httpsPolicy()
	for i := range 20000 {
		cfg.AllowV4 = append(cfg.AllowV4, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		cfg.AllowPortV4 = append(cfg.AllowPortV4, fmt.Sprintf("172.16.%d.%d . tcp . 443", i/256, i%256))
	}

	cfg.AllowV4 = append(cfg.AllowV4, "192.0.2.10")
	applyForTest(t, cfg)

	expectTraffic(t, "192.0.2.10", 9, true)
	expectTraffic(t, "192.0.2.11", 9, false)
}

func strictPolicy(t *testing.T) {
	t.Helper()
	t.Setenv("BRIDGE_INTERFACES", "docker0")
	trafficNet(t)
	applyForTest(t, rulesetVariants()["dns-strict bridge"])
}

type resolvedSet struct{ family, table, set string }

func resolvedSets() []resolvedSet {
	sets := make([]resolvedSet, 0, 8)

	for _, prefix := range []string{"g0efilter", "g0efilter_bridge"} {
		sets = append(sets,
			resolvedSet{"ip", prefix + "_v4", "resolved_allow_v4"},
			resolvedSet{"ip", prefix + "_v4", "resolved_allow_v4_port"},
			resolvedSet{"ip6", prefix + "_v6", "resolved_allow_v6"},
			resolvedSet{"ip6", prefix + "_v6", "resolved_allow_v6_port"},
		)
	}

	return sets
}

// expiries maps each element of a resolved set to its remaining lifetime.
func (s resolvedSet) expiries(t *testing.T) []time.Duration {
	t.Helper()

	var listing struct {
		Nftables []struct {
			Set *struct {
				Elem []struct {
					Elem struct {
						Expires int `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}

	err := json.Unmarshal([]byte(nftCLI(t, "", "-j", "list", "set", s.family, s.table, s.set)), &listing)
	if err != nil {
		t.Fatalf("decode %s: %v", s.set, err)
	}

	var out []time.Duration

	for _, item := range listing.Nftables {
		if item.Set != nil {
			for _, elem := range item.Set.Elem {
				out = append(out, time.Duration(elem.Elem.Expires)*time.Second)
			}
		}
	}

	return out
}

func TestKernelResolvedIPsFollowTheLatestDNSAnswer(t *testing.T) {
	requireKernel(t)
	strictPolicy(t)

	ips := []string{"192.0.2.30", "2001:db8::30"}
	mdns := []policy.DomainRule{{Proto: policy.ProtoUDP, Port: 5353}}

	expectTraffic(t, "192.0.2.30", 5353, false)

	answer := func(ttl time.Duration) {
		t.Helper()

		err := errors.Join(AddResolvedIPs(t.Context(), ips, ttl, nil), AddResolvedIPs(t.Context(), ips, ttl, mdns))
		if err != nil {
			t.Fatalf("AddResolvedIPs: %v", err)
		}
	}

	check := func(minimum, maximum time.Duration) {
		t.Helper()

		for _, s := range resolvedSets() {
			got := s.expiries(t)
			if len(got) != 1 || got[0] < minimum || got[0] > maximum {
				t.Errorf("%s %s expiries %v, want one in %v-%v", s.table, s.set, got, minimum, maximum)
			}
		}
	}

	answer(10 * time.Minute)
	check(9*time.Minute, 10*time.Minute)
	expectTraffic(t, "192.0.2.30", 5353, true)
	expectTraffic(t, "2001:db8::30", 9, true)

	// A shorter answer for live entries must reset their timers, not keep the longer one.
	answer(time.Minute)
	check(50*time.Second, time.Minute)
}

// One DNS answer can carry thousands of records; all must land in every set.
func TestKernelLargeDNSAnswerFillsEverySet(t *testing.T) {
	requireKernel(t)
	strictPolicy(t)

	ips := make([]string, 0, 5100)
	for i := range 4000 {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}

	for i := range 1000 {
		ips = append(ips, fmt.Sprintf("2001:db8::%x", i+1))
	}

	ips = append(ips, ips[:100]...)
	rules := []policy.DomainRule{{}, {Proto: policy.ProtoTCP, Port: 443}, {Proto: policy.ProtoUDP, Port: 53}}

	err := AddResolvedIPs(t.Context(), ips, time.Minute, rules)
	if err != nil {
		t.Fatalf("AddResolvedIPs: %v", err)
	}

	want := map[string]int{
		"resolved_allow_v4": 4000, "resolved_allow_v4_port": 8000,
		"resolved_allow_v6": 1000, "resolved_allow_v6_port": 2000,
	}

	for _, s := range resolvedSets() {
		if got := len(s.expiries(t)); got != want[s.set] {
			t.Errorf("%s %s holds %d elements, want %d", s.table, s.set, got, want[s.set])
		}
	}
}

func TestKernelCanceledUpdateChangesNothing(t *testing.T) {
	requireKernel(t)
	strictPolicy(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := AddResolvedIPs(ctx, []string{"192.0.2.30"}, time.Minute, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("AddResolvedIPs() = %v, want context.Canceled", err)
	}

	expectTraffic(t, "192.0.2.30", 9, false)
}

// A DNS handler that outlives its service's shutdown must not authorize anything
// under the policy that replaced it, however its updates interleave with the apply.
func TestKernelRetiredServiceCannotAuthorizeUnderReplacement(t *testing.T) {
	requireKernel(t)
	strictPolicy(t)

	for range 100 {
		retireDuringUpdates(t)
	}

	expectTraffic(t, "192.0.2.30", 9, false)
}

func retireDuringUpdates(t *testing.T) {
	t.Helper()

	retired, retire := context.WithCancel(t.Context())
	committed := make(chan struct{}, 4)
	failed := make(chan error, 1)

	var wg sync.WaitGroup

	defer wg.Wait()
	defer retire()

	for range 4 {
		wg.Go(func() { updateUntilRetired(retired, committed, failed) })
	}

	timeout := time.After(10 * time.Second)

	for range 4 {
		select {
		case <-committed:
		case err := <-failed:
			t.Fatalf("AddResolvedIPs before retirement: %v", err)
		case <-timeout:
			t.Fatal("four DNS updates did not commit within 10s")
		}
	}

	retire()
	applyForTest(t, rulesetVariants()["dns-strict bridge"])
	wg.Wait()

	for _, s := range resolvedSets() {
		if got := s.expiries(t); len(got) != 0 {
			t.Fatalf("a retired service authorized %d elements in %s %s", len(got), s.table, s.set)
		}
	}
}

// updateUntilRetired reports each commit, and any failure retirement does not explain.
func updateUntilRetired(retired context.Context, committed chan<- struct{}, failed chan<- error) {
	for retired.Err() == nil {
		err := AddResolvedIPs(retired, []string{"192.0.2.30"}, time.Minute, nil)

		switch {
		case err == nil:
			select {
			case committed <- struct{}{}:
			default:
			}
		case retired.Err() == nil:
			select {
			case failed <- err:
			default:
			}
		}
	}
}

func TestKernelProbe(t *testing.T) {
	requireKernel(t)

	err := Probe(t.Context())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
}
