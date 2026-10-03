//nolint:paralleltest // every kernel test owns the namespace's whole ruleset
package nftables

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
	"golang.org/x/sys/unix"
)

const bridgeName = "br-g0test"

// The observer sits after every filter hook, so a recorded packet is one the kernel let out.
const observerRuleset = `table inet g0observe
delete table inet g0observe
table inet g0observe {
    set seen4 {
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
    }

    set seen6 {
        type ipv6_addr . inet_proto . inet_service
        flags dynamic
    }

    chain postrouting {
        type filter hook postrouting priority 500; policy accept;
        meta l4proto { tcp, udp } add @seen4 { ip daddr . meta l4proto . th dport }
        meta l4proto { tcp, udp } add @seen6 { ip6 daddr . meta l4proto . th dport }
    }
}
`

type probe struct {
	role  string
	proto string
	dst   netip.Addr
	port  int
}

func (p probe) String() string {
	return fmt.Sprintf("%s %s %s", p.role, p.proto, netip.AddrPortFrom(p.dst, uint16(p.port))) //nolint:gosec // test ports
}

func observe(t *testing.T) {
	t.Helper()
	nftCLI(t, observerRuleset, "-f", "-")
}

// leaves reports whether p reached postrouting. A TCP SYN dropped on output gives
// its sender no error, so only the observer can tell.
func leaves(t *testing.T, p probe, send func(probe)) bool {
	t.Helper()

	set := "seen4"
	if p.dst.Is6() {
		set = "seen6"
	}

	nftCLI(t, "", "flush", "set", "inet", "g0observe", set)
	send(p)

	element := fmt.Sprintf("{ %s . %s . %d }", p.dst, p.proto, p.port)

	//nolint:gosec // nft with test-built arguments
	return exec.CommandContext(t.Context(), "nft", "get", "element", "inet", "g0observe", set, element).Run() == nil
}

// sendLocal emits one packet from this host. Errors are ignored: EPERM on a drop
// and EINPROGRESS once a SYN is out are both expected.
func sendLocal(t *testing.T) func(probe) {
	t.Helper()

	return func(p probe) {
		kind := unix.SOCK_DGRAM
		if p.proto == "tcp" {
			kind = unix.SOCK_STREAM
		}

		family, addr := unix.AF_INET6, unix.Sockaddr(&unix.SockaddrInet6{Port: p.port, Addr: p.dst.As16()})
		if p.dst.Is4() {
			family, addr = unix.AF_INET, &unix.SockaddrInet4{Port: p.port, Addr: p.dst.As4()}
		}

		fd, err := unix.Socket(family, kind|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("socket: %v", err)
		}

		if p.proto == "tcp" {
			_ = unix.Connect(fd, addr)
		} else {
			_ = unix.Sendto(fd, []byte("probe"), 0, addr)
		}

		_ = unix.Close(fd)
	}
}

// bridgeNet returns a TAP port of br-g0test: a frame written to it arrives as a
// container's egress and is routed through the forward hook.
func bridgeNet(t *testing.T) *os.File {
	t.Helper()
	trafficNet(t)

	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		content, err := os.ReadFile(path) //nolint:gosec // fixed procfs paths
		if err == nil && strings.TrimSpace(string(content)) == "1" {
			continue
		}

		err = os.WriteFile(path, []byte("1"), 0o600)
		if err != nil {
			t.Fatalf("%s must be 1; scripts/test-kernel.sh sets it: %v", path, err)
		}
	}

	tap := openTAP(t, "g0tap")

	run(t, "", "sh", "-c", `ip link show `+bridgeName+` >/dev/null 2>&1 || ip link add `+bridgeName+` type bridge
		ip link set g0tap master `+bridgeName+` && ip link set g0tap up && ip link set `+bridgeName+` up &&
		ip addr replace 172.30.0.1/24 dev `+bridgeName+` && ip addr replace fd30::1/64 dev `+bridgeName+` nodad`)

	return tap
}

func openTAP(t *testing.T, name string) *os.File {
	t.Helper()

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun; scripts/test-kernel.sh passes it in: %v", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("ifreq: %v", err)
	}

	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)

	err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	if err != nil {
		t.Fatalf("create TAP %s: %v", name, err)
	}

	tap := os.NewFile(uintptr(fd), name)

	t.Cleanup(func() { _ = tap.Close() })

	return tap
}

func sendBridged(t *testing.T, tap *os.File) func(probe) {
	t.Helper()

	sourcePort := uint16(40000)

	return func(p probe) {
		bridge, err := net.InterfaceByName(bridgeName)
		if err != nil {
			t.Fatalf("bridge: %v", err)
		}

		sourcePort++

		frame := slices.Concat(bridge.HardwareAddr, []byte{0x02, 0, 0, 0, 0, 0x02}, containerPacket(p, sourcePort))

		_, err = tap.Write(frame)
		if err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
}

// containerPacket returns the ethertype and IP packet a container on the bridge
// would send; checksums must be valid or conntrack marks the flow invalid.
func containerPacket(p probe, sourcePort uint16) []byte {
	proto, transport := byte(unix.IPPROTO_UDP), make([]byte, 8)
	sumOffset := 6

	if p.proto == "tcp" {
		proto, transport, sumOffset = unix.IPPROTO_TCP, make([]byte, 20), 16
		transport[12], transport[13] = 5<<4, 0x02
		binary.BigEndian.PutUint16(transport[14:], 65535)
	} else {
		binary.BigEndian.PutUint16(transport[4:], 8)
	}

	binary.BigEndian.PutUint16(transport[0:], sourcePort)
	binary.BigEndian.PutUint16(transport[2:], uint16(p.port)) //nolint:gosec // test ports

	src := netip.MustParseAddr("172.30.0.2")
	if p.dst.Is6() {
		src = netip.MustParseAddr("fd30::2")
	}

	pseudo := slices.Concat(src.AsSlice(), p.dst.AsSlice(), []byte{0, proto})
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(transport))) //nolint:gosec // small header

	sum := checksum(slices.Concat(pseudo, transport))
	if sum == 0 && p.proto == "udp" {
		sum = 0xffff // a zero UDP checksum means none, which IPv6 forbids
	}

	binary.BigEndian.PutUint16(transport[sumOffset:], sum)

	if p.dst.Is6() {
		header := make([]byte, 40)
		header[0], header[6], header[7] = 0x60, proto, 64
		binary.BigEndian.PutUint16(header[4:], uint16(len(transport))) //nolint:gosec // small header
		copy(header[8:], src.AsSlice())
		copy(header[24:], p.dst.AsSlice())

		return slices.Concat([]byte{0x86, 0xdd}, header, transport)
	}

	header := make([]byte, 20)
	header[0], header[8], header[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(header[2:], uint16(20+len(transport))) //nolint:gosec // small header
	copy(header[12:], src.AsSlice())
	copy(header[16:], p.dst.AsSlice())
	binary.BigEndian.PutUint16(header[10:], checksum(header))

	return slices.Concat([]byte{0x08, 0x00}, header, transport)
}

func checksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}

	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}

	return ^uint16(sum)
}

func outcomeConfigs() map[string]RulesetConfig {
	configs := map[string]RulesetConfig{}

	for _, mode := range []string{"https", "dns", "dns-strict"} {
		for _, defaultAllow := range []bool{false, true} {
			for _, audit := range []bool{false, true} {
				cfg := RulesetConfig{
					AllowV4: []string{"192.0.2.10"}, AllowV6: []string{"2001:db8::10"},
					DenyV4: []string{"192.0.2.66"}, DenyV6: []string{"2001:db8::66"},
					HTTPSPort: 18443, HTTPPort: 18080, DNSPort: 65053,
					Mode: mode, DefaultAllow: defaultAllow, Audit: audit,
					BridgeInterfaces: []string{bridgeName},
				}

				if portConstraintsEnforceable(mode, defaultAllow) {
					cfg.AllowPortV4 = []string{"192.0.2.20 . udp . 5300"}
					cfg.AllowPortV6 = []string{"2001:db8::20 . udp . 5300"}
				}

				configs[fmt.Sprintf("%s default-allow=%t audit=%t", mode, defaultAllow, audit)] = cfg
			}
		}
	}

	return configs
}

func outcomeProbes() []probe {
	probes := make([]probe, 0, 18)

	for _, prefix := range []string{"192.0.2.", "2001:db8::"} {
		addr := func(host string) netip.Addr { return netip.MustParseAddr(prefix + host) }

		probes = append(probes,
			probe{"allowed", "tcp", addr("10"), 22}, probe{"allowed", "udp", addr("10"), 9},
			probe{"denied", "tcp", addr("66"), 22}, probe{"denied", "udp", addr("66"), 9},
			probe{"unlisted", "tcp", addr("99"), 22}, probe{"unlisted", "udp", addr("99"), 9},
			probe{"port", "udp", addr("20"), 5300}, probe{"port", "udp", addr("20"), 5301},
			probe{"port", "tcp", addr("20"), 5300},
		)
	}

	return probes
}

// wantEgress is the policy contract: dns mode blocks only deny-listed addresses,
// the other modes block anything unlisted, and audit blocks nothing.
func wantEgress(cfg RulesetConfig, p probe) bool {
	switch {
	case cfg.Audit || p.role == "allowed":
		return true
	case p.role == "port" && len(cfg.AllowPortV4) > 0:
		return p.proto == "udp" && p.port == 5300
	case p.role == "denied" && cfg.DefaultAllow:
		return false
	default:
		return cfg.DefaultAllow || cfg.Mode == "dns"
	}
}

// Every mode and posture is judged by what actually leaves, from this host and
// from a container on a managed bridge, over TCP and UDP, IPv4 and IPv6.
func TestKernelEgressFollowsThePolicyContract(t *testing.T) {
	requireKernel(t)
	t.Setenv("BRIDGE_INTERFACES", bridgeName)

	tap := bridgeNet(t)
	observe(t)

	paths := map[string]func(probe){"host": sendLocal(t), "bridged": sendBridged(t, tap)}
	configs := outcomeConfigs()

	for _, name := range slices.Sorted(maps.Keys(configs)) {
		cfg := configs[name]
		applyForTest(t, cfg)

		for _, path := range slices.Sorted(maps.Keys(paths)) {
			for _, p := range outcomeProbes() {
				if got, want := leaves(t, p, paths[path]), wantEgress(cfg, p); got != want {
					t.Errorf("%s, %s %v: left the host = %t, want %t", name, path, p, got, want)
				}
			}
		}
	}
}

func strictBridgePolicy(t *testing.T) *os.File {
	t.Helper()
	t.Setenv("BRIDGE_INTERFACES", bridgeName)

	tap := bridgeNet(t)
	observe(t)
	applyForTest(t, RulesetConfig{
		HTTPSPort: 18443, HTTPPort: 18080, DNSPort: 65053, Mode: "dns-strict", BridgeInterfaces: []string{bridgeName},
	})

	return tap
}

// A port-constrained answer must admit only its protocol and port, judged alone
// so an unrestricted grant for the same address cannot mask a constraint failure.
func TestKernelDNSGrantsAdmitOnlyWhatTheyAuthorize(t *testing.T) {
	requireKernel(t)

	tap := strictBridgePolicy(t)
	constrained := []string{"192.0.2.30", "2001:db8::30"}
	unrestricted := []string{"192.0.2.40", "2001:db8::40"}

	err := AddResolvedIPs(t.Context(), constrained, time.Minute, []policy.DomainRule{{Proto: policy.ProtoUDP, Port: 5353}})
	if err != nil {
		t.Fatalf("AddResolvedIPs: %v", err)
	}

	err = AddResolvedIPs(t.Context(), unrestricted, time.Minute, nil)
	if err != nil {
		t.Fatalf("AddResolvedIPs: %v", err)
	}

	probes := make([]probe, 0, 6*len(constrained))

	for i := range constrained {
		granted, open := netip.MustParseAddr(constrained[i]), netip.MustParseAddr(unrestricted[i])
		never := netip.MustParseAddr(strings.Replace(constrained[i], "30", "50", 1))

		probes = append(probes,
			probe{"granted", "udp", granted, 5353}, probe{"wrong port", "udp", granted, 5354},
			probe{"wrong protocol", "tcp", granted, 5353}, probe{"granted", "tcp", open, 22},
			probe{"granted", "udp", open, 9}, probe{"never resolved", "tcp", never, 22},
		)
	}

	for path, send := range map[string]func(probe){"host": sendLocal(t), "bridged": sendBridged(t, tap)} {
		for _, p := range probes {
			if got, want := leaves(t, p, send), p.role == "granted"; got != want {
				t.Errorf("%s %v: left the host = %t, want %t", path, p, got, want)
			}
		}
	}
}

// grant writes an answer with an exact lifetime, bypassing the TTL floor so expiry
// can be observed in seconds.
func grant(t *testing.T, ip string, lifetime time.Duration) {
	t.Helper()

	pending := map[string]*pendingSet{}

	for _, prefix := range resolvedTablePrefixes() {
		set, key := resolvedElement(prefix, net.ParseIP(ip), policy.DomainRule{})
		pendingFor(pending, set).add(key)
	}

	err := refreshResolved(t.Context(), pending, lifetime)
	if err != nil {
		t.Fatalf("refreshResolved: %v", err)
	}
}

// Expiry is judged by fresh connections: an answer admits new flows only until its
// lifetime lapses, and each newer answer resets that deadline, shorter or longer.
func TestKernelDNSGrantsExpireAndRefresh(t *testing.T) {
	requireKernel(t)

	tap := strictBridgePolicy(t)
	paths := map[string]func(probe){"host": sendLocal(t), "bridged": sendBridged(t, tap)}

	expect := func(ip string, want bool, when string) {
		t.Helper()

		for path, send := range paths {
			p := probe{when, "tcp", netip.MustParseAddr(ip), 22}
			if got := leaves(t, p, send); got != want {
				t.Errorf("%s %v: left the host = %t, want %t", path, p, got, want)
			}
		}
	}

	start := time.Now()
	sleepUntil := func(offset time.Duration) { time.Sleep(time.Until(start.Add(offset))) }

	grant(t, "192.0.2.60", 2*time.Second)
	grant(t, "192.0.2.70", time.Minute)
	grant(t, "192.0.2.70", time.Second)
	expect("192.0.2.60", true, "fresh")

	sleepUntil(time.Second)
	grant(t, "192.0.2.60", 2*time.Second)

	sleepUntil(2500 * time.Millisecond)
	expect("192.0.2.60", true, "refreshed past its first deadline")
	expect("192.0.2.70", false, "shortened by a newer answer")

	sleepUntil(3600 * time.Millisecond)
	expect("192.0.2.60", false, "expired")
}

// A DNS reply waits for its commit, so commits must keep landing while large
// reloads contend for the ruleset lock.
func TestKernelDNSUpdatesLandDuringLargeReloads(t *testing.T) {
	requireKernel(t)
	trafficNet(t)
	observe(t)

	cfg := RulesetConfig{HTTPSPort: 18443, HTTPPort: 18080, DNSPort: 65053, Mode: "dns-strict"}
	for i := range 5000 {
		cfg.AllowV4 = append(cfg.AllowV4, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
	}

	applyForTest(t, cfg)

	reloading, stop := context.WithCancel(t.Context())
	reloads, reloadErrs := reloadUntil(reloading, atomicReplacePreamble+GenerateRuleset(cfg))

	latencies, errs := concurrentDNSUpdates(t.Context(), 4, 25)

	stop()

	for _, err := range append(<-reloadErrs, errs...) {
		t.Errorf("%v", err)
	}

	slices.Sort(latencies)
	t.Logf("%d updates during %d reloads: median %v, max %v",
		len(latencies), <-reloads, latencies[len(latencies)/2], latencies[len(latencies)-1])

	err := AddResolvedIPs(t.Context(), []string{"192.0.2.250"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("AddResolvedIPs: %v", err)
	}

	if !leaves(t, probe{"granted", "tcp", netip.MustParseAddr("192.0.2.250"), 22}, sendLocal(t)) {
		t.Error("an answer committed after the reloads did not admit its address")
	}
}

func reloadUntil(ctx context.Context, ruleset string) (<-chan int, <-chan []error) {
	reloads, errs := make(chan int, 1), make(chan []error, 1)

	go func() {
		var (
			count  int
			failed []error
		)

		for ctx.Err() == nil {
			err := applyRuleset(ctx, ruleset)
			if err != nil && ctx.Err() == nil {
				failed = append(failed, fmt.Errorf("reload: %w", err))
			}

			count++
		}

		reloads <- count

		errs <- failed
	}()

	return reloads, errs
}

func concurrentDNSUpdates(ctx context.Context, workers, each int) ([]time.Duration, []error) {
	var (
		mu        sync.Mutex
		latencies []time.Duration
		errs      []error
		wg        sync.WaitGroup
	)

	for worker := range workers {
		wg.Go(func() {
			for i := range each {
				ip := fmt.Sprintf("192.0.2.%d", 100+worker*each+i)
				start := time.Now()
				err := AddResolvedIPs(ctx, []string{ip}, time.Minute, nil)

				mu.Lock()

				latencies = append(latencies, time.Since(start))

				if err != nil {
					errs = append(errs, fmt.Errorf("DNS update for %s: %w", ip, err))
				}
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	return latencies, errs
}
