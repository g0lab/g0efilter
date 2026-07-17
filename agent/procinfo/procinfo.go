// Package procinfo resolves the process that owns a local socket by walking
// /proc, for log enrichment. Only usable when g0efilter shares a PID namespace
// with the client processes (host deploy or pid: host / shareProcessNamespace);
// a network-only sidecar cannot see client PIDs and lookups degrade gracefully.
package procinfo

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cacheTTL        = 30 * time.Second
	maxCmdlineLen   = 256
	maxCacheEntries = 4096
)

// Info identifies the process behind a connection.
type Info struct {
	PID        int
	Name       string
	Cmdline    string
	Executable string
}

// Provider looks up the owning process of a local connection. Implementations
// must be safe for concurrent use from filter goroutines.
type Provider interface {
	Lookup(srcIP string, srcPort int, proto string) (Info, bool)
}

type cacheEntry struct {
	info    Info
	ok      bool
	expires time.Time
}

// ProcProvider resolves processes via /proc. Results (including misses) are
// cached by source ip:port because the inode-to-PID scan is O(procs x fds).
type ProcProvider struct {
	root string

	mu    sync.Mutex
	cache map[string]cacheEntry
	now   func() time.Time
}

// New returns a Provider reading from /proc.
func New() *ProcProvider {
	return NewWithRoot("/proc")
}

// NewWithRoot returns a Provider reading from an alternate proc root (for tests).
func NewWithRoot(root string) *ProcProvider {
	return &ProcProvider{
		root:  root,
		mu:    sync.Mutex{},
		cache: make(map[string]cacheEntry),
		now:   time.Now,
	}
}

// Lookup resolves the process owning the socket with the given local address.
// proto is "tcp" or "udp". The boolean is false when the process can't be found.
func (p *ProcProvider) Lookup(srcIP string, srcPort int, proto string) (Info, bool) {
	key := proto + ":" + srcIP + ":" + strconv.Itoa(srcPort)

	p.mu.Lock()

	entry, hit := p.cache[key]
	if hit && p.now().Before(entry.expires) {
		p.mu.Unlock()

		return entry.info, entry.ok
	}
	p.mu.Unlock()

	info, ok := p.resolve(srcIP, srcPort, proto)

	p.mu.Lock()
	p.cache[key] = cacheEntry{info: info, ok: ok, expires: p.now().Add(cacheTTL)}
	p.pruneLocked()
	p.mu.Unlock()

	return info, ok
}

// pruneLocked drops expired entries so the cache stays bounded by recent flows.
func (p *ProcProvider) pruneLocked() {
	if len(p.cache) < maxCacheEntries {
		return
	}

	now := p.now()
	for k, e := range p.cache {
		if now.After(e.expires) {
			delete(p.cache, k)
		}
	}

	// Nothing expired yet: drop arbitrary entries so unique-flow churn stays bounded.
	for k := range p.cache {
		if len(p.cache) < maxCacheEntries {
			break
		}

		delete(p.cache, k)
	}
}

func (p *ProcProvider) resolve(srcIP string, srcPort int, proto string) (Info, bool) {
	inode, found := p.findSocketInode(srcIP, srcPort, proto)
	if !found {
		return Info{}, false //nolint:exhaustruct
	}

	pid, found := p.findPIDByInode(inode)
	if !found {
		return Info{}, false //nolint:exhaustruct
	}

	return p.processInfo(pid), true
}

// findSocketInode scans the /proc/net socket tables for a matching local address.
func (p *ProcProvider) findSocketInode(srcIP string, srcPort int, proto string) (string, bool) {
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return "", false
	}

	portHex := strings.ToUpper(strconv.FormatInt(int64(srcPort), 16))
	for len(portHex) < 4 {
		portHex = "0" + portHex
	}

	// A v4 source can also appear in the v6 table as a v4-mapped address.
	tables := []struct{ file, addrHex string }{}
	if v4 := ip.To4(); v4 != nil {
		tables = append(tables,
			struct{ file, addrHex string }{proto, hexV4(v4)},
			struct{ file, addrHex string }{proto + "6", hexV6(ip.To16())},
		)
	} else {
		tables = append(tables, struct{ file, addrHex string }{proto + "6", hexV6(ip.To16())})
	}

	for _, t := range tables {
		inode, found := p.scanNetTable(filepath.Join(p.root, "net", t.file), t.addrHex+":"+portHex)
		if found {
			return inode, true
		}
	}

	return "", false
}

// scanNetTable finds the inode of the socket whose local_address equals localHex.
func (p *ProcProvider) scanNetTable(path, localHex string) (string, bool) {
	f, err := os.Open(path) //nolint:gosec // path is proc root + fixed table names
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	const (
		localAddrField = 1
		inodeField     = 9
		minFields      = 10
	)

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < minFields {
			continue
		}

		if fields[localAddrField] == localHex {
			return fields[inodeField], true
		}
	}

	return "", false
}

// findPIDByInode scans every process's fd table for socket:[inode].
func (p *ProcProvider) findPIDByInode(inode string) (int, bool) {
	target := "socket:[" + inode + "]"

	entries, err := os.ReadDir(p.root)
	if err != nil {
		return 0, false
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join(p.root, entry.Name(), "fd")

		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or no permission
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && link == target {
				return pid, true
			}
		}
	}

	return 0, false
}

func (p *ProcProvider) processInfo(pid int) Info {
	dir := filepath.Join(p.root, strconv.Itoa(pid))

	name := ""

	commBytes, err := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec // proc path
	if err == nil {
		name = strings.TrimSpace(string(commBytes))
	}

	cmdline := ""

	cmdBytes, err := os.ReadFile(filepath.Join(dir, "cmdline")) //nolint:gosec // proc path
	if err == nil {
		cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmdBytes), "\x00", " "))
		if len(cmdline) > maxCmdlineLen {
			cmdline = cmdline[:maxCmdlineLen]
		}
	}

	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		exe = "" // often permission-denied for other users' processes
	}

	return Info{PID: pid, Name: name, Cmdline: cmdline, Executable: exe}
}

// hexV4 renders an IPv4 address the way /proc/net/tcp does: 32-bit little-endian hex.
func hexV4(ip net.IP) string {
	b := []byte{ip[3], ip[2], ip[1], ip[0]}

	return strings.ToUpper(hex.EncodeToString(b))
}

// hexV6 renders an IPv6 address as four 32-bit little-endian groups, matching /proc/net/tcp6.
func hexV6(ip net.IP) string {
	out := make([]byte, 0, net.IPv6len)
	for g := range 4 {
		out = append(out, ip[g*4+3], ip[g*4+2], ip[g*4+1], ip[g*4])
	}

	return strings.ToUpper(hex.EncodeToString(out))
}
