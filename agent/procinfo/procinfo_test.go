//nolint:testpackage // Need access to internal implementation details
package procinfo

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a minimal /proc tree: one process (pid 4242) owning a TCP socket
// with inode 98765 bound to 172.18.0.5:51000, plus a UDP socket with inode 55555
// bound to 172.18.0.5:53001.
func fakeProc(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "net"))
	mustMkdir(t, filepath.Join(root, "4242", "fd"))
	mustMkdir(t, filepath.Join(root, "sys")) // non-numeric dir must be skipped
	mustMkdir(t, filepath.Join(root, "999")) // process without fd dir must be skipped

	// 172.18.0.5 -> 050012AC (little-endian); port 51000 = C738, 53001 = CF09
	header := "  sl  local_address rem_address st tx rx tr tm retrnsmt uid timeout inode\n"
	mustWrite(t, filepath.Join(root, "net", "tcp"),
		header+"   0: 050012AC:C738 03004E14:01BB 01 0:0 00:0 0 1000 0 98765 1 f 20\n")
	mustWrite(t, filepath.Join(root, "net", "udp"),
		header+"   0: 050012AC:CF09 00000000:0000 07 0:0 00:0 0 1000 0 55555 2 f 0\n")
	mustWrite(t, filepath.Join(root, "net", "tcp6"), "header\n")
	mustWrite(t, filepath.Join(root, "net", "udp6"), "header\n")

	// Symlink targets don't need to exist for Readlink to return them
	mustSymlink(t, "socket:[98765]", filepath.Join(root, "4242", "fd", "4"))
	mustSymlink(t, "socket:[55555]", filepath.Join(root, "4242", "fd", "5"))

	mustWrite(t, filepath.Join(root, "4242", "comm"), "curl\n")
	mustWrite(t, filepath.Join(root, "4242", "cmdline"), "curl\x00-sS\x00https://github.com\x00")

	return root
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()

	err := os.MkdirAll(path, 0o750)
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, path string) {
	t.Helper()

	err := os.Symlink(target, path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLookupTCP(t *testing.T) {
	t.Parallel()

	p := NewWithRoot(fakeProc(t))

	info, ok := p.Lookup("172.18.0.5", 51000, "tcp")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}

	if info.PID != 4242 || info.Name != "curl" {
		t.Errorf("info = %+v, want pid 4242 name curl", info)
	}

	if info.Cmdline != "curl -sS https://github.com" {
		t.Errorf("cmdline = %q", info.Cmdline)
	}
}

func TestLookupUDP(t *testing.T) {
	t.Parallel()

	p := NewWithRoot(fakeProc(t))

	info, ok := p.Lookup("172.18.0.5", 53001, "udp")
	if !ok || info.PID != 4242 {
		t.Fatalf("udp lookup = %+v ok=%v, want pid 4242", info, ok)
	}
}

func TestLookupMissDegradesGracefully(t *testing.T) {
	t.Parallel()

	p := NewWithRoot(fakeProc(t))

	if _, ok := p.Lookup("172.18.0.5", 40000, "tcp"); ok {
		t.Error("unknown port must not resolve")
	}

	if _, ok := p.Lookup("not-an-ip", 80, "tcp"); ok {
		t.Error("invalid IP must not resolve")
	}
}

func TestLookupCaches(t *testing.T) {
	t.Parallel()

	root := fakeProc(t)
	p := NewWithRoot(root)

	if _, ok := p.Lookup("172.18.0.5", 51000, "tcp"); !ok {
		t.Fatal("first lookup failed")
	}

	// Remove the proc tree: a cached result must still be served
	err := os.RemoveAll(filepath.Join(root, "net"))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := p.Lookup("172.18.0.5", 51000, "tcp"); !ok {
		t.Error("cached lookup must not rescan /proc")
	}
}

func TestCacheBoundedUnderUniqueFlowChurn(t *testing.T) {
	t.Parallel()

	p := NewWithRoot(t.TempDir())

	// Every lookup is a fresh flow, so nothing is expired when the cap is hit;
	// the fallback eviction must still bound the cache.
	for i := range maxCacheEntries + 50 {
		p.Lookup("10.0.0.1", 1000+i, "tcp")
	}

	if len(p.cache) > maxCacheEntries {
		t.Errorf("cache = %d entries, want <= %d", len(p.cache), maxCacheEntries)
	}
}

func TestHexEncodingMatchesProcFormat(t *testing.T) {
	t.Parallel()

	// Known-good examples from /proc/net/tcp: 127.0.0.1 -> 0100007F
	if got := hexV4(net.ParseIP("127.0.0.1").To4()); got != "0100007F" {
		t.Errorf("hexV4(127.0.0.1) = %q, want 0100007F", got)
	}

	if got := hexV4(net.ParseIP("172.18.0.5").To4()); got != "050012AC" {
		t.Errorf("hexV4(172.18.0.5) = %q, want 050012AC", got)
	}

	// ::1 -> three zero groups then 01000000 in little-endian group encoding
	if got := hexV6(net.ParseIP("::1").To16()); got != "00000000000000000000000001000000" {
		t.Errorf("hexV6(::1) = %q", got)
	}
}
