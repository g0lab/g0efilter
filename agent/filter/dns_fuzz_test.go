//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func dnsMessageSeeds(f *testing.F) {
	f.Helper()

	pack := func(msg *dns.Msg) []byte {
		wire, err := msg.Pack()
		if err != nil {
			f.Fatalf("pack seed: %v", err)
		}

		return wire
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	f.Add(pack(query))

	txt := new(dns.Msg)
	txt.SetQuestion("example.com.", dns.TypeTXT)
	f.Add(pack(txt))

	answer := new(dns.Msg)
	answer.SetQuestion("example.com.", dns.TypeA)
	answer.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Rdlength: 0, Ttl: 60,
		}, A: net.ParseIP("1.2.3.4")},
		&dns.AAAA{Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Rdlength: 0, Ttl: 30,
		}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.CNAME{Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Rdlength: 0, Ttl: 10,
		}, Target: "other.example."},
	}
	f.Add(pack(answer))

	f.Add([]byte{})
	f.Add([]byte{0x00})
	// A compression pointer to itself: the classic unpack loop.
	f.Add([]byte{0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c})
}

// dns-strict allows a destination because a response named it, so what the agent
// harvests from a response is a policy decision made on attacker-supplied wire data.
func FuzzDNSResponseHandling(f *testing.F) {
	dnsMessageSeeds(f)

	f.Fuzz(func(t *testing.T, wire []byte) {
		msg := new(dns.Msg)

		err := msg.Unpack(wire)
		if err != nil {
			return
		}

		_ = checkExfilResponse(msg) // must never panic

		for _, question := range msg.Question {
			_ = checkExfilQuery(strings.ToLower(strings.TrimSuffix(question.Name, ".")), question.Qtype)
			_, _ = sanitizeDNSQname(question.Name)
		}

		ips, _ := extractAnswerIPs(msg)

		if len(ips) > len(msg.Answer) {
			t.Fatalf("harvested %d addresses from %d answers", len(ips), len(msg.Answer))
		}

		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				t.Fatalf("harvested %q, which is not an address", ip)
			}
		}

		if got := countAddressRecords(msg); len(ips) != got {
			t.Fatalf("harvested %d addresses from %d A/AAAA records", len(ips), got)
		}
	})
}

func countAddressRecords(msg *dns.Msg) int {
	count := 0

	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if record.A != nil {
				count++
			}
		case *dns.AAAA:
			if record.AAAA != nil {
				count++
			}
		}
	}

	return count
}

// entryAddress strips the optional protocol prefix and port from an allowlist entry.
func entryAddress(entry string) string {
	if proto, rest, found := strings.Cut(entry, "/"); found {
		switch strings.ToLower(proto) {
		case "tcp", "udp":
			entry = rest
		}
	}

	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		if end < 0 {
			return ""
		}

		return entry[1:end]
	}

	// An IPv6 literal has two or more colons, so a single one marks a port.
	if strings.Count(entry, ":") == 1 {
		host, _, err := net.SplitHostPort(entry)
		if err != nil {
			return ""
		}

		return host
	}

	return canonicalPrefixLength(entry)
}

// net.ParseCIDR tolerates a zero-padded prefix length and net/netip does not, so
// the padding is normalised away rather than reported as a widening.
func canonicalPrefixLength(entry string) string {
	addr, bits, found := strings.Cut(entry, "/")
	if !found || bits == "" || strings.TrimLeft(bits, "0123456789") != "" {
		return entry
	}

	length, err := strconv.Atoi(bits)
	if err != nil {
		return entry
	}

	return addr + "/" + strconv.Itoa(length)
}

// referenceCovers re-parses one allowlist entry with net/netip, an address
// implementation independent of the net.IPNet path the allowlist uses.
func referenceCovers(entry, ipText string) (bool, bool) {
	addr, err := netip.ParseAddr(ipText)
	if err != nil {
		return false, false
	}

	host := entryAddress(strings.TrimSpace(entry))
	if host == "" {
		return false, false
	}

	prefix, prefixErr := netip.ParsePrefix(host)
	if prefixErr == nil {
		return prefix.Masked().Contains(addr.Unmap()) || prefix.Masked().Contains(addr), true
	}

	other, err := netip.ParseAddr(host)
	if err != nil {
		return false, false
	}

	return other.Unmap() == addr.Unmap(), true
}

// An IP the allowlist admits must be covered by an entry that actually names it.
// The check is one-directional on purpose: only the permissive direction is a
// security failure, so a conservative disagreement never fails the run.
func FuzzIPAllowlistNeverWidens(f *testing.F) {
	for _, seed := range []struct{ entries, ip string }{
		{"1.2.3.4", "1.2.3.4"},
		{"10.0.0.0/8", "10.1.2.3"},
		{"10.0.0.0/8", "11.1.2.3"},
		{"tcp/1.2.3.4:443", "1.2.3.4"},
		{"2001:db8::/32", "2001:db8::1"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"0.0.0.0/0", "8.8.8.8"},
		{"1.2.3.4\n10.0.0.0/8", "10.0.0.1"},
		{"", "1.2.3.4"},
		{"not-an-ip", "1.2.3.4"},
		{"tCP/1.2.3.4:1", "1.2.3.4"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		f.Add(seed.entries, seed.ip)
	}

	f.Fuzz(func(t *testing.T, entries, ipText string) {
		ip := net.ParseIP(ipText)
		if ip == nil {
			return
		}

		lines := strings.Split(entries, "\n")

		if !newIPAllowlist(lines).contains(ip) {
			return
		}

		for _, entry := range lines {
			covers, parsed := referenceCovers(entry, ipText)
			if parsed && covers {
				return
			}
		}

		t.Fatalf("%q was allowed, but no entry in %q covers it", ipText, entries)
	})
}
