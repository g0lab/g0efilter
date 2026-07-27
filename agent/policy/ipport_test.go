//nolint:testpackage // exercises unexported parser details
package policy

import "testing"

func TestParseIPPortRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry string
		want  IPPortRule
	}{
		{"bare ipv4", "1.2.3.4", IPPortRule{Addr: "1.2.3.4"}},
		{"ipv4 cidr", "10.0.0.0/8", IPPortRule{Addr: "10.0.0.0/8"}},
		{"bare ipv6", "2606:4700::1111", IPPortRule{Addr: "2606:4700::1111"}},
		{"ipv6 cidr", "2606:4700::/32", IPPortRule{Addr: "2606:4700::/32"}},
		{"ipv4 port defaults tcp", "1.2.3.4:3389", IPPortRule{Addr: "1.2.3.4", Proto: "tcp", Port: 3389}},
		{"explicit tcp", "tcp/1.2.3.4:3389", IPPortRule{Addr: "1.2.3.4", Proto: "tcp", Port: 3389}},
		{"explicit udp", "udp/1.2.3.4:53", IPPortRule{Addr: "1.2.3.4", Proto: "udp", Port: 53}},
		{"bracketed ipv6 port", "[2606:4700::1111]:443", IPPortRule{Addr: "2606:4700::1111", Proto: "tcp", Port: 443}},
		{"udp bracketed ipv6", "udp/[2606:4700::1111]:853", IPPortRule{Addr: "2606:4700::1111", Proto: "udp", Port: 853}},
		{"cidr with port", "tcp/10.0.0.0/24:443", IPPortRule{Addr: "10.0.0.0/24", Proto: "tcp", Port: 443}},
		{"bracketed ipv4 cidr", "[192.168.0.0/16]:443", IPPortRule{Addr: "192.168.0.0/16", Proto: "tcp", Port: 443}},
		{"bracketed ipv6 cidr", "udp/[2606:4700::/32]:53", IPPortRule{Addr: "2606:4700::/32", Proto: "udp", Port: 53}},
		{"bracketed ipv4 no port", "[10.0.0.0/8]", IPPortRule{Addr: "10.0.0.0/8"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseIPPortRule(tt.entry)
			if err != nil {
				t.Fatalf("ParseIPPortRule(%q) error: %v", tt.entry, err)
			}

			if got != tt.want {
				t.Errorf("ParseIPPortRule(%q) = %+v, want %+v", tt.entry, got, tt.want)
			}
		})
	}
}

func TestParseIPPortRuleConstrained(t *testing.T) {
	t.Parallel()

	unconstrained, _ := ParseIPPortRule("1.2.3.4")
	if unconstrained.Constrained() {
		t.Error("bare IP must be unconstrained")
	}

	constrained, _ := ParseIPPortRule("1.2.3.4:22")
	if !constrained.Constrained() {
		t.Error("ip:port must be constrained")
	}
}

func TestParseIPPortRuleRejects(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"",
		"not-an-ip",
		"1.2.3.4:0",        // port out of range
		"1.2.3.4:70000",    // port out of range
		"1.2.3.4:ssh",      // non-numeric port
		"tcp/1.2.3.4",      // protocol without port
		"udp/2606:4700::1", // protocol without port (unbracketed v6)
		"1.2.3.4; drop",    // injection attempt
		"sctp/1.2.3.4:443", // unsupported protocol falls through to invalid IP
	} {
		_, err := ParseIPPortRule(bad)
		if err == nil {
			t.Errorf("ParseIPPortRule(%q) = nil error, want rejection", bad)
		}
	}
}

func TestParseDomainRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry string
		want  DomainRule
	}{
		{"bare domain", "example.com", DomainRule{Pattern: "example.com"}},
		{"port defaults tcp", "example.com:443", DomainRule{Pattern: "example.com", Proto: "tcp", Port: 443}},
		{"explicit tcp", "tcp/example.com:8443", DomainRule{Pattern: "example.com", Proto: "tcp", Port: 8443}},
		{"explicit udp", "udp/example.com:53", DomainRule{Pattern: "example.com", Proto: "udp", Port: 53}},
		{"wildcard with port", "*.example.com:443", DomainRule{Pattern: "*.example.com", Proto: "tcp", Port: 443}},
		{"bare wildcard", "*.example.com", DomainRule{Pattern: "*.example.com"}},
		{"regex with port", `/^api\..*\.com$/:443`, DomainRule{Pattern: `/^api\..*\.com$/`, Proto: "tcp", Port: 443}},
		{"match all", "*", DomainRule{Pattern: "*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDomainRule(tt.entry)
			if err != nil {
				t.Fatalf("ParseDomainRule(%q) error: %v", tt.entry, err)
			}

			if got != tt.want {
				t.Errorf("ParseDomainRule(%q) = %+v, want %+v", tt.entry, got, tt.want)
			}
		})
	}
}

func TestParseDomainRuleRejects(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"",
		"example.com:0",      // port out of range
		"example.com:70000",  // port out of range
		"tcp/example.com",    // protocol without port
		"udp/example.com",    // protocol without port
		"exa mple.com:443",   // invalid domain
		"example.com; drop",  // injection attempt
		"sctp/example.com:1", // unsupported protocol leaves an invalid domain
	} {
		_, err := ParseDomainRule(bad)
		if err == nil {
			t.Errorf("ParseDomainRule(%q) = nil error, want rejection", bad)
		}
	}
}

func TestParseDomainRuleRegexColonNotAPort(t *testing.T) {
	t.Parallel()

	got, err := ParseDomainRule(`/^host:name$/`)
	if err != nil {
		t.Fatalf("ParseDomainRule regex with colon: %v", err)
	}

	if got.Constrained() || got.Pattern != `/^host:name$/` {
		t.Errorf("got %+v, want the whole pattern unconstrained", got)
	}
}
