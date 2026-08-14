package alerting

import "testing"

type ignoreCase struct {
	name    string
	pattern string
	info    BlockedConnectionInfo
	want    bool
}

func runIgnoreCases(t *testing.T, tests []ignoreCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := compileIgnoreRules([]string{tt.pattern})
			if len(rules) != 1 {
				t.Fatalf("compileIgnoreRules(%q) produced %d rules, want 1", tt.pattern, len(rules))
			}

			if got := rules.matches(tt.info); got != tt.want {
				t.Errorf("%q against %+v = %v, want %v", tt.pattern, tt.info, got, tt.want)
			}
		})
	}
}

func TestIgnoreDomainRules(t *testing.T) {
	t.Parallel()

	runIgnoreCases(t, []ignoreCase{
		{"exact domain", "example.com", BlockedConnectionInfo{Destination: "example.com"}, true},
		{"exact domain mismatch", "example.com", BlockedConnectionInfo{Destination: "example.org"}, false},
		{"domain is case insensitive", "example.com", BlockedConnectionInfo{Destination: "EXAMPLE.COM"}, true},
		{"wildcard subdomain", "*.example.com", BlockedConnectionInfo{Destination: "api.example.com"}, true},
		{"wildcard skips the base", "*.example.com", BlockedConnectionInfo{Destination: "example.com"}, false},
	})
}

func TestIgnoreAddressRules(t *testing.T) {
	t.Parallel()

	runIgnoreCases(t, []ignoreCase{
		{"cidr matches destination ip", "10.0.0.0/8", BlockedConnectionInfo{DestinationIP: "10.1.2.3"}, true},
		{"cidr rejects outside address", "10.0.0.0/8", BlockedConnectionInfo{DestinationIP: "192.168.1.1"}, false},
		{"cidr matches destination field", "10.0.0.0/8", BlockedConnectionInfo{Destination: "10.1.2.3"}, true},
		{
			"non-canonical cidr is masked",
			"10.1.2.3/8",
			BlockedConnectionInfo{DestinationIP: "10.9.9.9"},
			true,
		},
		{"bare ip", "1.2.3.4", BlockedConnectionInfo{DestinationIP: "1.2.3.4"}, true},
		{"bare ip is exact", "1.2.3.4", BlockedConnectionInfo{DestinationIP: "1.2.3.5"}, false},
		{"ipv6 cidr", "2001:db8::/32", BlockedConnectionInfo{DestinationIP: "2001:db8::1"}, true},
	})
}

func TestIgnoreAddressClassRules(t *testing.T) {
	t.Parallel()

	runIgnoreCases(t, []ignoreCase{
		// IPv6 neighbour discovery is the noisiest source of nflog blocks.
		{"multicast matches ff02", "multicast", BlockedConnectionInfo{Destination: "ff02::16"}, true},
		{"multicast matches ipv4", "multicast", BlockedConnectionInfo{DestinationIP: "224.0.0.251"}, true},
		{"multicast spares unicast", "multicast", BlockedConnectionInfo{DestinationIP: "1.2.3.4"}, false},
		{"loopback", "loopback", BlockedConnectionInfo{DestinationIP: "127.0.0.1"}, true},
		{"link-local matches fe80", "link-local", BlockedConnectionInfo{DestinationIP: "fe80::1"}, true},
		{"link-local matches ff02", "link-local", BlockedConnectionInfo{Destination: "ff02::1:ff19:20c7"}, true},
		{"private", "private", BlockedConnectionInfo{DestinationIP: "10.1.2.3"}, true},
		{"private spares public", "private", BlockedConnectionInfo{DestinationIP: "8.8.8.8"}, false},
		{"local covers multicast", "local", BlockedConnectionInfo{Destination: "ff02::2"}, true},
		{"local covers loopback", "local", BlockedConnectionInfo{DestinationIP: "127.0.0.1"}, true},
		{"local spares public", "local", BlockedConnectionInfo{DestinationIP: "8.8.8.8"}, false},
		{"public is the inverse of local", "public", BlockedConnectionInfo{DestinationIP: "8.8.8.8"}, true},
		{"public spares multicast", "public", BlockedConnectionInfo{Destination: "ff02::2"}, false},
		{"address class needs an address", "multicast", BlockedConnectionInfo{Destination: "example.com"}, false},
	})
}

func TestIgnoreComponentAndShapeRules(t *testing.T) {
	t.Parallel()

	runIgnoreCases(t, []ignoreCase{
		{"component", "component:dns", BlockedConnectionInfo{Component: "dns"}, true},
		{"component is case insensitive", "component:dns", BlockedConnectionInfo{Component: "DNS"}, true},
		{"component mismatch", "component:dns", BlockedConnectionInfo{Component: "https"}, false},

		{"empty destination matches nothing", "example.com", BlockedConnectionInfo{}, false},

		{
			"ip-only matches a bare address block",
			"ip-only",
			BlockedConnectionInfo{Destination: "1.2.3.4:443", DestinationIP: "1.2.3.4", DestinationPort: "443"},
			true,
		},
		{
			"ip-only matches an unknown destination",
			"ip-only",
			BlockedConnectionInfo{Destination: "unknown destination", DestinationIP: "1.2.3.4"},
			true,
		},
		{
			"ip-only leaves domain blocks alerting",
			"ip-only",
			BlockedConnectionInfo{Destination: "example.com", DestinationIP: "1.2.3.4", DestinationPort: "443"},
			false,
		},
	})
}

func TestCompileIgnoreRulesSkipsUnusable(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"", "component:"} {
		if rules := compileIgnoreRules([]string{pattern}); rules != nil {
			t.Errorf("compileIgnoreRules(%q) = %v, want nil", pattern, rules)
		}
	}
}

func TestIgnoreRulesAreORed(t *testing.T) {
	t.Parallel()

	rules := compileIgnoreRules([]string{"*.telemetry.example.com", "10.0.0.0/8", "component:dns"})

	matching := []BlockedConnectionInfo{
		{Destination: "a.telemetry.example.com"},
		{DestinationIP: "10.4.5.6"},
		{Component: "dns", Destination: "anything.example.net"},
	}

	for _, info := range matching {
		if !rules.matches(info) {
			t.Errorf("expected %+v to be ignored", info)
		}
	}

	if rules.matches(BlockedConnectionInfo{Destination: "example.net", Component: "https"}) {
		t.Error("expected an unrelated block to alert")
	}
}

// A malformed CIDR must be rejected, not kept as a domain rule that never matches.
func TestUnusableIgnorePatternsAreRejected(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"10.0.0.0/33", "1.2.3.4:443", "10.0.0.0/", "component:"} {
		rule, ok := parseIgnoreRule(pattern)
		if ok {
			t.Errorf("parseIgnoreRule(%q) = %#v, want rejected", pattern, rule)
		}
	}
}

func TestIgnorePatternCaseIsNormalized(t *testing.T) {
	t.Parallel()

	rules := compileIgnoreRules([]string{"  *.Telemetry.Example.COM  "})
	if !rules.matches(BlockedConnectionInfo{Destination: "api.telemetry.example.com"}) {
		t.Error("a mixed-case pattern must match a lowercase destination")
	}
}

// IGMP membership reports to 224.0.0.22 are the noisiest thing a runner emits, and a
// component may report the destination only as host:port.
func TestAddressClassesMatchEitherDestinationForm(t *testing.T) {
	t.Parallel()

	rules := compileIgnoreRules([]string{"local"})

	for _, info := range []BlockedConnectionInfo{
		{DestinationIP: "224.0.0.22"},
		{Destination: "224.0.0.22"},
		{Destination: "224.0.0.22:0"},
		{Destination: "[ff02::16]:0"},
		{DestinationIP: "224.0.0.22", DestinationPort: "0"},
	} {
		if !rules.matches(info) {
			t.Errorf("local did not match %+v", info)
		}
	}

	if rules.matches(BlockedConnectionInfo{Destination: "example.com:443"}) {
		t.Error("local must not match a public hostname")
	}
}
