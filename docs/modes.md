# Filter modes

Attached containers share g0efilter's network namespace. Allowed IPs and CIDRs
pass through directly. Other traffic is handled by `FILTER_MODE`.

| Mode | Domain check | Hardcoded IPs blocked? | Best for |
| --- | --- | ---: | --- |
| `https` | Each HTTP or HTTPS connection | Yes | Precise web filtering |
| `dns` | DNS lookup | No | Simple filtering across protocols |
| `dns-strict` | DNS lookup and connection | Yes | Strict domain filtering on any port |

> [!NOTE]
> Workloads must not listen on g0efilter's internal HTTP, HTTPS, or DNS ports.
> The defaults are 65080, 65443, and 65053.

## HTTPS mode

g0efilter redirects outbound traffic on ports 80 and 443 to local proxies. It
checks the HTTP `Host` header or TLS SNI against the policy. TLS is not
decrypted.

Allowed connections continue to the original destination. Blocked connections
are reset. Other destination ports are blocked unless their IP is allowed.

This mode works well with CDNs and changing IPs. It only checks domains on ports
80 and 443, and blocks TLS clients that omit SNI under a default-deny policy.

## DNS mode

g0efilter redirects TCP and UDP DNS traffic on port 53 to its DNS proxy. Allowed
domains resolve normally. Blocked A and AAAA queries return sinkhole addresses;
other blocked query types return `NXDOMAIN`.

If an unlisted domain resolves to an allowed IP, only its allowed addresses are
returned. This check applies only when the policy contains allowed IPs.

DNS mode works with any protocol, but enforces rules only during lookup.
Hardcoded IPs, cached answers and DNS-over-HTTPS can bypass it.

The default upstream is Docker's `127.0.0.11:53`. On Kubernetes, set
`DNS_UPSTREAMS` (or `dns.upstreams` in the Helm library chart and
`spec.sidecar.dns.upstreams` in an `EgressPolicy`) to the cluster DNS Service,
such as `10.96.0.10:53`.

## DNS-strict mode

DNS-strict starts with DNS mode, then adds each allowed A or AAAA answer to a
temporary nftables set. Connections are allowed only when their destination is
in that set or the IP allowlist.

Use it when allowed domains serve protocols or ports other than HTTP and HTTPS,
but direct-IP and alternate-DNS bypasses must still be blocked.

Entries follow the DNS TTL, with a 60-second minimum and 24-hour maximum.
Existing connections survive expiry. A policy reload clears resolved entries.

DNS-strict also:

- Covers all ports and IPv4/IPv6.
- Blocks hardcoded IPs, cached answers, and DNS-over-HTTPS bypasses.
- Requires `default_action: deny`.
- Falls back to DNS mode during learning or default-allow mode.
