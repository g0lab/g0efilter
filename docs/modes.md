# Filter modes

Attached containers share g0efilter's network namespace. Traffic to allowlisted IPs/CIDRs passes through directly; everything else is handled by the selected `FILTER_MODE`.

| Mode | Checks domains at | Blocks hardcoded IPs? | Best for |
| --- | --- | ---: | --- |
| `https` | Connection time via TLS SNI / HTTP Host inspection | Yes, unless IP allowlisted | Web-heavy workloads needing precise domain control |
| `dns` | DNS resolution time | No | Lightweight broad filtering |
| `dns-strict` | DNS plus kernel connection-time enforcement | Yes | Strong default-deny egress control |

> [!NOTE]
> Attached containers must not bind to ports used by g0efilter: `HTTP_PORT` (8080), `HTTPS_PORT` (8443), and `DNS_PORT` (53) in dns modes.

## https mode

Outbound traffic on ports 80/443 is redirected by nftables to local proxy services inside g0efilter. The proxies read the HTTP `Host` header (port 80) or the TLS SNI from the ClientHello (port 443, without terminating TLS) and check it against the policy. Allowed connections are spliced through to the original destination at kernel speed; blocked connections are reset. Traffic on other ports is dropped unless the destination IP is allowlisted.

```text
Start
|
+- Destination IP in allowlist? -- Yes -> ALLOW (no redirect)
|
+- Connection already established? -- Yes -> ALLOW
|
+- Destination port 80/443? -- No -> BLOCK
|
+- Redirect to local proxy, extract Host header / SNI
|
+- Domain matches policy? -- Yes -> FORWARD to original destination
|                          -- No  -> DROP (connection reset)
|
+- LOG decision -> dashboard (if enabled)
```

Strengths: precise per-connection domain checks, works with CDNs and changing IPs.
Limits: domain filtering applies to ports 80/443 only; a client that sends no SNI is blocked (default-deny).

## dns mode

All DNS (UDP/TCP port 53) is redirected to an internal DNS proxy. Allowed domains resolve normally through the upstream resolver; non-allowlisted A/AAAA queries are sinkholed to 0.0.0.0/:: and other blocked query types get NXDOMAIN.

```text
Start
|
+- DNS query to port 53? -- No -> PASS (no domain check)
|
+- Redirect to local DNS proxy
|
+- Domain matches policy? -- Yes -> FORWARD to upstream resolver
|                          -- No  -> Resolves to an allowlisted IP? -- Yes -> return only those IPs
|                                                                    -- No  -> SINKHOLE A/AAAA or NXDOMAIN
|
+- LOG decision -> dashboard (if enabled)
```

When the policy has IP allowlist entries, a domain that is not domain-allowlisted is still resolved so its addresses can be checked; if any resolved IP is allowlisted the proxy replies with only those records (non-allowlisted IPs are stripped), matching https mode's connection-time IP allowance. With no IPs in the policy the domain is sinkholed as before.

Strengths: covers every protocol and port, cheapest data path (no proxying of the traffic itself).
Limits: enforcement happens at resolution only. A process that connects to a hardcoded IP, uses DNS-over-HTTPS, or replays a cached answer bypasses filtering entirely. Use `dns-strict` to close that gap.

## dns-strict mode

Everything dns mode does, plus: when an allowed domain resolves, the proxy pushes the answer's A/AAAA addresses into a kernel nftables set with a TTL-bounded timeout (60s floor, 24h cap), before the client sees the answer. The filter chain is default-drop, so connections to any IP that was never resolved through the proxy (hardcoded IPs, DoH, cached answers) are dropped.

```text
Start
|
+- Destination IP in allowlist/resolved set? -- Yes -> ALLOW
|
+- DNS query to port 53? -- Yes -> Redirect to DNS proxy
|      |
|      +- Domain matches policy? -- Yes -> Resolve, add answer IPs, return answer
|      |                          -- No  -> SINKHOLE A/AAAA or NXDOMAIN
|
+- Connection already established? -- Yes -> ALLOW
|
+- BLOCK
|
+- LOG decision -> dashboard (if enabled)
```

- Enforcement covers all ports and both IPv4/IPv6, entirely in the kernel
- Entries expire with the DNS TTL; established connections survive expiry via conntrack
- Resolved entries are flushed on policy reload and repopulate on the next resolution
- Requires `default_action: deny`; under default-allow or learning mode it degrades to plain dns mode with a warning
