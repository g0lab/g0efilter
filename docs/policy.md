# Policy

## Allowlist

The default policy blocks traffic unless an IP or domain matches the allowlist:

```yaml
allowlist:
  ips:
    - '1.1.1.1'
    - '192.168.0.0/16'
  domains:
    - 'github.com'                    # exact
    - '*.alpinelinux.org'             # wildcard
    - 'bucket.*.r2.example.com'       # mid-name wildcard
    - '/cache-[0-9]+\.example\.com/'  # regular expression
```

`*` matches one or more characters, including dots. Regular expressions are
case-insensitive and match the whole hostname.

### Protocol and port constraints

An allowlist IP entry can be restricted to a protocol and port. A bare IP or
CIDR still allows every port.

```yaml
allowlist:
  ips:
    - '1.2.3.4'
    - '1.2.3.4:3389'            # tcp is implied
    - 'udp/1.2.3.4:53'
    - 'tcp/[2606:4700::1]:443'
    - '[192.168.0.0/16]:443'
    - 'udp/[2606:4700::/32]:53'
```

CIDR ranges use the same syntax. Brackets are required around an IPv6 address or
CIDR when a port follows and are optional for IPv4.

A protocol prefix must be `tcp` or `udp` and requires a port. Port constraints
are enforced by the default-deny packet filter (`https` and `dns-strict`).
They are rejected at startup in `dns` mode and permissive configurations
(`default_action: allow` or learning mode), where they cannot be enforced.

#### Domain entries (dns-strict only)

Allowlist domains take the same syntax, on exact, wildcard and regex patterns:

```yaml
allowlist:
  domains:
    - 'github.com'
    - 'tcp/github.com:443'
    - 'udp/ntp.example.com:123'
    - '*.cdn.example.com:443'
```

The DNS proxy adds each answer to a protocol/port set that expires with the
record's TTL. This IP-layer enforcement is available only in default-deny
`dns-strict`; other modes and permissive configurations reject constrained
domains at startup.

Resolved-IP enforcement has two consequences:

- The kernel matches on address, not hostname. On shared hosting or a CDN,
  `tcp/example.com:443` opens tcp/443 to whatever address that name resolves to,
  including other sites served from it.
- An unconstrained domain or IP entry for the same address takes precedence.

The policy reloads when the file changes. Mount its directory so editors that
replace files during save do not break reloads:

```yaml
volumes:
  - ./policy/:/app/policy/
```

The file is hashed every five seconds; unchanged content does not reload. Send
`SIGHUP` to apply a changed file immediately:

```sh
docker kill --signal HUP g0efilter
```

Environment variables can replace file-based lists. See
[environment variables](configuration.md#environment-variables).

## Default-allow denylist

Set `default_action: 'allow'` to allow traffic unless it matches the denylist. An
allowlist match always wins.

```yaml
default_action: 'allow'
allowlist:
  domains:
    - 'api.github.com'
denylist:
  ips:
    - '192.168.0.0/16'
  domains:
    - '*.github.com'
    - '*.doubleclick.net'
```

Changing `default_action` live-reloads with the rest of the policy. The denylist
is ignored when the action is `deny`.

## Learning mode

Set `LEARNING_MODE=true` to allow all traffic and append new domains or
destination IPs to the policy. Review the result before returning to
enforcement.

## Audit mode

Set `ENFORCE=audit` to allow traffic while logging decisions that enforcement
would block. Audit mode does not change the policy file.

## Process details

Set `PROCESS_INFO=true` to add the owning PID, process name, executable, cgroup,
and container ID to flow logs when available. The agent must share a PID
namespace with the workload. Otherwise, the process name is reported as
`unknown`. Command lines are omitted because arguments can contain secrets; set
`PROCESS_CMDLINE=true` only when that exposure is acceptable.

Process identity is observability metadata and is not a policy selector.

See [example policies](../examples/policy/) for complete files.
