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

The policy reloads when the file changes. Mount its directory so editors that
replace files during save do not break reloads:

```yaml
volumes:
  - ./policy/:/app/policy/
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

Set `PROCESS_INFO=true` to add the owning PID and command to flow logs. The
agent must share a PID namespace with the workload. Otherwise, the process name
is reported as `unknown`.

See [example policies](../examples/policy/) for complete files.
