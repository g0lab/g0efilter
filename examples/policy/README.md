# Example policies

The Compose examples mount this directory and load `policy.yaml`. To try the
other policy, copy it over `policy.yaml`; live reload applies the change.

| File | Behavior |
| --- | --- |
| `policy.yaml` | Blocks everything except its allowlist |
| `policy-default-allow.yaml` | Allows everything except its denylist |

Domain lists accept exact names, wildcards, and regular expressions:

```yaml
domains:
  - 'github.com'
  - '*.example.com'
  - 'bucket.*.r2.example.com'
  - '/cache-[0-9]+\.example\.com/'
```

`*` can cross dots. Use a regular expression when a match must stay within one
domain label. Use single quotes for all policy string values.

See the main [policy guide](../../docs/policy.md) for denylist, learning, and
audit modes.
