# Kubernetes packaging

Four integrations attach the same sidecar:

| Path | Use when |
| --- | --- |
| `kustomize/sidecar` | You render plain manifests with Kustomize. |
| `helm/g0efilter` | You maintain the chart and can include a template. |
| `helm/post-renderer.sh` | The chart is someone else's and cannot be edited. |
| `helm/g0efilter-controller` or `webhook/` | Admission should inject it cluster-wide. |

Optional Kustomize components layer on `kustomize/sidecar`. Most have matching
library-chart values:

| Add-on | Effect |
| --- | --- |
| `kustomize/audit` | Logs denied decisions without blocking them. |
| `kustomize/events` | Records the first denials as Events on the pod. The only feature that grants Kubernetes API access. |
| `kustomize/learning` | Runs in learning mode against a writable emptyDir, to build a policy by observation. |
| `kustomize/metrics` | Serves Prometheus metrics on port 9095 with scrape annotations. |

`tests/manifests/` checks parity. See
[docs/kubernetes.md](../docs/kubernetes.md) for usage.

The Helm repository at `https://g0lab.github.io/g0efilter` and OCI namespace
`oci://ghcr.io/g0lab/helm` publish the library, controller, and dashboard charts.
