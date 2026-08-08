# Kubernetes packaging

Three ways to attach the g0efilter sidecar, all injecting an identical container:

| Path | Use when |
| --- | --- |
| `kustomize/sidecar` | You render plain manifests with Kustomize. |
| `helm/g0efilter` | You maintain the chart and can include a template. |
| `helm/post-renderer.sh` | The chart is someone else's and cannot be edited. |

Three optional Kustomize add-ons layer on top of `kustomize/sidecar`, with Helm
equivalents under `g0efilter.events`, `g0efilter.learning` and
`g0efilter.metrics`:

| Add-on | Effect |
| --- | --- |
| `kustomize/events` | Records the first denials as Events on the pod. The only feature that grants Kubernetes API access. |
| `kustomize/learning` | Runs in learning mode against a writable emptyDir, to build a policy by observation. |
| `kustomize/metrics` | Serves Prometheus metrics on port 9095 with scrape annotations. |

`tests/manifests/` renders all three and fails if the sidecar they produce
diverges. See [docs/kubernetes.md](../docs/kubernetes.md) for usage.

Released library charts are available from the Helm repository at
`https://g0lab.github.io/g0efilter` and from the OCI registry at
`oci://ghcr.io/g0lab/helm/g0efilter`.
