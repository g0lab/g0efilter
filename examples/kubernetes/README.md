# Kubernetes with Kustomize

This overlay requires Kubernetes 1.29 or later. Cluster DNS needs no entry in the
policy: the sidecar reads the pod's resolver and allows it on port 53.

```sh
kubectl apply -k examples/kubernetes
```

Test one allowed and one blocked destination:

```sh
kubectl -n g0efilter-demo exec deployment/demo -c app -- curl -fsS https://example.com
kubectl -n g0efilter-demo exec deployment/demo -c app -- curl -I --max-time 5 https://github.com
```

See the [Kubernetes guide](../../docs/kubernetes.md) for Helm and admission
options. Admission installations can enable the controller chart's NetworkPolicy
after supplying the cluster's API-server source CIDRs; it is intentionally not
guessed by the portable Kustomize overlay.

When using admission injection, create the `EgressPolicy` before its workloads.
Where a `ClusterEgressPolicy` selects the namespace, new selected pods are also
rejected until the controller records that baseline's current revision.
