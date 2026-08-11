# Kubernetes with Kustomize

This overlay requires Kubernetes 1.29 or later. Before applying it, replace
`10.96.0.10` in `policy.yaml` with your cluster DNS Service address:

```sh
kubectl -n kube-system get service -l k8s-app=kube-dns -o jsonpath='{.items[0].spec.clusterIP}'
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
