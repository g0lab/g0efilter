# Helm library chart

This chart shows the minimum templates needed to consume the published g0efilter
library chart. Replace `10.96.0.10` in `values.yaml` with your cluster DNS Service
address (`kubectl -n kube-system get service -l k8s-app=kube-dns -o
jsonpath='{.items[0].spec.clusterIP}'`), then run from the repository root:

This example requires Kubernetes 1.29 or later.

```sh
helm dependency update --skip-refresh examples/helm/demo
kubectl create namespace g0efilter-demo
kubectl label namespace g0efilter-demo pod-security.kubernetes.io/enforce=privileged
helm install demo examples/helm/demo --namespace g0efilter-demo
```

Test the workload:

```sh
kubectl -n g0efilter-demo exec deployment/demo -c app -- curl -fsS https://example.com
kubectl -n g0efilter-demo exec deployment/demo -c app -- curl -I --max-time 5 https://github.com
```

See the [Helm library chart guide](../../../docs/kubernetes.md#helm-library-chart)
for published dependencies and optional settings.
