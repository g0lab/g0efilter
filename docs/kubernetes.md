# Kubernetes

g0efilter runs as a native sidecar. Containers in a pod share one network
namespace, so the sidecar programs nftables before the application container
starts and filters everything the pod sends. The application container needs no
extra privileges.

The render-time integrations need no controller, webhook or Service. The optional
admission integration adds a controller and webhook, but filtering remains local
to each pod after it starts.

## Requirements

- g0efilter v0.8.0 or later. Earlier images start as root and drop privileges, so
  they need `SETUID`, `SETGID` and `CHOWN`, and they fail against the
  `runAsNonRoot: true` the packaging here sets.
- Kubernetes 1.29 or later, for sidecar init containers (`restartPolicy: Always`).
  GA since 1.33.
- A namespace that permits `NET_ADMIN`, which means Pod Security `privileged`.
  See [privileges](configuration.md#privileges) for why, and why the sidecar is
  still unprivileged in every other respect.
- A `g0efilter-policy` ConfigMap in the workload's namespace.

## Choose an integration

| You control | Use | Covers |
| --- | --- | --- |
| Plain manifests | [Kustomize component](#kustomize) | Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob |
| Your own Helm chart | [Helm library chart](#helm-library-chart) | Any pod template you template yourself |
| Nothing - a third-party chart | [Helm post-renderer](#helm-post-renderer) | Any chart, no fork and no values contract |
| Nothing at all, cluster-wide | [Mutating webhook](#mutating-webhook) | Any pod, including ones an operator creates |

### Kustomize

Reference the component from your overlay. It patches every workload kind it
finds, so nothing in your own manifests mentions g0efilter:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - policy.yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
```

Pin `ref` to a release tag. The component sets the image tag to match, so the
sidecar version and the component version never drift apart.

A complete overlay is in [examples/kubernetes](../examples/kubernetes); render it
with `kubectl kustomize examples/kubernetes`.

### Helm library chart

For a chart you maintain, declare the dependency:

```yaml
dependencies:
  - name: g0efilter
    version: 0.1.0
    repository: file://../../deploy/helm/g0efilter
```

Then include the sidecar as the **first** init container, and its volume:

```yaml
    spec:
      initContainers:
        {{- include "g0efilter.sidecar" . | nindent 8 }}
      containers:
        - name: app
          image: {{ .Values.image }}
      volumes:
        {{- include "g0efilter.policyVolume" . | nindent 8 }}
```

Ordering matters: an init container placed before the sidecar runs with
unfiltered egress. That bites charts which fetch config or run database
migrations during init.

Override defaults under a `g0efilter` key; anything you leave out comes from the
library chart's own `values.yaml`:

```yaml
g0efilter:
  mode: dns-strict
  logLevel: DEBUG
  image:
    tag: v0.8.0
  policy:
    configMapName: my-policy
```

Values are validated against
[values.schema.json](../deploy/helm/g0efilter/values.schema.json), so a misspelled
key or an invalid mode fails the render instead of silently doing nothing.

If events are enabled, also render the RBAC and mount the token:

```yaml
{{- include "g0efilter.eventsRBAC" . }}
```

```yaml
    spec:
      automountServiceAccountToken: true
```

A working example is in [examples/helm/demo](../examples/helm/demo).

### Helm post-renderer

For a chart you do not control, inject at render time instead of editing it:

```sh
helm install app oci://example.com/app \
  --post-renderer deploy/helm/post-renderer.sh
```

Outside this repository, point the script at a pinned component:

```sh
export G0EFILTER_COMPONENT='github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0'
```

This is the only path that needs no cooperation from the chart at all. It still
requires the policy ConfigMap and the namespace label.

### Mutating webhook

The three integrations above add the sidecar when the manifest is rendered. The
webhook adds it at admission instead, so pods created by an operator, a CI job or
anything else you do not template are filtered too.

Install the control plane with the webhook overlay:

```sh
kubectl apply --server-side -f deploy/crds/
kubectl apply -k deploy/webhook
```

Then opt a namespace in and write a policy that selects the pods:

```sh
kubectl label namespace tenant-a g0efilter.io/inject=enabled
```

```yaml
apiVersion: g0efilter.io/v1alpha1
kind: EgressPolicy
metadata:
  name: web
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: web
  sidecar:
    events: true
  egress:
    - name: apis
      to:
        - domainNames: ['api.example.com']
```

Wait for the policy before creating its workloads:

```sh
kubectl -n tenant-a wait --for=condition=Ready egresspolicy/web --timeout=2m
```

Any pod in `tenant-a` labelled `app: web` gets the sidecar, the policy volume and
the scrape annotations, with the sidecar first in `initContainers`.

The controller renders one ConfigMap per `EgressPolicy`. Admission waits for the
policy's current generation to be Ready, so a pod is not created with a missing or
stale policy volume. If a policy update is rejected, existing pods keep enforcing
the previous ConfigMap while new selected pods are denied until the policy is fixed.

`ClusterEgressPolicy` provides additive baseline rules. Its `namespaceSelector`
chooses namespaces, and its rules are merged into every `EgressPolicy` there. It
cannot remove an allowance from a namespaced policy.

Rules with ports must match the selected sidecar mode. `https` can enforce ports
on network peers; `dns-strict` can enforce ports on network and domain peers.
Plain `dns` cannot enforce port-constrained rules, so the controller marks such a
policy not Ready instead of silently widening it.

### Webhook certificates

An admission webhook must be served over TLS and the API server has to trust it.
By default the controller issues its own certificate, stores it in a Secret,
writes the CA into the `MutatingWebhookConfiguration`, and renews it a month
before it expires. Nothing else has to be installed.

Use cert-manager instead when a managed issuer is required:

```sh
kubectl apply -k deploy/webhook-cert-manager
```

That overlay creates a `Certificate`, mounts its Secret, lets cainjector fill the
`caBundle`, and passes `--webhook-cert-source=external` so the controller does
not touch either.

The default is self-signed rather than cert-manager on purpose. The trust
relationship is narrow: one CA, one Service name, one consumer, and both ends are
published by the same controller. Requiring cert-manager would add an install
ordering dependency to a webhook configured `failurePolicy: Fail`, so a
cert-manager problem could stop pods being admitted.

`spec.sidecar` tunes the injected container: `image`, `mode`, `logLevel`,
`events`, `metrics` and `resources`. The defaults match the Kustomize component
and the Helm chart.

**Opting out.** Set `g0efilter.io/inject: "false"` as a pod annotation or label.
Pods that already carry a `g0efilter` container, and host-network pods, are
skipped.

**Two policies selecting one pod is rejected.** Each policy renders its own
ConfigMap, so admission fails rather than guessing. Set the
`g0efilter.io/policy: <name>` annotation on the pod to choose.

> [!WARNING]
> The webhook is configured `failurePolicy: Fail`, so it fails closed: if the
> controller is unreachable, pod creation in opted-in namespaces stops rather
> than admitting unfiltered pods. `g0efilter-system` and `kube-system` are
> excluded so the controller itself can always be rescheduled. Switch to
> `Ignore` only if availability matters more than the guarantee.

### Denial visibility

Denials are logged and sent to the dashboard by default. To also surface the first
few on the pod itself, so they show up in `kubectl describe pod`:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
  - github.com/g0lab/g0efilter//deploy/kustomize/events?ref=v0.8.0
```

This is opt-in because it is the only feature that gives the pod Kubernetes API
access. The permission is narrow - `create` on `events` in one namespace, nothing
readable - but because a pod has a single ServiceAccount it is granted to the
*workload's* ServiceAccount, not to the sidecar alone. The add-on binds the
`default` ServiceAccount; patch the RoleBinding subject if the workload uses
another, and note that it also sets `automountServiceAccountToken: true`.

**Allow the API server in the policy.** The sidecar's own egress is filtered by the
policy it enforces, so without a rule for the Kubernetes Service it blocks its own
Event reports and nothing appears on the pod:

```sh
kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}'
```

Events are capped per pod (`KUBE_EVENTS_MAX`, default 10) and deduplicated by
destination and reason, so a port scan cannot flood the event stream. If the RBAC
is missing, g0efilter logs one warning and keeps filtering.

### Metrics

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
  - github.com/g0lab/g0efilter//deploy/kustomize/metrics?ref=v0.8.0
```

Or `g0efilter.metrics.enabled: true` with the Helm chart. Both expose `/metrics` on
port 9095 and add `prometheus.io/*` scrape annotations.

```
g0efilter_connections_total{component,action}
g0efilter_denials_total{component,reason}
g0efilter_policy_reloads_total{result}
```

Series are keyed on component, verdict and reason - **never on destination** - so a
port scan cannot grow the series count. Distinct label combinations are capped per
metric and overflow is folded into a `reason="other"` series, so totals stay correct
even under abuse.

### Building a policy by observation

Learning mode blocks nothing and appends every destination the workload reaches to
its policy file. Because the policy has to be writable, the add-on swaps the
read-only ConfigMap mount for an emptyDir the sidecar seeds itself:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
  - github.com/g0lab/g0efilter//deploy/kustomize/learning?ref=v0.8.0
```

Or `g0efilter.learning.enabled: true` with the Helm chart.

Exercise the workload, then turn what it learned into something committable:

```sh
kubectl -n <ns> exec <pod> -c g0efilter -- /app/g0efilter policy > policy.yaml
kubectl apply -f policy.yaml
```

The output is a ConfigMap, already namespaced and keyed to match the mount, so it
can also be piped straight to `kubectl apply -f -`. The command validates the policy
first, so a malformed learned file fails locally instead of on the cluster. Commit
`policy.yaml` and remove the learning component to start enforcing.

The learned policy lives in an emptyDir, so it is lost when the pod is replaced -
capture it before then. `/app/g0efilter policy` also works outside learning mode, to
print whatever policy a running sidecar is actually enforcing.

## Policy

The policy is a ConfigMap mounted as a directory. Mount the directory, not a
single file via `subPath`: kubelet updates a ConfigMap by swapping a symlink,
which a `subPath` mount never sees, and live reload would stop working.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: g0efilter-policy
data:
  policy.yaml: |
    allowlist:
      ips:
        - '10.96.0.10'
      domains:
        - 'api.example.com'
        - '*.cdn.example.com'
```

Edit the ConfigMap and g0efilter reloads it in place; no pod restart is needed.
See [policy.md](policy.md) for the full schema.

Expect up to a minute or two, not seconds: kubelet refreshes a mounted ConfigMap
on its own sync period, and the sidecar can only see the file after that. Its own
5-second check is not the limit, and `SIGHUP` does not help because the file in
the pod has not changed yet.

A policy the agent refuses to load leaves the previous one in force rather than
opening egress. That shows up as a `PolicyReloadFailed` Event on the pod when
`events` are enabled, and as `g0efilter_policy_reloads_total{result="failure"}`.

**Always allow cluster DNS.** g0efilter is default-deny, so without the DNS
ClusterIP every name lookup fails and every request looks blocked for reasons
unrelated to your domain rules:

```sh
kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'
```

In `https` mode only ports 80 and 443 are matched by domain. Anything else must be
allowed by IP or CIDR - including in-cluster traffic to other Services, which
NetworkPolicy can then narrow further.

## Verify

```sh
kubectl -n <ns> logs <pod> -c g0efilter | head
```

`startup.capabilities` reports the runtime uid, and `startup.ready` means the
ruleset is live. Then test one allowed and one blocked destination:

```sh
kubectl -n <ns> exec <pod> -c app -- curl -fsS https://api.example.com
kubectl -n <ns> exec <pod> -c app -- curl -fsS --max-time 5 https://example.org
```

## Troubleshooting

**`exec /app/g0efilter: operation not permitted`, and the pod never starts.**
The container was not granted `NET_ADMIN`. The kernel refuses to apply the
binary's file capabilities, and refuses the exec rather than starting it
unprivileged. Add the capability:

```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_ADMIN]
```

**Everything is blocked, including things you allowed.** Cluster DNS is almost
always the cause. Check the allowlist contains the kube-dns ClusterIP.

**Check a pod's privileges directly:**

```sh
kubectl -n <ns> exec <pod> -c g0efilter -- /app/g0efilter caps
```

It prints the capability state, confirms a child `nft` process can reach netlink,
and exits non-zero with a remediation hint if not.

**A pod is running but unfiltered.** Confirm the sidecar is the first entry in
`initContainers`:

```sh
kubectl -n <ns> get pod <pod> -o jsonpath='{.spec.initContainers[*].name}'
```

## Limits

- `hostNetwork: true` pods cannot be filtered per-pod, because the network
  namespace is the host's.
- The namespace needs Pod Security `privileged`, because `NET_ADMIN` is outside
  the `baseline` capability allow-list. Put filtered workloads in their own
  namespace rather than relaxing a shared one.
- The Kustomize, Helm and post-renderer integrations only cover rendered pod
  templates. Use the webhook for pods created dynamically by operators or users.
