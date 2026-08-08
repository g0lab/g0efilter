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

The first three render the sidecar into the manifest, so they need no controller.
The webhook adds one, installed with the
[`g0efilter-controller` chart](#installing-the-control-plane) or the Kustomize
overlays. All four produce the same container: `tests/manifests/` and
`controller/internal/webhook/parity_test.go` fail the build if they drift.

### Published charts

| Chart | Type | Use |
| --- | --- | --- |
| `g0efilter-controller` | application | The control plane: controller, webhook, CRDs and RBAC. One `helm install` per cluster. |
| `g0efilter-dashboard` | application | The dashboard the sidecars ship their logs to. |
| `g0efilter` | library | Sidecar templates for a chart you maintain. Not installable on its own - Helm refuses to install a library chart. |

All three are published to `https://g0lab.github.io/g0efilter` and to
`oci://ghcr.io/g0lab/helm`, and share the release's version.

#### Upgrades and rollback

The application charts use normal Helm-managed resources and support Helm's release
rollback:

```sh
helm history g0efilter -n g0efilter-system
helm rollback g0efilter <revision> -n g0efilter-system --wait
```

With Helm 4, use `helm upgrade --rollback-on-failure`; with Helm 3, use
`helm upgrade --atomic`. A rollback restores the rendered Kubernetes resources and
image tags, not application data. The dashboard claim is retained, so back up SQLite
before an upgrade whose migrations may not be backward-compatible.

The controller chart manages CRDs as templates so upgrades and rollbacks apply their
schemas. Existing custom resources are not rewound, so confirm they remain valid for
the older CRD and controller before rolling the control plane back.

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

Layer the optional components after `sidecar`:

| Component | Effect |
| --- | --- |
| `audit` | `ENFORCE=audit`: log what the policy would deny and allow it through anyway |
| `metrics` | Serve Prometheus metrics on 9095 and add the scrape annotations |
| `events` | Record the first denials as Kubernetes Events, with the RBAC to do it |
| `learning` | Observe and append what is seen to a writable policy, blocking nothing |
| `process-info` | Add the originating pid and process name to flow logs |

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.0
  - github.com/g0lab/g0efilter//deploy/kustomize/audit?ref=v0.8.0
```

`audit` and `learning` are not the same thing. `audit` keeps enforcing the policy's
verdicts in the logs while letting the traffic pass, so it reports against the policy
you wrote. `learning` has no policy to report against and rewrites one instead.

`process-info` sets `shareProcessNamespace: true`, which also lets every container in
the pod see and signal the others' processes. Leave it off unless the attribution is
worth that.

A complete overlay is in [examples/kubernetes](../examples/kubernetes); render it
with `kubectl kustomize examples/kubernetes`.

### Helm library chart

For a chart you maintain, add the GitHub Pages repository and declare the
dependency. The `0.x.x` constraint follows the newest v0 chart without naming a
patch release that may not exist yet:

```sh
helm repo add g0efilter https://g0lab.github.io/g0efilter
helm repo update
```

```yaml
dependencies:
  - name: g0efilter
    version: 0.x.x
    repository: https://g0lab.github.io/g0efilter
```

OCI is available as an alternative. Helm appends the dependency name to this
repository path, resolving `oci://ghcr.io/g0lab/helm/g0efilter`:

```yaml
dependencies:
  - name: g0efilter
    version: 0.x.x
    repository: oci://ghcr.io/g0lab/helm
```

Run `helm dependency update` after choosing either source. The example in this
repository uses a `file://` dependency so it always tests the local chart.

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
  enforcement: audit
  logLevel: DEBUG
  image:
    tag: v0.8.0
  policy:
    configMapName: my-policy
  dashboard:
    host: http://g0efilter-dashboard.g0efilter-system.svc:8081
    apiKeySecret:
      name: g0efilter-dashboard-key
```

The chart exposes the same options as the `EgressPolicy`
[sidecar block](#sidecar-options), named for Helm rather than for Kubernetes API
conventions: `tenantId`, `processInfo`, `events.maxDenials`, `dashboard.*`,
`notifications.*`, `dns.*`, `ports.*`, `connections.*` and `nflog.*`. Two differ
because Helm has no duration type, so the millisecond value is named for its unit:
`connections.maxLifetimeMs`, while `dashboard.startDelay` is a duration string the
agent parses itself.

A numeric value left `null` is not rendered, so the agent applies its own default.
That distinction matters where `0` means something: `connections.max: 0` is
unlimited, and `events.maxDenials: 0` records no Events at all.

Values are validated against
[values.schema.json](../deploy/helm/g0efilter/values.schema.json), so a misspelled
key or an invalid mode fails the render instead of silently doing nothing.

`processInfo` is the one option the library chart cannot fully apply on its own: it
needs `shareProcessNamespace: true` on the pod template, which belongs to your chart
rather than to the sidecar.

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

#### Installing the control plane

The chart is the shortest path. It installs the CRDs, the controller, the webhook
and its RBAC, and issues its own serving certificate:

```sh
helm install g0efilter oci://ghcr.io/g0lab/helm/g0efilter-controller \
  --namespace g0efilter-system --create-namespace
```

The controller itself needs no capabilities, so its namespace can run the
`restricted` Pod Security Standard - unlike a filtered workload's:

```sh
kubectl label namespace g0efilter-system pod-security.kubernetes.io/enforce=restricted
```

The Kustomize overlays install the same thing, for a cluster managed without Helm.
CRDs are applied separately there so that Argo CD and Helm do not fight over
ordering:

```sh
kubectl apply --server-side -f deploy/crds/
kubectl apply -k deploy/webhook            # or deploy/webhook-cert-manager
```

The chart's most useful values:

| Value | Default | Effect |
| --- | --- | --- |
| `crds.install` | `true` | Install the CRDs from the chart. Set false when a separate sync wave applies them. They are annotated `helm.sh/resource-policy: keep`, so uninstalling never deletes your policies. |
| `webhook.enabled` | `true` | With false the controller only renders policies into ConfigMaps and injects nothing. |
| `webhook.failurePolicy` | `Fail` | Fails closed: an unreachable webhook blocks pod creation in opted-in namespaces rather than admitting unfiltered pods. |
| `webhook.certificate.source` | `self-signed` | `cert-manager` hands issuing and rotation to cert-manager instead. Needs cainjector. |
| `sidecar.image` | the release default | The image the webhook injects. |
| `replicaCount` | `2` | Leader election keeps one replica reconciling; both serve admission. |
| `metrics.service.enabled` | `false` | Also `metrics.serviceMonitor.enabled` for Prometheus Operator. |

The release namespace is always excluded from injection, so a failing webhook can
never stop the control plane being rescheduled.

#### Writing a policy

Opt a namespace in and write a policy that selects the pods:

```sh
kubectl label namespace tenant-a g0efilter.io/inject=enabled
kubectl label namespace tenant-a pod-security.kubernetes.io/enforce=privileged
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
    # Observe before enforcing. Switch to block once the logs are clean.
    enforcement: audit
    events:
      enabled: true
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

#### Sidecar options

`spec.sidecar` tunes the injected container. Every field is optional; anything left
out keeps the agent's own default, and the injector leaves it out of the pod
entirely. The Kustomize component and the library chart ignore this block - they
carry their own settings.

`mode` and `enforcement` are different axes. `mode` picks the data path that reads a
destination; `enforcement` decides what happens once a verdict exists.

| Field | Sets | Notes |
| --- | --- | --- |
| `image`, `imagePullPolicy` | - | The sidecar image. Defaults to the controller's pinned release. |
| `mode` | `FILTER_MODE` | `https`, `dns` or `dns-strict`. |
| `enforcement` | `ENFORCE` | `block` or `audit`. Always rendered, so a pod's posture is readable without knowing the default. |
| `logLevel` | `LOG_LEVEL` | |
| `processInfo` | `PROCESS_INFO` | Also sets `shareProcessNamespace: true` on the pod, which lets every container see and signal the others' processes. |
| `tenantId` | `TENANT_ID` | Tenant identifier on netfilter log events. |
| `events.enabled` | `KUBE_EVENTS` | Needs `create` on events for the pod's ServiceAccount. |
| `events.maxDenials` | `KUBE_EVENTS_MAX` | Caps Events per pod. `0` records none. |
| `metrics.enabled`, `metrics.port` | `METRICS_ADDR` | Also declares the container port. |
| `metrics.annotations` | - | Adds `prometheus.io/*` to the pod. |
| `dashboard.host` | `DASHBOARD_HOST` | Where to ship logs. |
| `dashboard.apiKeySecretRef` | `DASHBOARD_API_KEY` | Read from a Secret in the pod's namespace. |
| `dashboard.queueSize` | `DASHBOARD_QUEUE_SIZE` | Oldest entries drop when full, so shipping never blocks traffic. |
| `dashboard.startDelay` | `DASHBOARD_START_DELAY` | A duration, e.g. `10s`. |
| `dashboard.remoteUnblock` | `ENABLE_REMOTE_UNBLOCK` | |
| `dashboard.unblockPollInterval` | `UNBLOCK_POLL_INTERVAL` | |
| `notifications.host` | `NOTIFICATION_HOST` | Gotify server. |
| `notifications.keySecretRef` | `NOTIFICATION_KEY` | Read from a Secret in the pod's namespace. |
| `notifications.backoffSeconds` | `NOTIFICATION_BACKOFF_SECONDS` | |
| `notifications.ignoreDomains` | `NOTIFICATION_IGNORE_DOMAINS` | Wildcards allowed. |
| `dns.upstreams` | `DNS_UPSTREAMS` | `host:port` list. |
| `dns.hardening` | `DNS_HARDENING` | On unless set to false. |
| `dns.rateQps`, `dns.rateBurst` | `DNS_RATE_QPS`, `DNS_RATE_BURST` | One budget for the whole pod, not per client. |
| `ports.http`, `ports.https`, `ports.dns` | `HTTP_PORT`, `HTTPS_PORT`, `DNS_PORT` | For a workload that already binds 65080, 65443 or 65053. |
| `connections.max` | `MAX_CONNECTIONS` | `0` is unlimited. |
| `connections.maxLifetime` | `CONN_MAX_LIFETIME_MS` | A duration. One absolute deadline, not an idle timeout. |
| `nflog.bufSize`, `nflog.qthresh` | `NFLOG_BUFSIZE`, `NFLOG_QTHRESH` | Raise only if the logs report dropped netfilter messages. |
| `runAsUser`, `runAsGroup` | - | Must not be 0. |
| `resources` | - | Requests and limits. |
| `extraEnv` | - | For agent options this API does not model yet. |

The sidecar filters its own egress as well as the application's, so anything it has
to reach must be allowed by the same policy: the API server for `events`, and the
hosts named by `dashboard.host` and `notifications.host`.

Credentials are referenced, never inlined - an `EgressPolicy` is readable by anyone
with `get` on it. The controller never reads the Secret; kubelet resolves it in the
pod's namespace, so a missing key shows up as the pod failing to start rather than as
a sidecar with no key.

`extraEnv` cannot set anything the fields above already derive, nor `ALLOWLIST_*`,
`DENYLIST_*`, `DEFAULT_ACTION`, `LEARNING_MODE`, `POLICY_PATH` or
`POLICY_CONFIGMAP`. Those replace the rendered policy wholesale, so a pod would stop
enforcing the `EgressPolicy` that selected it. The CRD rejects them:

```console
$ kubectl apply -f bypass.yaml
The EgressPolicy "web" is invalid: spec.sidecar.extraEnv: Invalid value: "array":
extraEnv must not set ALLOWLIST_*, DENYLIST_*, DEFAULT_ACTION, LEARNING_MODE,
POLICY_PATH or POLICY_CONFIGMAP: they would stop the sidecar enforcing this policy
```

There is no `learning` option here for the same reason: learning mode needs a
writable policy file, which would displace the ConfigMap the controller rendered.
Use `enforcement: audit` instead - it reports against the policy you wrote.

#### Rolling a policy out

A new policy is default-deny, so enforcing it immediately can break a workload on
its first request to something you forgot. Start by observing:

```yaml
  sidecar:
    enforcement: audit
```

Nothing is dropped. Everything the policy would have denied is logged as an `audit`
decision, with the destination:

```sh
kubectl -n tenant-a logs deploy/web -c g0efilter | grep audit
```

Add what you find to `egress`, and once the audit lines stop, switch over:

```sh
kubectl -n tenant-a patch egresspolicy/web --type=merge \
  -p '{"spec":{"sidecar":{"enforcement":"block"}}}'
kubectl -n tenant-a rollout restart deployment/web
```

The restart is required. Policy *rules* reload live from the ConfigMap, but
`enforcement` is part of the pod spec the webhook wrote at admission, so it only
changes when the pod is recreated.

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

The controller exposes its own metrics on 8080. Enable
`metrics.service.enabled` in the controller chart, and
`metrics.serviceMonitor.enabled` with Prometheus Operator.

### Dashboard

The dashboard collects what the sidecars ship and shows live and stored traffic:

```sh
helm install g0efilter-dashboard oci://ghcr.io/g0lab/helm/g0efilter-dashboard \
  --namespace g0efilter-system
```

It keeps its state in SQLite, so the chart runs exactly one replica with the
`Recreate` strategy and a `ReadWriteOnce` claim. Scaling it out needs more than a
replica count and is not supported. The claim is annotated
`helm.sh/resource-policy: keep`, so an uninstall does not throw away the history; set
`ephemeral: true` (with `persistence.enabled: false`) for a throwaway install that
keeps everything in memory.

By default the dashboard generates an admin password and a machine API key on first
start and prints each once:

```sh
kubectl -n g0efilter-system logs deploy/g0efilter-dashboard | grep -iE 'password|api key'
```

Supply them yourself with a Secret you manage, which keeps them out of the Helm
release:

```sh
kubectl -n g0efilter-system create secret generic g0efilter-dashboard \
  --from-literal=api-key="$(openssl rand -hex 32)" \
  --from-literal=admin-password-hash="$(docker run --rm -i docker.io/g0lab/g0efilter-dashboard:v0.8.0 hash-password)"
```

```yaml
secrets:
  existingSecret: g0efilter-dashboard
```

Then point the sidecars at it. The API key Secret is resolved by kubelet in the
workload's own namespace, so it has to exist in each namespace that ships logs, and
the policy has to allow the dashboard - a sidecar filters its own egress too:

```yaml
spec:
  sidecar:
    dashboard:
      host: http://g0efilter-dashboard.g0efilter-system.svc:8081
      apiKeySecretRef:
        name: g0efilter-dashboard-key
        key: api-key
  egress:
    - name: dashboard
      to:
        - domainNames: ['g0efilter-dashboard.g0efilter-system.svc']
```

`auth.mode` defaults to `session`. `none` leaves the UI and its sensitive endpoints
unauthenticated and is only safe behind a proxy that authenticates for it; `forward`
and `jwt` delegate to one. See
[dashboard authentication](configuration.md#dashboard-authentication).

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
