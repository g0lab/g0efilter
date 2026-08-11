# Kubernetes

g0efilter runs as a native sidecar. It programs nftables before application
containers start and filters their shared network namespace. Application
containers need no extra privileges.

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

The first three render the sidecar without a controller. The webhook uses the
[`g0efilter-controller` chart](#installing-the-control-plane) or Kustomize
overlays. Tests keep all four paths in sync.

### Published charts

| Chart | Type | Use |
| --- | --- | --- |
| `g0efilter-controller` | application | The control plane: controller, webhook, CRDs and RBAC. One `helm install` per cluster. |
| `g0efilter-dashboard` | application | The dashboard the sidecars ship their logs to. |
| `g0efilter` | library | Sidecar templates for a chart you maintain; not directly installable. |

All three are published to `https://g0lab.github.io/g0efilter` and to
`oci://ghcr.io/g0lab/helm`, and share the release's version.

#### Upgrades and rollback

The application charts support Helm release rollback:

```sh
helm history g0efilter -n g0efilter-system
helm rollback g0efilter <revision> -n g0efilter-system --wait
```

With Helm 4, use `helm upgrade --rollback-on-failure`; with Helm 3, use
`helm upgrade --atomic`. A rollback restores the rendered Kubernetes resources and
image tags, not application data. The dashboard claim is retained, so back up SQLite
before an upgrade whose migrations may not be backward-compatible.

The controller chart manages CRDs as templates, so their schemas also roll back.
Existing custom resources do not; check compatibility with the older controller
first.

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
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5
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
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5
  - github.com/g0lab/g0efilter//deploy/kustomize/audit?ref=v0.8.5
```

`audit` reports policy verdicts without blocking. `learning` builds a new policy
from observed traffic.

`process-info` sets `shareProcessNamespace: true`, which also lets every container in
the pod see and signal the others' processes. Leave it off unless the attribution is
worth that.

A complete overlay is in [examples/kubernetes](../examples/kubernetes); render it
with `kubectl kustomize examples/kubernetes`.

### Helm library chart

For a chart you maintain, add the repository and dependency. The `0.x.x`
constraint follows the newest v0 chart:

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

For OCI, Helm appends the dependency name to the repository path:

```yaml
dependencies:
  - name: g0efilter
    version: 0.x.x
    repository: oci://ghcr.io/g0lab/helm
```

Run `helm dependency update` after choosing either source. The example in this
repository uses the published OCI chart so it works without configuring a Helm
repository first.

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

Any init container before the sidecar has unfiltered egress.

Override defaults under a `g0efilter` key; anything you leave out comes from the
library chart's own `values.yaml`:

When using `dns` or `dns-strict`, set `dns.upstreams` to the cluster DNS Service.
The agent's `127.0.0.11:53` default is Docker-specific.

```yaml
g0efilter:
  mode: dns-strict
  enforcement: audit
  logLevel: DEBUG
  image:
    tag: v0.8.5
  policy:
    configMapName: my-policy
  dns:
    upstreams: ['10.96.0.10:53']
  dashboard:
    host: http://g0efilter-dashboard.g0efilter-system.svc:8081
    apiKeySecret:
      name: g0efilter-dashboard-key
```

The chart mirrors the `EgressPolicy` [sidecar options](#sidecar-options).
`connections.maxLifetimeMs` is expressed in milliseconds; dashboard durations
are strings such as `10s`.

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
export G0EFILTER_COMPONENT='github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5'
```

This path needs no cooperation from the chart. It still requires the policy
ConfigMap.

### Mutating webhook

The webhook injects at admission, covering pods that were not rendered through
the other integrations.

#### Installing the control plane

The chart installs the CRDs, controller, webhook, RBAC, and serving certificate:

```sh
helm install g0efilter oci://ghcr.io/g0lab/helm/g0efilter-controller \
  --namespace g0efilter-system --create-namespace
```

The controller itself needs no capabilities, so its namespace can run the
`restricted` Pod Security Standard - unlike a filtered workload's:

```sh
kubectl label namespace g0efilter-system pod-security.kubernetes.io/enforce=restricted
```

For Kustomize, apply CRDs before the webhook overlay:

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
| `networkPolicy.enabled` | `false` | Restrict webhook ingress to `networkPolicy.apiServerCIDRs`. Requires cluster-specific API-server source CIDRs. |
| `sidecar.image` | the release default | The image the webhook injects. |
| `replicaCount` | `2` | Leader election keeps one replica reconciling; both serve admission. |
| `metrics.service.enabled` | `false` | Also `metrics.serviceMonitor.enabled` for Prometheus Operator. |

The release namespace is always excluded from injection, so a failing webhook can
never stop the control plane being rescheduled.

#### Writing a policy

Opt a namespace in and write a policy that selects the pods:

```sh
kubectl label namespace tenant-a g0efilter.g0lab.com/inject=enabled
kubectl label namespace tenant-a pod-security.kubernetes.io/enforce=privileged
```

```yaml
apiVersion: g0efilter.g0lab.com/v1alpha1
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
  egress:
    - name: apis
      to:
        - domainNames: ['api.example.com']
```

Wait for the policy before creating its workloads:

```sh
kubectl -n tenant-a wait --for=condition=Ready egresspolicy/web --timeout=2m
```

Any pod in `tenant-a` labelled `app: web` gets the sidecar and policy volume, with
the sidecar first in `initContainers`.

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

`spec.sidecar` tunes webhook injection. Fields are optional; Kustomize and the
library chart use their own settings.

`mode` and `enforcement` are different axes. `mode` picks the data path that reads a
destination; `enforcement` decides what happens once a verdict exists.

| Field | Sets | Notes |
| --- | --- | --- |
| `image`, `imagePullPolicy` | - | The sidecar image. Defaults to the controller's pinned release. |
| `mode` | `FILTER_MODE` | `https`, `dns` or `dns-strict`. |
| `enforcement` | `ENFORCE` | `block` or `audit`. Always rendered, so a pod's posture is readable without knowing the default. |
| `logLevel` | `LOG_LEVEL` | |
| `processInfo` | `PROCESS_INFO` | Uses `hostPID` when set; otherwise the webhook enables the shared process namespace and rejects an explicit `shareProcessNamespace: false`. |
| `tenantId` | `TENANT_ID` | Tenant identifier on netfilter log events. |
| `events` | `KUBE_EVENTS` | Needs `create` on events for the pod's ServiceAccount. |
| `eventsMaxDenials` | `KUBE_EVENTS_MAX` | Caps Events per pod. `0` records none. |
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

The API server must be allowed when Kubernetes Events are enabled. Dashboard,
remote-unblock, notification, and upstream-DNS connections use marked sockets
that bypass the packet filter. In `dns` modes, hostname lookups still pass through
the DNS policy, so allow dashboard and notification hostnames when they are names
rather than IP addresses.

Credentials use Secret references because `EgressPolicy` is not a Secret. Kubelet
resolves them in the pod's namespace; the controller never reads them.

`extraEnv` cannot override derived settings or replace the rendered policy with
`ALLOWLIST_*`, `DENYLIST_*`, `DEFAULT_ACTION`, `LEARNING_MODE`, `POLICY_PATH`, or
`POLICY_CONFIGMAP`. The CRD rejects these names.

Learning mode needs a writable policy and is therefore unavailable here. Use
`enforcement: audit` to test the rendered policy.

#### Rolling a policy out

Start a default-deny policy in audit mode:

```yaml
  sidecar:
    enforcement: audit
```

Denied decisions are logged as `audit` without being dropped:

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
not touch either. It also removes the controller's certificate Secret and
`MutatingWebhookConfiguration` permissions entirely.

Self-signed is the default to avoid making a fail-closed webhook depend on
cert-manager startup. Use cert-manager when cluster policy requires a managed
issuer. In self-signed mode, Secret access is held in a namespace-scoped Role;
the only cluster-scoped certificate permission is `get` and `update` on the
named `MutatingWebhookConfiguration`.

### Webhook network isolation

The webhook Service is cluster-internal, but a ClusterIP alone does not prevent
other pods from connecting to it. The controller only returns admission patches -
the Kubernetes API server is still the component that applies them - but restricting
the listener is useful defense in depth.

API-server source addresses differ between managed clusters, self-hosted control
planes and CNIs, so the chart cannot safely guess them. After obtaining the source
CIDRs from the cluster provider, enable the ingress policy explicitly:

```yaml
networkPolicy:
  enabled: true
  apiServerCIDRs:
    - 10.0.0.0/24 # replace with this cluster's API-server source CIDR
```

Enabling the policy with an empty CIDR list is rejected. The policy keeps the health
probe port reachable, opens controller metrics only when its Service is enabled, and
accepts webhook traffic only from the configured CIDRs. Confirm pod admission before
rolling it out to every opted-in namespace: with `failurePolicy: Fail`, an incorrect
CIDR stops new pods in those namespaces.

The Kustomize webhook overlay does not install a guessed NetworkPolicy. Add an
equivalent cluster-specific policy when using that installation path.

**Opting out.** Set `g0efilter.g0lab.com/inject: "false"` as a pod annotation or label.
Pods that already carry a `g0efilter` container, and host-network pods, are
skipped.

**Two policies selecting one pod is rejected.** Each policy renders its own
ConfigMap, so admission fails rather than guessing. Set the
`g0efilter.g0lab.com/policy: <name>` annotation on the pod to choose.

> [!WARNING]
> The webhook is configured `failurePolicy: Fail`, so it fails closed: if the
> controller is unreachable, pod creation in opted-in namespaces stops rather
> than admitting unfiltered pods. `g0efilter-system` and `kube-system` are
> excluded so the controller itself can always be rescheduled. Switch to
> `Ignore` only if availability matters more than the guarantee.

### Denial visibility

Denials are logged. To also show the first few in `kubectl describe pod`:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5
  - github.com/g0lab/g0efilter//deploy/kustomize/events?ref=v0.8.5
```

This grants the workload ServiceAccount `create` on Events in its namespace and
mounts its token. The add-on binds `default`; patch the RoleBinding for another
ServiceAccount.

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
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5
  - github.com/g0lab/g0efilter//deploy/kustomize/metrics?ref=v0.8.5
```

Or `g0efilter.metrics.enabled: true` with the Helm chart. Both expose `/metrics` on
port 9095 and add `prometheus.io/*` scrape annotations.

```
g0efilter_connections_total{component,action}
g0efilter_denials_total{component,reason}
g0efilter_policy_reloads_total{result}
```

Metrics never label by destination. Label combinations are capped and overflow is
folded into `reason="other"`.

The controller exposes its own metrics on 8080. Enable
`metrics.service.enabled` in the controller chart, and
`metrics.serviceMonitor.enabled` with Prometheus Operator.

### Dashboard

The dashboard collects what the sidecars ship and shows live and stored traffic:

```sh
helm install g0efilter-dashboard oci://ghcr.io/g0lab/helm/g0efilter-dashboard \
  --namespace g0efilter-system --create-namespace
```

SQLite limits the chart to one replica with a `Recreate` strategy and
`ReadWriteOnce` claim. The retained claim survives uninstall. For an in-memory
install, set `ephemeral: true` and `persistence.enabled: false`.

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
  --from-literal=admin-password-hash="$(docker run --rm -i docker.io/g0lab/g0efilter-dashboard:v0.8.5 hash-password)"
```

```yaml
secrets:
  existingSecret: g0efilter-dashboard
  existingSecretKeys:
    apiKey: true
    adminPasswordHash: true
```

Declare only keys that are present. This lets the chart validate JWT setup and
show recovery instructions when an optional credential is generated at startup.

The API key Secret must exist in each workload namespace:

```yaml
spec:
  sidecar:
    dashboard:
      host: http://g0efilter-dashboard.g0efilter-system.svc:8081
      apiKeySecretRef:
        name: g0efilter-dashboard-key
        key: api-key
```

In `dns` and `dns-strict` modes, also allow the dashboard hostname so the DNS
proxy resolves it. The marked dashboard connection itself bypasses filtering.

`auth.mode` defaults to `session`. Use `none` only behind an authenticating proxy;
`forward` and `jwt` delegate authentication. See
[dashboard authentication](configuration.md#dashboard-authentication).

### Building a policy by observation

Learning mode appends observed destinations to a writable policy without blocking.
The add-on replaces the ConfigMap mount with an emptyDir:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.8.5
  - github.com/g0lab/g0efilter//deploy/kustomize/learning?ref=v0.8.5
```

Or `g0efilter.learning.enabled: true` with the Helm chart.

Exercise the workload, then turn what it learned into something committable:

```sh
kubectl -n <ns> exec <pod> -c g0efilter -- /app/g0efilter policy > policy.yaml
kubectl apply -f policy.yaml
```

The output is a validated ConfigMap and can be piped to `kubectl apply -f -`.
Commit it and remove the learning component to enforce it.

Capture the learned policy before its pod and emptyDir are replaced.
`/app/g0efilter policy` also prints the active policy outside learning mode.

## Policy

Mount the policy ConfigMap as a directory. A `subPath` file mount does not receive
kubelet updates, so live reload would stop.

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

Kubelet may take a minute or two to refresh the mount. The sidecar's five-second
check and `SIGHUP` cannot see an update before kubelet writes it.

A policy the agent refuses to load leaves the previous one in force rather than
opening egress. That shows up as a `PolicyReloadFailed` Event on the pod when
`events` are enabled, and as `g0efilter_policy_reloads_total{result="failure"}`.

**Allow cluster DNS in `https` mode.** Its default-deny packet filter otherwise
blocks the workload's resolver, so every request looks blocked for reasons
unrelated to domain rules:

```sh
kubectl -n kube-system get svc -l k8s-app=kube-dns -o jsonpath='{.items[0].spec.clusterIP}'
```

In `dns` and `dns-strict` modes, configure that address as `DNS_UPSTREAMS`
instead. The DNS proxy's marked upstream connection does not need a policy rule.

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
The container lacks `NET_ADMIN`, so the kernel rejects its file capabilities.
Add the capability:

```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_ADMIN]
```

**Everything is blocked, including things you allowed.** Check that `https` mode
allows the kube-dns ClusterIP, or that a DNS mode sets `DNS_UPSTREAMS` to it.

**Check a pod's privileges directly:**

```sh
kubectl -n <ns> exec <pod> -c g0efilter -- /app/g0efilter caps
```

It checks capabilities and child `nft` netlink access.

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
