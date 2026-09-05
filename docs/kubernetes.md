# Kubernetes

g0efilter runs as a native sidecar. It programs nftables before application
containers start and filters their shared network namespace. Application
containers need no extra privileges.

Render-time integrations need no controller, webhook or Service. Admission
injection adds a controller and webhook. Filtering still runs inside each pod.

## Requirements

- g0efilter v0.8.0 or later. Earlier images start as root and drop privileges, so
  they need `SETUID`, `SETGID` and `CHOWN`, and they fail against the
  `runAsNonRoot: true` the packaging here sets.
- Kubernetes 1.29 or later. Native sidecars use `restartPolicy: Always` and are
  stable in Kubernetes 1.33 and later.
- A namespace that permits `NET_ADMIN`, which means Pod Security `privileged`.
  See [privileges](configuration.md#privileges) for why, and why the sidecar is
  still unprivileged in every other respect.
- A policy ConfigMap in each workload namespace for render-time integrations.
  The controller creates policy ConfigMaps for admission injection.

## Choose an integration

| You control | Use | Covers |
| --- | --- | --- |
| Plain manifests | [Kustomize component](#kustomize) | Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob |
| Your own Helm chart | [Helm library chart](#helm-library-chart) | Any pod template in that chart |
| A third-party Helm chart | [Helm post-renderer](#helm-post-renderer) | Any rendered pod template, without forking the chart |
| Cluster admission | [Mutating webhook](#mutating-webhook) | Any selected pod, including pods created by an operator |

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
`helm upgrade --atomic`. A rollback restores rendered Kubernetes resources and
image tags, not application data. The dashboard claim is retained. Back up SQLite
before an upgrade if its migrations may not work with an older dashboard.

The controller chart manages CRDs as templates, so their schemas also roll back.
Existing custom resources do not; check compatibility with the older controller
first.

### Kustomize

Reference the component from your overlay. It patches every supported workload
in the Kustomization:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - policy.yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6
```

Pin `ref` to a release tag. The component sets the same image tag.

Layer the optional components after `sidecar`:

| Component | Effect |
| --- | --- |
| `audit` | `ENFORCE=audit`: log what the policy would deny and allow it through anyway |
| `metrics` | Serve Prometheus metrics on 9095 and add the scrape annotations |
| `events` | Record the first denials as Kubernetes Events, with the RBAC to do it |
| `learning` | Observe and append what is seen to a writable policy, blocking nothing |

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6
  - github.com/g0lab/g0efilter//deploy/kustomize/audit?ref=v0.9.6
```

`audit` reports policy verdicts without blocking. `learning` builds a new policy
from observed traffic.

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

Override defaults under `g0efilter`. Unset values come from the library chart's
`values.yaml`.

When using `dns` or `dns-strict`, set `dns.upstreams` to the cluster DNS Service.
The agent's `127.0.0.11:53` default is Docker-specific.

```yaml
g0efilter:
  mode: dns-strict
  enforcement: audit
  logLevel: DEBUG
  image:
    tag: v0.9.6
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

[values.schema.json](../deploy/helm/g0efilter/values.schema.json) validates the
values. A misspelled key or invalid mode fails the render.

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
export G0EFILTER_COMPONENT='github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6'
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

The controller itself needs no capabilities, so its namespace can use the
`restricted` Pod Security Standard. Filtered workload namespaces cannot:

```sh
kubectl label namespace g0efilter-system pod-security.kubernetes.io/enforce=restricted
```

For Kustomize, apply CRDs before the webhook overlay:

```sh
kubectl apply --server-side -f deploy/crds/
kubectl apply -k deploy/webhook            # or deploy/webhook-cert-manager
```

Key chart values:

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

The release namespace is always excluded from injection. A failing webhook cannot
stop the control plane from being rescheduled.

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

The controller renders one ConfigMap per `EgressPolicy`. Admission waits until the
current policy generation is Ready. If an update is rejected, existing pods keep
the previous ConfigMap and admission rejects new selected pods until the policy is
fixed.

`ClusterEgressPolicy` adds baseline rules. Its `namespaceSelector` chooses
namespaces, and the controller merges its rules into each `EgressPolicy` there.
It cannot remove an allowance from a namespaced policy.

Rules with ports must match the selected sidecar mode. `https` can enforce ports
on network peers; `dns-strict` can enforce ports on network and domain peers.
Plain `dns` cannot enforce port-constrained rules, so the controller marks such a
policy not Ready instead of silently widening it.

#### Sidecar options

`spec.sidecar` tunes webhook injection. Fields are optional; Kustomize and the
library chart use their own settings.

`mode` chooses how the agent reads a destination. `enforcement` decides whether a
denied verdict is blocked or only logged.

| Field | Sets | Notes |
| --- | --- | --- |
| `image`, `imagePullPolicy` | - | The sidecar image. Defaults to the controller's pinned release. |
| `mode` | `FILTER_MODE` | `https`, `dns` or `dns-strict`. |
| `enforcement` | `ENFORCE` | `block` or `audit`. Always rendered, so a pod's posture is readable without knowing the default. |
| `logLevel` | `LOG_LEVEL` | |
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
| `notifications.urlsSecretRef` | `NOTIFICATION_URLS` | shoutrrr service URLs, from a Secret because they carry tokens. |
| `notifications.backoffSeconds` | `NOTIFICATION_BACKOFF_SECONDS` | |
| `notifications.ignoreDomains` | `NOTIFICATION_IGNORE_DOMAINS` | See [notifications](configuration.md#notifications). |
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

Allow the API server when Kubernetes Events are enabled. Dashboard,
remote-unblock, notification HTTP and upstream-DNS connections use marked
sockets. Their hostname lookups are marked too, so they need no policy rule.
The `smtp` and `mqtt` notification services dial unmarked and must be allowed.

Credentials use Secret references because `EgressPolicy` is readable as a custom
resource. Kubelet resolves them in the pod's namespace, and the controller never
reads them. Notification URLs also belong in a Secret because they contain access
tokens.

Read notification URLs from a file. A command-line literal can appear in shell
history and process listings.

```sh
umask 077 && cat > urls <<'EOF'
ntfy://ntfy.sh/my-topic telegram://BOT_TOKEN@telegram?chats=CHAT_ID
EOF
kubectl create secret generic g0efilter-notifications --from-file=urls
rm urls
```

```yaml
spec:
  sidecar:
    notifications:
      urlsSecretRef:
        name: g0efilter-notifications
        key: urls
      ignoreDomains: [local]
```

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

Self-signed is the default, so webhook startup does not depend on cert-manager.
Use cert-manager when cluster policy requires a managed issuer. In self-signed
mode, a namespace Role controls Secret access. The only cluster-scoped
certificate permission is `get` and `update` on the named
`MutatingWebhookConfiguration`.

### Webhook network isolation

The webhook Service is cluster-internal, but other pods can still connect to its
ClusterIP. The controller returns admission patches and the API server applies
them. A NetworkPolicy can limit which sources reach the webhook.

API-server source addresses differ between managed clusters, self-hosted control
planes and CNIs, so the chart cannot safely guess them. After obtaining the source
CIDRs from the cluster provider, enable the ingress policy explicitly:

```yaml
networkPolicy:
  enabled: true
  apiServerCIDRs:
    - 10.0.0.0/24 # replace with this cluster's API-server source CIDR
```

The chart rejects an empty CIDR list. The policy keeps the health probe reachable,
opens controller metrics only when its Service is enabled, and accepts webhook
traffic only from the configured CIDRs. Test pod admission before a broad rollout.
With `failurePolicy: Fail`, a wrong CIDR stops new pods in opted-in namespaces.

The Kustomize webhook overlay does not install a guessed NetworkPolicy. Add an
equivalent cluster-specific policy when using that installation path.

#### Injection rules

- Set the pod annotation or label `g0efilter.g0lab.com/inject: "false"` to opt
  out. The webhook also skips host-network pods and pods that already contain a
  `g0efilter` container.
- Admission rejects a pod selected by two policies because each policy has its
  own ConfigMap. Set the pod annotation
  `g0efilter.g0lab.com/policy: <name>` to choose one.

> [!WARNING]
> The default `failurePolicy: Fail` stops pod creation in opted-in namespaces
> when the controller is unreachable. It does not admit an unfiltered pod.
> The chart excludes its release namespace and `kube-system`. Use `Ignore` only
> if pod availability matters more than fail-closed admission.

### Denial visibility

Denials are logged. To also show the first few in `kubectl describe pod`:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6
  - github.com/g0lab/g0efilter//deploy/kustomize/events?ref=v0.9.6
```

This grants the workload ServiceAccount `create` on Events in its namespace and
mounts its token. The add-on binds `default`; patch the RoleBinding for another
ServiceAccount.

The policy must allow the Kubernetes API server. Event requests use the
workload's normal network path, so the sidecar otherwise blocks its own reports:

```sh
kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}'
```

Events are capped per pod (`KUBE_EVENTS_MAX`, default 10) and deduplicated by
destination and reason, so a port scan cannot flood the event stream. If the RBAC
is missing, g0efilter logs one warning and keeps filtering.

### Metrics

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6
  - github.com/g0lab/g0efilter//deploy/kustomize/metrics?ref=v0.9.6
```

Or `g0efilter.metrics.enabled: true` with the Helm chart. Both expose `/metrics` on
port 9095 and add `prometheus.io/*` scrape annotations.

```
g0efilter_connections_total{component,action}
g0efilter_denials_total{component,reason}
g0efilter_policy_reloads_total{result}
g0efilter_panics_total{component}
```

Metrics never use destinations as labels. Label combinations are capped, and
extra combinations use `reason="other"`.

`g0efilter_panics_total` counts panics the agent contained. The
agent recovers these so a single connection, query or packet fails instead of the
process, which would take filtering away from the whole pod. It should stay at
zero. An increase is a defect worth reporting. The matching `panic.recovered`
log record contains the stack trace.

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

On first start, the dashboard generates an admin password and machine API key. It
prints each credential once:

```sh
kubectl -n g0efilter-system logs deploy/g0efilter-dashboard | grep 'dashboard.bootstrap_'
```

To supply both credentials without storing them in the Helm release, create a
Secret from files:

```bash
umask 077
G0EFILTER_CREDENTIAL_DIR="$(mktemp -d)"
trap 'rm -r "$G0EFILTER_CREDENTIAL_DIR"' EXIT
openssl rand -hex 32 > "$G0EFILTER_CREDENTIAL_DIR/api-key"
read -rsp 'Admin password: ' G0EFILTER_ADMIN_PASSWORD
printf '\n'
printf '%s' "$G0EFILTER_ADMIN_PASSWORD" | \
  docker run --rm -i docker.io/g0lab/g0efilter-dashboard:v0.9.6 hash-password \
  > "$G0EFILTER_CREDENTIAL_DIR/admin-password-hash"
unset G0EFILTER_ADMIN_PASSWORD
kubectl -n g0efilter-system create secret generic g0efilter-dashboard \
  --from-file=api-key="$G0EFILTER_CREDENTIAL_DIR/api-key" \
  --from-file=admin-password-hash="$G0EFILTER_CREDENTIAL_DIR/admin-password-hash"
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

Dashboard connections and their DNS lookups use marked sockets, so they need no
policy rule.

`auth.mode` defaults to `session`. Use `none` only behind an authenticating proxy;
`forward` and `jwt` delegate authentication. See
[dashboard authentication](configuration.md#dashboard-authentication).

### Building a policy by observation

Learning mode appends observed destinations to a writable policy without blocking.
The add-on replaces the ConfigMap mount with an emptyDir:

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.6
  - github.com/g0lab/g0efilter//deploy/kustomize/learning?ref=v0.9.6
```

Or `g0efilter.learning.enabled: true` with the Helm chart.

Exercise the workload, then export the learned policy:

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

Kubelet may take a minute or two to refresh the mount. The sidecar checks every
five seconds, but it cannot reload content before kubelet writes it. `SIGHUP` has
the same limit.

If the agent rejects a changed policy, it keeps enforcing the previous one. With
Events enabled, the pod gets a `PolicyReloadFailed` Event. Metrics record
`g0efilter_policy_reloads_total{result="failure"}`.

In `https` mode, allow the cluster DNS Service. Otherwise the default-deny packet
filter blocks the workload's resolver:

```sh
kubectl -n kube-system get svc -l k8s-app=kube-dns -o jsonpath='{.items[0].spec.clusterIP}'
```

In `dns` and `dns-strict` modes, configure that address as `DNS_UPSTREAMS`
instead. The DNS proxy's marked upstream connection does not need a policy rule.

In `https` mode, domain rules match only ports 80 and 443. Allow other traffic by
IP or CIDR. This includes traffic to in-cluster Services, which NetworkPolicy can
narrow further.

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

### The pod fails with `operation not permitted`

The container lacks `NET_ADMIN`, so the kernel rejects its file capabilities.
Add it:

```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_ADMIN]
```

### Everything is blocked

Check that `https` mode allows the kube-dns ClusterIP. In a DNS mode, check that
`DNS_UPSTREAMS` points to that address.

Check a pod's privileges directly:

```sh
kubectl -n <ns> exec <pod> -c g0efilter -- /app/g0efilter caps
```

It checks capabilities and child `nft` netlink access.

### A pod is running but unfiltered

Confirm the sidecar is the first entry in `initContainers`:

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
