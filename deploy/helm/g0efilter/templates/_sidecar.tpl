{{/*
g0efilter.sidecar renders the sidecar container. Include it as the FIRST entry of
a pod template's initContainers: anything ordered before it has unfiltered egress.

  initContainers:
    {{- include "g0efilter.sidecar" . | nindent 8 }}
*/}}
{{- define "g0efilter.sidecar" -}}
{{- $c := .Values.g0efilter -}}
{{- $metricsPort := int $c.metrics.port -}}
{{- $httpPort := int (default 65080 $c.ports.http) -}}
{{- $httpsPort := int (default 65443 $c.ports.https) -}}
{{- if eq $httpPort $httpsPort -}}
{{- fail "g0efilter.ports.http and g0efilter.ports.https must differ" -}}
{{- end -}}
{{- if and $c.metrics.enabled (has $c.mode (list "dns" "dns-strict")) (eq $metricsPort (int (default 65053 $c.ports.dns))) -}}
{{- fail "g0efilter.metrics.port must differ from the active DNS proxy port" -}}
{{- end -}}
{{- if and $c.metrics.enabled (eq $c.mode "https") (or (eq $metricsPort $httpPort) (eq $metricsPort $httpsPort)) -}}
{{- fail "g0efilter.metrics.port must differ from the active HTTP and HTTPS proxy ports" -}}
{{- end -}}
- name: g0efilter
  image: {{ printf "%s:%s" $c.image.repository $c.image.tag | quote }}
  imagePullPolicy: {{ $c.image.pullPolicy }}
  # A native sidecar: nftables is programmed before the application container starts.
  restartPolicy: Always
  env:
    - name: FILTER_MODE
      value: {{ $c.mode | quote }}
    - name: ENFORCE
      value: {{ $c.enforcement | quote }}
    - name: POLICY_PATH
      value: {{ printf "%s/%s" $c.policy.mountPath $c.policy.fileName | quote }}
    - name: POLICY_CONFIGMAP
      value: {{ $c.policy.configMapName | quote }}
    - name: LOG_LEVEL
      value: {{ $c.logLevel | quote }}
    - name: POD_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace
    {{- with $c.tenantId }}
    - name: TENANT_ID
      value: {{ . | quote }}
    {{- end }}
    {{- if $c.metrics.enabled }}
    - name: METRICS_ADDR
      value: {{ printf ":%v" $c.metrics.port | quote }}
    {{- end }}
    {{- if $c.learning.enabled }}
    - name: LEARNING_MODE
      value: "true"
    {{- end }}
    {{- if $c.events.enabled }}
    - name: KUBE_EVENTS
      value: "true"
    - name: POD_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
    - name: POD_UID
      valueFrom:
        fieldRef:
          fieldPath: metadata.uid
    {{- include "g0efilter.optionalInt" (list "KUBE_EVENTS_MAX" $c.events.maxDenials) }}
    {{- end }}
    {{- with $c.dashboard.host }}
    - name: DASHBOARD_HOST
      value: {{ . | quote }}
    {{- end }}
    {{- with $c.dashboard.apiKeySecret.name }}
    - name: DASHBOARD_API_KEY
      valueFrom:
        secretKeyRef:
          name: {{ . | quote }}
          key: {{ $c.dashboard.apiKeySecret.key | quote }}
    {{- end }}
    {{- include "g0efilter.optionalInt" (list "DASHBOARD_QUEUE_SIZE" $c.dashboard.queueSize) }}
    {{- with $c.dashboard.startDelay }}
    - name: DASHBOARD_START_DELAY
      value: {{ . | quote }}
    {{- end }}
    {{- if $c.dashboard.remoteUnblock }}
    - name: ENABLE_REMOTE_UNBLOCK
      value: "true"
    {{- end }}
    {{- with $c.dashboard.unblockPollInterval }}
    - name: UNBLOCK_POLL_INTERVAL
      value: {{ . | quote }}
    {{- end }}
    {{- with $c.notifications.urlsSecret.name }}
    - name: NOTIFICATION_URLS
      valueFrom:
        secretKeyRef:
          name: {{ . | quote }}
          key: {{ $c.notifications.urlsSecret.key | quote }}
    {{- end }}
    {{- include "g0efilter.optionalInt" (list "NOTIFICATION_BACKOFF_SECONDS" $c.notifications.backoffSeconds) }}
    {{- with $c.notifications.ignoreDomains }}
    - name: NOTIFICATION_IGNORE_DOMAINS
      value: {{ join "," . | quote }}
    {{- end }}
    {{- with $c.dns.upstreams }}
    - name: DNS_UPSTREAMS
      value: {{ join "," . | quote }}
    {{- end }}
    {{- if not (kindIs "invalid" $c.dns.hardening) }}
    - name: DNS_HARDENING
      value: {{ $c.dns.hardening | quote }}
    {{- end }}
    {{- include "g0efilter.optionalInt" (list "DNS_RATE_QPS" $c.dns.rateQps) }}
    {{- include "g0efilter.optionalInt" (list "DNS_RATE_BURST" $c.dns.rateBurst) }}
    {{- include "g0efilter.optionalInt" (list "HTTP_PORT" $c.ports.http) }}
    {{- include "g0efilter.optionalInt" (list "HTTPS_PORT" $c.ports.https) }}
    {{- include "g0efilter.optionalInt" (list "DNS_PORT" $c.ports.dns) }}
    {{- include "g0efilter.optionalInt" (list "MAX_CONNECTIONS" $c.connections.max) }}
    {{- include "g0efilter.optionalInt" (list "CONN_MAX_LIFETIME_MS" $c.connections.maxLifetimeMs) }}
    {{- include "g0efilter.optionalInt" (list "NFLOG_BUFSIZE" $c.nflog.bufSize) }}
    {{- include "g0efilter.optionalInt" (list "NFLOG_QTHRESH" $c.nflog.qthresh) }}
    {{- with $c.extraEnv }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  securityContext:
    runAsNonRoot: true
    runAsUser: {{ $c.runAsUser }}
    runAsGroup: {{ $c.runAsGroup }}
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    seccompProfile:
      type: RuntimeDefault
    capabilities:
      drop:
        - ALL
      add:
        # The only capability needed. It is carried as a file capability on the
        # binary, so the container never runs as root.
        - NET_ADMIN
  volumeMounts:
    - name: g0efilter-policy
      mountPath: {{ $c.policy.mountPath | quote }}
      # Learning mode appends to the policy file, so the mount cannot be read-only.
      readOnly: {{ not $c.learning.enabled }}
  {{- if $c.metrics.enabled }}
  ports:
    - name: metrics
      containerPort: {{ $c.metrics.port }}
      protocol: TCP
  {{- end }}
  resources:
    {{- toYaml $c.resources | nindent 4 }}
{{- end -}}

{{/*
g0efilter.policyVolume renders the matching volume. Include it in the same pod's
volumes list. The ConfigMap is mounted as a directory, not a subPath file, so that
kubelet's refresh triggers g0efilter's live reload.

  volumes:
    {{- include "g0efilter.policyVolume" . | nindent 8 }}
*/}}
{{- define "g0efilter.policyVolume" -}}
{{- $c := .Values.g0efilter -}}
- name: g0efilter-policy
  {{- if $c.learning.enabled }}
  emptyDir: {}
  {{- else }}
  configMap:
    name: {{ $c.policy.configMapName | quote }}
  {{- end }}
{{- end -}}

{{/*
g0efilter.podAnnotations renders the Prometheus scrape annotations, and nothing when
metrics are disabled. Include it in the pod template's metadata.annotations.
*/}}
{{- define "g0efilter.podAnnotations" -}}
{{- $c := .Values.g0efilter -}}
{{- if and $c.metrics.enabled $c.metrics.annotations }}
prometheus.io/scrape: "true"
prometheus.io/port: {{ $c.metrics.port | quote }}
prometheus.io/path: /metrics
{{- end }}
{{- end -}}

{{/*
g0efilter.optionalInt renders one env entry from (list NAME VALUE), or nothing at
all when VALUE is null. Tested with kindIs rather than a truth test because 0 is
meaningful for several of these variables, and it indents itself so that a null
leaves no blank line behind.

  {{- include "g0efilter.optionalInt" (list "MAX_CONNECTIONS" $c.connections.max) }}
*/}}
{{- define "g0efilter.optionalInt" -}}
{{- $value := index . 1 -}}
{{- if not (kindIs "invalid" $value) -}}
{{- printf "- name: %s\n  value: %q" (index . 0) (toString $value) | nindent 4 -}}
{{- end -}}
{{- end -}}
