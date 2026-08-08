{{/*
g0efilter.sidecar renders the sidecar container. Include it as the FIRST entry of
a pod template's initContainers: anything ordered before it has unfiltered egress.

  initContainers:
    {{- include "g0efilter.sidecar" . | nindent 8 }}
*/}}
{{- define "g0efilter.sidecar" -}}
{{- $c := .Values.g0efilter -}}
- name: g0efilter
  image: {{ printf "%s:%s" $c.image.repository $c.image.tag | quote }}
  imagePullPolicy: {{ $c.image.pullPolicy }}
  # A native sidecar: nftables is programmed before the application container starts.
  restartPolicy: Always
  env:
    - name: FILTER_MODE
      value: {{ $c.mode | quote }}
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
    {{- end }}
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
