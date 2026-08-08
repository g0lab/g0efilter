{{/*
g0efilter.eventsRBAC renders the Role and RoleBinding the sidecar needs to create
Events, and nothing when events are disabled. Render it at the top level of your
chart, and set automountServiceAccountToken: true on the pod:

  {{- include "g0efilter.eventsRBAC" . }}
*/}}
{{- define "g0efilter.eventsRBAC" -}}
{{- $c := .Values.g0efilter -}}
{{- if $c.events.enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Release.Name }}-g0efilter-events
  labels:
    {{- include "g0efilter.labels" . | nindent 4 }}
rules:
  - apiGroups: ['']
    resources: ['events']
    verbs: ['create']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Release.Name }}-g0efilter-events
  labels:
    {{- include "g0efilter.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ .Release.Name }}-g0efilter-events
subjects:
  - kind: ServiceAccount
    name: {{ $c.events.serviceAccountName | quote }}
{{- end }}
{{- end -}}
