{{/*
Labels for the resources this library chart renders. The chart name and version are
literal: .Chart inside a library template resolves to the consuming chart, not to
g0efilter.
*/}}
{{- define "g0efilter.labels" -}}
app.kubernetes.io/name: g0efilter
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: egress-filter
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
