{{- define "g0efilter-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The Deployment's selector labels are immutable and the topologySpreadConstraints and
webhook Service select on app.kubernetes.io/name, so this stays g0efilter-controller
unless explicitly overridden.
*/}}
{{- define "g0efilter-controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "g0efilter-controller.name" . | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "g0efilter-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "g0efilter-controller.fullname" . }}
{{- end -}}

{{- define "g0efilter-controller.labels" -}}
{{ include "g0efilter-controller.selectorLabels" . }}
app.kubernetes.io/component: control-plane
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: g0efilter
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "g0efilter-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "g0efilter-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "g0efilter-controller.webhookServiceName" -}}
{{- if or .Values.nameOverride .Values.fullnameOverride -}}
{{- printf "%s-webhook" (include "g0efilter-controller.fullname" .) -}}
{{- else -}}
g0efilter-webhook
{{- end -}}
{{- end -}}

{{- define "g0efilter-controller.certSecretName" -}}
{{- if or .Values.nameOverride .Values.fullnameOverride -}}
{{- printf "%s-webhook-cert" (include "g0efilter-controller.fullname" .) -}}
{{- else -}}
g0efilter-webhook-cert
{{- end -}}
{{- end -}}

{{- define "g0efilter-controller.webhookConfigName" -}}
{{- if or .Values.nameOverride .Values.fullnameOverride -}}
{{- printf "%s-sidecar-injector" (include "g0efilter-controller.fullname" .) -}}
{{- else -}}
g0efilter-sidecar-injector
{{- end -}}
{{- end -}}

{{- define "g0efilter-controller.validate" -}}
{{- $source := .Values.webhook.certificate.source -}}
{{- if not (has $source (list "self-signed" "cert-manager")) -}}
{{- fail (printf "webhook.certificate.source must be self-signed or cert-manager, got %q" $source) -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled .Values.webhook.enabled (empty .Values.networkPolicy.apiServerCIDRs) -}}
{{- fail "networkPolicy.apiServerCIDRs must contain at least one API-server source CIDR when webhook network isolation is enabled" -}}
{{- end -}}
{{- end -}}
