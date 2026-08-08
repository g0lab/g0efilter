{{- define "g0efilter-dashboard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "g0efilter-dashboard.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "g0efilter-dashboard.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "g0efilter-dashboard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "g0efilter-dashboard.fullname" . }}
{{- end -}}

{{- define "g0efilter-dashboard.labels" -}}
{{ include "g0efilter-dashboard.selectorLabels" . }}
app.kubernetes.io/component: dashboard
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: g0efilter
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "g0efilter-dashboard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "g0efilter-dashboard.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "g0efilter-dashboard.secretName" -}}
{{- default (include "g0efilter-dashboard.fullname" .) .Values.secrets.existingSecret -}}
{{- end -}}

{{/* True when values contain credentials for a chart-managed Secret. */}}
{{- define "g0efilter-dashboard.createSecret" -}}
{{- $s := .Values.secrets -}}
{{- if and (not $s.existingSecret) (or $s.apiKey $s.adminPasswordHash $s.jwtSecret) -}}
true
{{- end -}}
{{- end -}}

{{- define "g0efilter-dashboard.secretData" -}}
{{- with .Values.secrets.apiKey }}
{{ $.Values.secrets.keys.apiKey }}: {{ . | quote }}
{{- end }}
{{- with .Values.secrets.adminPasswordHash }}
{{ $.Values.secrets.keys.adminPasswordHash }}: {{ . | quote }}
{{- end }}
{{- with .Values.secrets.jwtSecret }}
{{ $.Values.secrets.keys.jwtSecret }}: {{ . | quote }}
{{- end }}
{{- end -}}

{{- define "g0efilter-dashboard.pvcName" -}}
{{- default (include "g0efilter-dashboard.fullname" .) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "g0efilter-dashboard.validate" -}}
{{- if and .Values.ephemeral .Values.persistence.enabled -}}
{{- fail "ephemeral and persistence.enabled are mutually exclusive: ephemeral keeps all state in memory" -}}
{{- end -}}
{{- if and .Values.fleet.enabled (not .Values.persistence.enabled) -}}
{{- fail "fleet.enabled needs persistence.enabled: fleet management requires persistent storage" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.enabled needs ingress.host" -}}
{{- end -}}
{{- if has "*" .Values.cors.allowedOrigins -}}
{{- fail "cors.allowedOrigins cannot contain '*': the API is served with credentials enabled" -}}
{{- end -}}
{{- $s := .Values.secrets -}}
{{- if and $s.existingSecret (or $s.apiKey $s.adminPasswordHash $s.jwtSecret) -}}
{{- fail "secrets.existingSecret cannot be combined with inline credentials" -}}
{{- end -}}
{{- if and (not $s.existingSecret) (or $s.existingSecretKeys.apiKey $s.existingSecretKeys.adminPasswordHash $s.existingSecretKeys.jwtSecret) -}}
{{- fail "secrets.existingSecretKeys requires secrets.existingSecret" -}}
{{- end -}}
{{- $externalJWT := ternary "existing-secret" "" (and (ne $s.existingSecret "") $s.existingSecretKeys.jwtSecret) -}}
{{- $jwtSources := compact (list .Values.auth.jwt.jwksUrl .Values.auth.jwt.publicKey $s.jwtSecret $externalJWT) -}}
{{- if and (eq .Values.auth.mode "jwt") (gt (len $jwtSources) 1) -}}
{{- fail "auth.mode jwt accepts exactly one key source" -}}
{{- end -}}
{{- if and (eq .Values.auth.mode "jwt") (eq (len $jwtSources) 0) -}}
{{- fail "auth.mode jwt needs a key source: auth.jwt.jwksUrl, auth.jwt.publicKey or secrets.jwtSecret" -}}
{{- end -}}
{{- end -}}
