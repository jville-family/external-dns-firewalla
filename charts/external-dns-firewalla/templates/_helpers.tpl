{{/*
Expand the name of the chart.
*/}}
{{- define "external-dns-firewalla.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "external-dns-firewalla.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "external-dns-firewalla.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "external-dns-firewalla.labels" -}}
helm.sh/chart: {{ include "external-dns-firewalla.chart" . }}
{{ include "external-dns-firewalla.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "external-dns-firewalla.selectorLabels" -}}
app.kubernetes.io/name: {{ include "external-dns-firewalla.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "external-dns-firewalla.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "external-dns-firewalla.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "external-dns-firewalla.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- include "external-dns-firewalla.fullname" . }}
{{- end }}
{{- end }}
