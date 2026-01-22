{{- define "tip.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "tip.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end -}}
{{- define "tip.labels" -}}
app.kubernetes.io/name: {{ include "tip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "tip.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "tip.grace" -}}
{{- $g := dig "server" "shutdown_grace" "15s" .Values.config -}}
{{- $sleep := .Values.preStopSleepSeconds | int -}}
{{- if hasSuffix "m" $g }}{{ add (mul (trimSuffix "m" $g | int) 60) 5 $sleep }}{{ else }}{{ add (trimSuffix "s" $g | int) 5 $sleep }}{{ end -}}
{{- end -}}
{{- define "tip.caSecret" -}}
{{- if .Values.ca.existingSecret }}{{ .Values.ca.existingSecret }}{{ else if and .Values.ca.cert .Values.ca.key }}{{ include "tip.fullname" . }}-ca{{ end -}}
{{- end -}}
