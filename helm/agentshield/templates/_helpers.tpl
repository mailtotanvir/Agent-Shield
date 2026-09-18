{{- define "agentshield.name" -}}agentshield{{- end }}
{{- define "agentshield.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "agentshield.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "agentshield.image" -}}
{{- if .Values.image.digest -}}
{{ required "image.repository is required" .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ required "image.repository is required" .Values.image.repository }}:{{ required "image.tag or image.digest is required" .Values.image.tag }}
{{- end -}}
{{- end }}

