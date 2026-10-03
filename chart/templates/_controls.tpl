{{/*
  Control evidence engine env (DESIGN §13); included by api.yaml and worker.yaml.
*/}}
{{- define "security-posture.controlsEnv" -}}
{{- $c := .Values.controlsEngine -}}
- name: CONTROLS_ENGINE_ENABLED
  value: {{ $c.enabled | quote }}
- name: CONTROLS_BASELINE
  value: {{ $c.baseline | quote }}
- name: CONTROLS_ADMIN_SUBJECTS
  value: {{ join "," ($c.adminSubjectsAllowlist | default list) | quote }}
- name: CONTROLS_SYSTEM_NAMESPACES
  value: {{ join "," ($c.systemNamespaces | default list) | quote }}
- name: CONTROLS_KEYCLOAK_URL
  value: {{ $c.keycloak.url | quote }}
- name: CONTROLS_KEYCLOAK_REALM
  value: {{ $c.keycloak.realm | quote }}
- name: CONTROLS_KEYCLOAK_ADMIN_REALM
  value: {{ $c.keycloak.adminRealm | default "" | quote }}
- name: CONTROLS_KEYCLOAK_CLIENT_ID
  value: {{ $c.keycloak.clientId | default "admin-cli" | quote }}
- name: CONTROLS_KEYCLOAK_ADMIN_GROUP
  value: {{ $c.keycloak.adminGroup | default "" | quote }}
- name: CONTROLS_KEYCLOAK_VERIFY_TLS
  value: {{ $c.keycloak.verifyTls | quote }}
- name: CONTROLS_KEYCLOAK_ADMIN_SECRET_NAME
  value: {{ $c.keycloak.adminSecret.name | quote }}
- name: CONTROLS_KEYCLOAK_ADMIN_SECRET_NAMESPACE
  value: {{ $c.keycloak.adminSecret.namespace | quote }}
- name: CONTROLS_LOKI_URL
  value: {{ $c.lokiUrl | default "" | quote }}
- name: CONTROLS_PROMETHEUS_URL
  value: {{ $c.prometheusUrl | default "" | quote }}
- name: CONTROLS_ALERTMANAGER_URL
  value: {{ $c.alertmanagerUrl | default "" | quote }}
- name: CONTROLS_REGISTRY_URL
  value: {{ $c.registryUrl | default "" | quote }}
- name: CONTROLS_TIMEOUT_SECONDS
  value: {{ $c.timeoutSeconds | quote }}
- name: CONTROLS_TLS_PROBE
  value: {{ $c.tlsProbe | quote }}
{{- end }}

{{/*
  Keycloak credentials for the controls engine (privileged worker only;
  security review M4): a dedicated view-only client (KEYCLOAK_CLIENT_ID +
  KEYCLOAK_CLIENT_SECRET_FILE) when configured, else the admin Secret named
  in CONTROLS_KEYCLOAK_ADMIN_SECRET_* is read through the Role in rbac.yaml.
*/}}
{{- define "security-posture.keycloakClientEnv" -}}
{{- $kc := .Values.controlsEngine.keycloak -}}
{{- $vc := $kc.viewClient | default dict -}}
- name: KEYCLOAK_ALLOW_MASTER_FALLBACK
  value: {{ $kc.allowMasterFallback | default false | quote }}
{{- if and .Values.controlsEngine.enabled $vc.clientId }}
- name: KEYCLOAK_CLIENT_ID
  value: {{ $vc.clientId | quote }}
{{- if $vc.existingSecret }}
- name: KEYCLOAK_CLIENT_SECRET_FILE
  value: /etc/posture/keycloak/client-secret
{{- end }}
{{- end }}
{{- end }}
