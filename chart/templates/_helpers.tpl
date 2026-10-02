{{/*
Expand the name of the chart.
*/}}
{{- define "security-posture.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. Release "security-posture" + chart
"nebari-security-posture-pack" collapses to just the release name (either
contains the other), keeping derived names short: the operator-provisioned
Keycloak client id is "<namespace>-<fullname>" and every component appends a
suffix ("-postgres", "-trivy", ...).
*/}}
{{- define "security-posture.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 50 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if or (contains $name .Release.Name) (contains .Release.Name $name) }}
{{- .Release.Name | trunc 50 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 50 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "security-posture.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "security-posture.labels" -}}
helm.sh/chart: {{ include "security-posture.chart" . }}
{{ include "security-posture.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nebari-security-posture-pack
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "security-posture.selectorLabels" -}}
app.kubernetes.io/name: {{ include "security-posture.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component labels / selector labels.
Usage: include "security-posture.componentLabels" (dict "ctx" $ "component" "api")
*/}}
{{- define "security-posture.componentLabels" -}}
{{ include "security-posture.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "security-posture.componentSelectorLabels" -}}
{{ include "security-posture.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component resource name: <fullname>-<component>.
*/}}
{{- define "security-posture.componentName" -}}
{{- printf "%s-%s" (include "security-posture.fullname" .ctx) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
ServiceAccount used by api + worker (bound to the read-only ClusterRole).
*/}}
{{- define "security-posture.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "security-posture.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference. Usage: include "security-posture.image" .Values.images.api
A digest, when set, wins over the tag.
*/}}
{{- define "security-posture.image" -}}
{{- $repo := required "image repository is required" .repository -}}
{{- if .digest -}}
{{- printf "%s@%s" $repo .digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (required (printf "image tag is required for %s" $repo) (toString .tag)) -}}
{{- end -}}
{{- end }}

{{/*
Admin groups as a comma list (ADMIN_GROUPS env).
*/}}
{{- define "security-posture.adminGroups" -}}
{{- join "," .Values.adminGroups -}}
{{- end }}

{{/*
Admin groups in both forms the realm may emit: "group" (grace operator
mapper) and "/group" (NIC realm mapper, full.path=true). Returns JSON list.
*/}}
{{- define "security-posture.adminGroupClaimValues" -}}
{{- $out := list -}}
{{- range .Values.adminGroups -}}
{{- $g := trimPrefix "/" . -}}
{{- $out = append $out $g -}}
{{- $out = append $out (printf "/%s" $g) -}}
{{- end -}}
{{- $out | uniq | toJson -}}
{{- end }}

{{/* ---------------------------------------------------------------------
     Database helpers. The bundled Postgres (postgresql.enabled) and an
     external server (externalDatabase.*) are addressed the same way: host,
     port, user, two database names, and a password read from a Secret key.
     The password never appears in a rendered manifest except via
     secretKeyRef; DATABASE_URL is assembled in-container with $(DB_PASSWORD)
     dependent-env expansion.
     --------------------------------------------------------------------- */}}
{{- define "security-posture.db.host" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "security-posture.componentName" (dict "ctx" . "component" "postgres") -}}
{{- else -}}
{{- required "externalDatabase.host is required when postgresql.enabled is false" .Values.externalDatabase.host -}}
{{- end -}}
{{- end }}

{{- define "security-posture.db.port" -}}
{{- if .Values.postgresql.enabled }}5432{{ else }}{{ .Values.externalDatabase.port | default 5432 }}{{ end -}}
{{- end }}

{{- define "security-posture.db.user" -}}
{{- if .Values.postgresql.enabled }}{{ .Values.postgresql.auth.username }}{{ else }}{{ required "externalDatabase.user is required" .Values.externalDatabase.user }}{{ end -}}
{{- end }}

{{- define "security-posture.db.name" -}}
{{- if .Values.postgresql.enabled }}{{ .Values.postgresql.auth.database }}{{ else }}{{ .Values.externalDatabase.database }}{{ end -}}
{{- end }}

{{- define "security-posture.db.clairName" -}}
{{- if .Values.postgresql.enabled }}{{ .Values.postgresql.auth.clairDatabase }}{{ else }}{{ .Values.externalDatabase.clairDatabase }}{{ end -}}
{{- end }}

{{- define "security-posture.db.sslmode" -}}
{{- if .Values.postgresql.enabled }}disable{{ else }}{{ .Values.externalDatabase.sslmode | default "require" }}{{ end -}}
{{- end }}

{{- define "security-posture.db.secretName" -}}
{{- if .Values.postgresql.enabled -}}
{{- default (printf "%s-db" (include "security-posture.fullname" .)) .Values.postgresql.existingSecret -}}
{{- else -}}
{{- required "externalDatabase.existingSecret is required when postgresql.enabled is false" .Values.externalDatabase.existingSecret -}}
{{- end -}}
{{- end }}

{{- define "security-posture.db.passwordKey" -}}
{{- if .Values.postgresql.enabled }}password{{ else }}{{ .Values.externalDatabase.passwordKey | default "password" }}{{ end -}}
{{- end }}

{{/*
SQLAlchemy URL for the posture database. $(DB_PASSWORD) is expanded by the
kubelet from the DB_PASSWORD env var, which must be declared first.
*/}}
{{- define "security-posture.db.url" -}}
{{- $url := printf "%s://%s:$(DB_PASSWORD)@%s:%s/%s" .Values.database.driver (include "security-posture.db.user" .) (include "security-posture.db.host" .) (include "security-posture.db.port" .) (include "security-posture.db.name" .) -}}
{{- $ssl := include "security-posture.db.sslmode" . -}}
{{- if ne $ssl "disable" -}}
{{- /* asyncpg takes `ssl=<mode>`; libpq-based drivers take `sslmode=<mode>`. */ -}}
{{- $url = printf "%s?%s=%s" $url (ternary "ssl" "sslmode" (contains "asyncpg" .Values.database.driver)) $ssl -}}
{{- end -}}
{{- $url -}}
{{- end }}

{{/*
libpq keyword/value connstring for Clair (password supplied via PGPASSWORD,
which pgx honours, so the Clair config Secret carries no credential).
*/}}
{{- define "security-posture.db.clairConnString" -}}
{{- printf "host=%s port=%s dbname=%s user=%s sslmode=%s application_name=clair" (include "security-posture.db.host" .) (include "security-posture.db.port" .) (include "security-posture.db.clairName" .) (include "security-posture.db.user" .) (include "security-posture.db.sslmode" .) -}}
{{- end }}

{{/*
DB_PASSWORD env entry (must precede any env referencing $(DB_PASSWORD)).
*/}}
{{- define "security-posture.db.passwordEnv" -}}
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "security-posture.db.secretName" . }}
      key: {{ include "security-posture.db.passwordKey" . }}
{{- end }}

{{/*
wait-for-db init container (uses the Postgres image's pg_isready). `-U` is
required: without it pg_isready looks up the OS user, which does not exist for
uid 10001 in the postgres image, and reports "no attempt" forever.
*/}}
{{- define "security-posture.waitForDb" -}}
- name: wait-for-db
  image: {{ include "security-posture.image" .Values.images.postgres | quote }}
  imagePullPolicy: {{ .Values.images.postgres.pullPolicy }}
  command:
    - sh
    - -c
    - |
      deadline=$(( $(date +%s) + {{ .Values.database.waitTimeoutSeconds }} ))
      until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -t 5; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
          echo "database $DB_HOST:$DB_PORT not ready, giving up" >&2
          exit 1
        fi
        echo "waiting for database $DB_HOST:$DB_PORT"
        sleep 3
      done
  env:
    - name: DB_HOST
      value: {{ include "security-posture.db.host" . | quote }}
    - name: DB_PORT
      value: {{ include "security-posture.db.port" . | quote }}
    - name: DB_USER
      value: {{ include "security-posture.db.user" . | quote }}
  securityContext:
    {{- toYaml .Values.containerSecurityContext | nindent 4 }}
  resources:
    requests: { cpu: 10m, memory: 16Mi }
    limits: { cpu: 100m, memory: 64Mi }
{{- end }}

{{/*
Service URLs.
*/}}
{{- define "security-posture.trivyUrl" -}}
{{- printf "http://%s:4954" (include "security-posture.componentName" (dict "ctx" . "component" "trivy")) -}}
{{- end }}

{{- define "security-posture.clairUrl" -}}
{{- printf "http://%s:6060" (include "security-posture.componentName" (dict "ctx" . "component" "clair")) -}}
{{- end }}

{{- define "security-posture.apiUrl" -}}
{{- printf "http://%s:8000" (include "security-posture.componentName" (dict "ctx" . "component" "api")) -}}
{{- end }}

{{/*
Enabled scanners as a comma list.
*/}}
{{- define "security-posture.enabledScanners" -}}
{{- $s := list -}}
{{- if .Values.scanner.trivy.enabled }}{{ $s = append $s "trivy" }}{{ end -}}
{{- if .Values.scanner.grype.enabled }}{{ $s = append $s "grype" }}{{ end -}}
{{- if .Values.scanner.clair.enabled }}{{ $s = append $s "clair" }}{{ end -}}
{{- join "," $s -}}
{{- end }}

{{/*
Environment shared by api and worker (DESIGN.md section 5).
*/}}
{{- define "security-posture.commonEnv" -}}
{{ include "security-posture.db.passwordEnv" . }}
- name: DATABASE_URL
  value: {{ include "security-posture.db.url" . | quote }}
- name: AUTH_MODE
  value: {{ .Values.auth.mode | quote }}
- name: OIDC_JWKS_URL
  value: {{ .Values.auth.jwksUrl | quote }}
- name: OIDC_ISSUERS
  value: {{ join "," .Values.auth.issuers | quote }}
- name: ADMIN_GROUPS
  value: {{ include "security-posture.adminGroups" . | quote }}
- name: TRIVY_SERVER_URL
  value: {{ include "security-posture.trivyUrl" . | quote }}
- name: CLAIR_URL
  value: {{ include "security-posture.clairUrl" . | quote }}
- name: TRIVY_ENABLED
  value: {{ .Values.scanner.trivy.enabled | quote }}
- name: GRYPE_ENABLED
  value: {{ .Values.scanner.grype.enabled | quote }}
- name: CLAIR_ENABLED
  value: {{ .Values.scanner.clair.enabled | quote }}
- name: MIRROR_ENABLED
  value: {{ .Values.scanner.mirror.enabled | quote }}
- name: MIRROR_REGISTRY
  value: {{ .Values.scanner.mirror.registry | quote }}
- name: MIRROR_INSECURE
  value: {{ .Values.scanner.mirror.insecure | quote }}
- name: MIRROR_REWRITE
  {{- $rw := list }}
  {{- range $src, $dst := (.Values.scanner.mirror.rewrite | default dict) }}
  {{- $rw = append $rw (printf "%s=%s" $src $dst) }}
  {{- end }}
  value: {{ join "," $rw | quote }}
- name: SCAN_PARALLELISM
  value: {{ .Values.scanner.parallelism | quote }}
- name: SCAN_TIMEOUT_SECONDS
  value: {{ .Values.scanner.timeoutSeconds | quote }}
- name: SCAN_INTERVAL_HOURS
  value: {{ .Values.scanner.intervalHours | quote }}
- name: RESCAN_AFTER_HOURS
  value: {{ .Values.scanner.rescanAfterHours | quote }}
- name: EXCLUDED_NAMESPACES
  value: {{ join "," .Values.scanner.excludedNamespaces | quote }}
- name: LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
- name: REPORTS_DIR
  value: {{ .Values.reports.dir | quote }}
- name: REPORTS_KEEP_PER_TYPE
  value: {{ .Values.reports.keepPerType | quote }}
- name: REPORTS_AUTO_GENERATE
  value: {{ join "," (.Values.reports.autoGenerate | default list) | quote }}
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: RELEASE_NAME
  value: {{ .Release.Name | quote }}
- name: HOME
  value: /tmp
{{- end }}

{{/*
NetworkPolicy pod peer. Usage: include "security-posture.np.peer" (dict "ctx" $ "component" "api")
*/}}
{{- define "security-posture.np.peer" -}}
- podSelector:
    matchLabels:
      {{- include "security-posture.componentSelectorLabels" . | nindent 6 }}
{{- end }}

{{/*
Reports volume (PVC shared by api + worker, or emptyDir without persistence).
*/}}
{{- define "security-posture.reportsVolume" -}}
- name: reports
  {{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ include "security-posture.fullname" . }}-reports
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end }}
