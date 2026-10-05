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
ServiceAccount per role (api | scanner | controls | hooks).
Usage: include "security-posture.saName" (dict "ctx" $ "role" "scanner")
*/}}
{{- define "security-posture.saName" -}}
{{- $names := .ctx.Values.serviceAccount.names | default dict -}}
{{- $override := get $names .role | default "" -}}
{{- if $override -}}
{{- $override -}}
{{- else if or .ctx.Values.serviceAccount.create (eq .role "hooks") -}}
{{- printf "%s-%s" (include "security-posture.fullname" .ctx) .role | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- fail (printf "serviceAccount.names.%s is required when serviceAccount.create is false" .role) -}}
{{- end -}}
{{- end }}

{{/*
ServiceAccount of the worker that runs the privileged stages (provenance,
controls, reports): <fullname>-controls. Without splitPrivileged the single
worker runs every stage with it.
*/}}
{{- define "security-posture.workerSplit" -}}
{{- if .Values.worker.splitPrivileged }}true{{ end -}}
{{- end }}

{{/* Release-wide render-time checks (included once, from rbac.yaml). */}}
{{- define "security-posture.validate" -}}
{{- if .Values.serviceAccount.name }}
{{- fail "serviceAccount.name was replaced by serviceAccount.names.{api,scanner,controls} (one ServiceAccount per privilege level)" }}
{{- end }}
{{- if hasKey .Values.reports "keepPerType" }}
{{- fail "reports.keepPerType was replaced by reports.retention.perType" }}
{{- end }}
{{- if and .Values.provenance.enabled .Values.provenance.helmReleases.enabled (not .Values.provenance.helmReleases.iUnderstandClusterSecretsRead) }}
{{- fail "provenance.helmReleases.enabled grants get/list on EVERY Secret in the cluster (RBAC cannot filter by label) to <fullname>-controls. Set provenance.helmReleases.iUnderstandClusterSecretsRead=true to accept that, or leave helmReleases disabled." }}
{{- end }}
{{- if and .Values.provenance.enabled .Values.provenance.compat.internalService.enabled (not .Values.networkPolicy.enabled) (not .Values.provenance.compat.internalService.allowAnonymousNetwork) }}
{{- fail "provenance.compat.internalService needs networkPolicy.enabled (otherwise every pod in the cluster can reach the listener). Set provenance.compat.internalService.allowAnonymousNetwork=true to accept that." }}
{{- end }}
{{- if eq .Values.auth.mode "disabled" }}
{{- fail "auth.mode=disabled is for local development only; the API refuses to start without POSTURE_DEV=1, which the chart never sets" }}
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

{{/* Clair gets its own bundled Postgres (clair.postgres.dedicated). */}}
{{- define "security-posture.db.clairDedicated" -}}
{{- if and .Values.scanner.clair.enabled .Values.postgresql.enabled .Values.clair.postgres.dedicated }}true{{ end -}}
{{- end }}

{{- define "security-posture.db.clairHost" -}}
{{- if include "security-posture.db.clairDedicated" . -}}
{{- include "security-posture.componentName" (dict "ctx" . "component" "clair-postgres") -}}
{{- else -}}
{{- include "security-posture.db.host" . -}}
{{- end -}}
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
{{- printf "host=%s port=%s dbname=%s user=%s sslmode=%s application_name=clair" (include "security-posture.db.clairHost" .) (include "security-posture.db.port" .) (include "security-posture.db.clairName" .) (include "security-posture.db.user" .) (include "security-posture.db.sslmode" .) -}}
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
{{- include "security-posture.waitForDbHost" (dict "ctx" . "host" (include "security-posture.db.host" .)) }}
{{- end }}

{{/* wait-for-db against a given host. Usage: include "security-posture.waitForDbHost" (dict "ctx" $ "host" "...") */}}
{{- define "security-posture.waitForDbHost" -}}
{{- $host := .host }}
{{- with .ctx }}
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
      value: {{ $host | quote }}
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
  value: {{ join "," (.Values.auth.issuers | default list) | quote }}
- name: OIDC_CLIENT_IDS
  value: {{ include "security-posture.oidcClientIds" . | quote }}
- name: OIDC_AUDIENCES
  value: {{ join "," (.Values.auth.audiences | default list) | quote }}
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
- name: REPORTS_RETENTION_PER_TYPE
  value: {{ .Values.reports.retention.perType | quote }}
- name: REPORTS_RETENTION_MAX_TOTAL_BYTES
  value: {{ .Values.reports.retention.maxTotalBytes | quote }}
- name: HISTORY_RETAIN_SCANS
  value: {{ .Values.history.retainScans | quote }}
- name: REPORTS_AUTO_GENERATE
  value: {{ join "," (.Values.reports.autoGenerate | default list) | quote }}
{{- /* DESIGN §14: defaults for settings scanners.scap / scap.* (api) and the scan hand-off (workers) */}}
- name: SCANNERS_SCAP_ENABLED
  value: {{ .Values.scanner.scap.enabled | quote }}
- name: SCAP_PREFER_DISA
  value: {{ .Values.scanner.scap.preferDisa | quote }}
- name: SCAP_TIMEOUT_SECONDS
  value: {{ .Values.scanner.scap.timeoutSeconds | quote }}
- name: SCAP_FINALIZE_WAIT_SECONDS
  value: {{ .Values.scanner.scap.finalizeWaitSeconds | quote }}
- name: SCAP_PARALLELISM
  value: {{ .Values.scanner.scap.parallelism | quote }}
- name: SCAP_EMBEDDED
  value: {{ .Values.scanner.scap.embedded | quote }}
{{- with .Values.scanner.scap.content.sources }}
- name: SCAP_CONTENT_SOURCES
  value: {{ . | toJson | quote }}
{{- end }}
- name: SCAP_DISA_URLS
  value: {{ .Values.scanner.scap.disa.urls | default list | toJson | quote }}
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

{{/*
OIDC client ids accepted in `aud` / `azp` (OIDC_CLIENT_IDS): auth.clientIds, else
the operator-provisioned client "<namespace>-<fullname>" when nebariapp.enabled.
*/}}
{{- define "security-posture.oidcClientIds" -}}
{{- if .Values.auth.clientIds -}}
{{- join "," .Values.auth.clientIds -}}
{{- else if .Values.nebariapp.enabled -}}
{{- .Values.adminGate.securityPolicy.clientID | default (printf "%s-%s" .Release.Namespace (include "security-posture.fullname" .)) -}}
{{- end -}}
{{- end }}

{{/* ---------------------------------------------------------------------
     extraCACerts: system bundle + extra CAs concatenated into one file by an
     init container (httpx ignores the system directories once SSL_CERT_FILE
     is set; Go tools read the file). Used by api and workers.
     --------------------------------------------------------------------- */}}
{{- define "security-posture.caBundle.init" -}}
{{- if .ctx.Values.extraCACerts.secretName }}
- name: ca-bundle
  image: {{ include "security-posture.image" .image | quote }}
  imagePullPolicy: {{ .image.pullPolicy }}
  command:
    - sh
    - -ec
    - |
      cat /etc/ssl/certs/ca-certificates.crt > /etc/posture/ca/ca-bundle.crt
      for f in /etc/posture/extra-ca/*.crt /etc/posture/extra-ca/*.pem; do
        [ -f "$f" ] || continue
        echo >> /etc/posture/ca/ca-bundle.crt
        cat "$f" >> /etc/posture/ca/ca-bundle.crt
      done
  securityContext:
    {{- toYaml .ctx.Values.containerSecurityContext | nindent 4 }}
  resources:
    requests: { cpu: 10m, memory: 16Mi }
    limits: { cpu: 100m, memory: 64Mi }
  volumeMounts:
    - name: extra-ca
      mountPath: /etc/posture/extra-ca
      readOnly: true
    - name: ca-bundle
      mountPath: /etc/posture/ca
{{- end }}
{{- end }}

{{- define "security-posture.caBundle.env" -}}
{{- if .Values.extraCACerts.secretName }}
- name: SSL_CERT_FILE
  value: /etc/posture/ca/ca-bundle.crt
- name: REQUESTS_CA_BUNDLE
  value: /etc/posture/ca/ca-bundle.crt
{{- end }}
{{- end }}

{{- define "security-posture.caBundle.mount" -}}
{{- if .Values.extraCACerts.secretName }}
- name: ca-bundle
  mountPath: /etc/posture/ca
  readOnly: true
{{- end }}
{{- end }}

{{- define "security-posture.caBundle.volumes" -}}
{{- if .Values.extraCACerts.secretName }}
- name: extra-ca
  secret:
    secretName: {{ .Values.extraCACerts.secretName }}
- name: ca-bundle
  emptyDir: {}
{{- end }}
{{- end }}

{{/* Name of the compat listener bearer-token Secret. */}}
{{- define "security-posture.compatTokenSecret" -}}
{{- .Values.provenance.compat.internalService.tokenSecret | default (printf "%s-compat-token" (include "security-posture.fullname" .)) -}}
{{- end }}

{{/* Compat listener enabled. */}}
{{- define "security-posture.compatEnabled" -}}
{{- if and .Values.provenance.enabled .Values.provenance.compat.internalService.enabled }}true{{ end -}}
{{- end }}

{{/*
Optional report queue lease env (reports.leaseSeconds / reports.maxAttempts;
unset = the application defaults 120 s / 2) for whichever process generates
reports: the report-worker, or the worker with the embedded reports stage.
*/}}
{{- define "security-posture.reportLeaseEnv" -}}
{{- with .Values.reports.leaseSeconds }}
- name: REPORT_LEASE_SECONDS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.reports.maxAttempts }}
- name: REPORT_MAX_ATTEMPTS
  value: {{ . | quote }}
{{- end }}
{{- end }}

{{/*
NetworkPolicy peers for Prometheus (monitoring.enabled): every pod in
monitoring.namespace, or only monitoring.podSelector pods there.
*/}}
{{- define "security-posture.np.monitoringPeers" -}}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ required "monitoring.namespace is required when monitoring.enabled" .Values.monitoring.namespace | quote }}
  {{- with .Values.monitoring.podSelector }}
  podSelector:
    matchLabels:
      {{- toYaml . | nindent 6 }}
  {{- end }}
{{- end }}
