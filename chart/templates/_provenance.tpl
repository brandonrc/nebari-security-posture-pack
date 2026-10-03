{{/*
Supply-chain provenance env (DESIGN §12), shared by api (settings defaults,
compat listener) and worker (checks). Keys: values.yaml `provenance:`.
*/}}
{{- define "security-posture.provenanceEnv" -}}
{{- $p := .Values.provenance }}
- name: PROVENANCE_ENABLED
  value: {{ $p.enabled | quote }}
- name: PROVENANCE_VERIFY_SIGNATURES
  value: {{ $p.verifySignatures | quote }}
- name: PROVENANCE_COSIGN_PUBLIC_KEY
  value: {{ ternary "/etc/posture/cosign/cosign.pub" ($p.cosignPublicKey | default "") (not (empty $p.cosign.existingSecret)) | quote }}
- name: PROVENANCE_COSIGN_CERTIFICATE_IDENTITY_REGEXP
  value: {{ $p.cosign.certificateIdentityRegexp | default "" | quote }}
- name: PROVENANCE_COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP
  value: {{ $p.cosign.certificateOidcIssuerRegexp | default "" | quote }}
- name: PROVENANCE_CHECK_SBOM
  value: {{ $p.checkSBOM | quote }}
- name: PROVENANCE_CHECK_PROVENANCE
  value: {{ $p.checkProvenance | quote }}
- name: PROVENANCE_CHECK_UPDATES
  value: {{ $p.checkUpdates | quote }}
- name: PROVENANCE_UPDATE_LEVEL
  value: {{ $p.updateLevel | quote }}
- name: PROVENANCE_SKIP_PRERELEASE
  value: {{ $p.skipPrerelease | quote }}
- name: PROVENANCE_RECHECK_HOURS
  value: {{ $p.recheckHours | quote }}
- name: PROVENANCE_CONCURRENCY
  value: {{ $p.concurrency | quote }}
- name: PROVENANCE_REGISTRY_TIMEOUT
  value: {{ $p.registryTimeoutSeconds | quote }}
- name: PROVENANCE_HELM_ENABLED
  value: {{ $p.helmReleases.enabled | quote }}
- name: PROVENANCE_HELM_CHART_REPOS
  value: {{ join "," ($p.helmReleases.chartRepos | default list) | quote }}
{{- end }}

{{/* Name of the unauthenticated compat Service (Grafana). */}}
{{- define "security-posture.provenanceInternalServiceName" -}}
{{- .Values.provenance.compat.internalService.name | default (printf "%s-web-internal" (include "security-posture.fullname" .)) -}}
{{- end }}
