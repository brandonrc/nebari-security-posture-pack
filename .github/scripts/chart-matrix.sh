#!/usr/bin/env bash
# Chart validation matrix (run from the repo root; needs helm + kubeconform on PATH and
# `helm dependency build chart/` done). Lints defaults and the grace values, renders 18
# value sets and validates each with kubeconform -strict against the Kubernetes schemas
# plus the CRD schemas in .github/kubeconform-schemas (NebariApp, SecurityPolicy,
# ServiceMonitor/PodMonitor/PrometheusRule), then checks that four unsafe/removed value
# combinations refuse to render with the right message.
set -uo pipefail
HELM=${HELM:-helm}
KC=${KUBECONFORM:-kubeconform}
OUT=${OUT:-$(mktemp -d)}
SCHEMAS=${SCHEMAS:-$(cd "$(dirname "$0")/../kubeconform-schemas" && pwd)}
mkdir -p "$OUT"
KC_ARGS=(-strict -summary -schema-location default
         -schema-location "$SCHEMAS/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json")
rc=0
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$1" >> "$GITHUB_STEP_SUMMARY"; echo "$1"; }

"$HELM" lint chart > "$OUT/lint.txt" 2>&1 || { echo "::error::helm lint (defaults) failed"; cat "$OUT/lint.txt"; rc=1; }
"$HELM" lint chart -f deploy/grace/values.yaml > "$OUT/lint-grace.txt" 2>&1 || { echo "::error::helm lint (grace) failed"; cat "$OUT/lint-grace.txt"; rc=1; }

run() {
  local n=$1; shift
  if "$HELM" template security-posture chart -n security-posture "$@" > "$OUT/$n.yaml" 2> "$OUT/$n.err"; then
    if "$KC" "${KC_ARGS[@]}" "$OUT/$n.yaml" > "$OUT/$n.kc" 2>&1; then
      summary "- \`$n\`: $(tail -1 "$OUT/$n.kc")"
    else
      echo "::error::kubeconform failed for value set $n"; cat "$OUT/$n.kc"; rc=1
    fi
  else
    echo "::error::helm template failed for value set $n"; cat "$OUT/$n.err"; rc=1
  fi
}

expfail() {
  local n=$1 msg=$2; shift 2
  if "$HELM" template t chart "$@" > /dev/null 2> "$OUT/$n.err"; then
    echo "::error::$n: expected a render failure, but the chart rendered"; rc=1
  elif grep -q -- "$msg" "$OUT/$n.err"; then
    summary "- \`$n\`: refuses to render (\"$msg\")"
  else
    echo "::error::$n: failed with the wrong message"; cat "$OUT/$n.err"; rc=1
  fi
}

summary "### Chart render matrix"
run defaults
run grace -f deploy/grace/values.yaml
run sp --set nebariapp.enabled=true --set nebariapp.hostname=t.example.com \
  --set adminGate.securityPolicy.enabled=true \
  --set adminGate.securityPolicy.externalIssuer=https://kc.example.com/auth/realms/nebari
run grace-sp -f deploy/grace/values.yaml --set adminGate.securityPolicy.enabled=true
run grace-nosplit -f deploy/grace/values.yaml --set worker.splitPrivileged=false
run nebariapp --set nebariapp.enabled=true --set nebariapp.hostname=test.example.com
run nebariapp-off --set nebariapp.enabled=false
run helm-releases --set provenance.helmReleases.enabled=true \
  --set provenance.helmReleases.iUnderstandClusterSecretsRead=true
run controls --set controlsEngine.enabled=true
run nosplit --set worker.splitPrivileged=false
run clair --set scanner.clair.enabled=true
run clair-shared --set scanner.clair.enabled=true --set clair.postgres.dedicated=false
run compat --set provenance.compat.internalService.enabled=true
run compat-anon --set provenance.compat.internalService.enabled=true --set networkPolicy.enabled=false \
  --set provenance.compat.internalService.allowAnonymousNetwork=true
run extdb --set postgresql.enabled=false --set externalDatabase.host=db.example.com \
  --set externalDatabase.existingSecret=db-creds --set scanner.clair.enabled=false \
  --set scanner.trivy.enabled=false
run nopersist --set persistence.enabled=false --set networkPolicy.enabled=false
run monitoring --set monitoring.enabled=true --set monitoring.labels.release=kps
run viewclient --set controlsEngine.keycloak.viewClient.clientId=posture-view \
  --set controlsEngine.keycloak.viewClient.existingSecret=kc-view --set extraCACerts.secretName=ca

summary "### Expected render failures"
expfail helm-noack iUnderstandClusterSecretsRead --set provenance.helmReleases.enabled=true
expfail compat-no-netpol allowAnonymousNetwork --set provenance.compat.internalService.enabled=true \
  --set networkPolicy.enabled=false
expfail auth-disabled "development only" --set auth.mode=disabled
expfail old-sa-key "serviceAccount.names" --set serviceAccount.name=foo

exit $rc
