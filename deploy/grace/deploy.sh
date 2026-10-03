#!/usr/bin/env bash
# Install / upgrade the pack on grace.
#
#   TAG=$(deploy/grace/build-push.sh | tail -n1) deploy/grace/deploy.sh
#
# Env:
#   TAG         image tag for api/worker/ui (required; from build-push.sh)
#   KUBECONFIG  default ~/.kube-grace/config
#   HELM        default ~/bin/helm
#   NAMESPACE   default security-posture
#   RELEASE     default security-posture
# Extra arguments are passed through to `helm upgrade --install`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube-grace/config}"
HELM="${HELM:-$HOME/bin/helm}"
NAMESPACE="${NAMESPACE:-security-posture}"
RELEASE="${RELEASE:-security-posture}"
: "${TAG:?set TAG to the image tag printed by deploy/grace/build-push.sh}"

# The operator ignores NebariApps in namespaces without this label.
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "${NAMESPACE}" nebari.dev/managed=true --overwrite

# extraCACerts (values.yaml): the nebari CA that signs artifacts.*.sslip.io.
kubectl create secret generic nebari-ca -n "${NAMESPACE}" \
  --from-literal=ca.crt="$(kubectl get secret -n cert-manager nebari-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d)" \
  --dry-run=client -o yaml | kubectl apply -f -

"${HELM}" dependency build chart

# Hooks (chart/templates/hooks.yaml) run before the upgrade: ensure-secrets
# keeps the existing ${RELEASE}-db Secret (only annotates it) and creates
# ${RELEASE}-compat-token once; migrate applies alembic head before the new
# api/worker pods start.

"${HELM}" upgrade --install "${RELEASE}" ./chart \
  -n "${NAMESPACE}" \
  -f deploy/grace/values.yaml \
  --set images.api.tag="${TAG}" \
  --set images.worker.tag="${TAG}" \
  --set images.ui.tag="${TAG}" \
  --wait --timeout 15m \
  "$@"

kubectl get nebariapp -n "${NAMESPACE}" -o wide || true
kubectl get pods -n "${NAMESPACE}"
echo
echo "Grafana compat listener token (Infinity datasource header 'Authorization: Bearer <token>'):"
echo "  kubectl get secret ${RELEASE}-compat-token -n ${NAMESPACE} -o jsonpath='{.data.token}' | base64 -d"
echo
echo "UI: https://security.100-89-230-107.sslip.io"
