#!/usr/bin/env bash
# Build the three first-party images and push them to grace's local registry
# (localhost:32000). Prints the tag on the last line of stdout so callers can
# capture it:   TAG=$(deploy/grace/build-push.sh | tail -n1)
#
# Env:
#   TAG       image tag (default: <short-sha>-<unix-time>)
#   REGISTRY  registry prefix (default: localhost:32000)
#   ONLY      space-separated subset of: api worker ui
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

REGISTRY="${REGISTRY:-localhost:32000}"
TAG="${TAG:-$(git rev-parse --short HEAD)-$(date +%s)}"
ONLY="${ONLY:-api worker ui}"

build_push() {
  local name="$1" dockerfile="$2" context="$3"
  local ref="${REGISTRY}/security-posture-${name}:${TAG}"
  echo ">> building ${ref} (${dockerfile})" >&2
  docker build -f "${dockerfile}" -t "${ref}" "${context}" >&2
  echo ">> pushing ${ref}" >&2
  docker push "${ref}" >&2
}

for component in ${ONLY}; do
  case "${component}" in
    api)    build_push api    api/Dockerfile.api    api ;;
    worker) build_push worker api/Dockerfile.worker api ;;
    ui)     build_push ui     ui/Dockerfile         ui ;;
    *) echo "unknown component: ${component}" >&2; exit 1 ;;
  esac
done

echo "${TAG}"
