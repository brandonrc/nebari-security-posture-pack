#!/bin/sh
# Re-generate ui/screenshots/*.png (Docker only; no host node needed).
# Usage: ui/screenshots/run.sh   (from the repo root or ui/)
#
# Uses --network host and never creates Docker networks: on the grace host
# `docker network create` restarts MicroK8s. PORT defaults to 4173.
set -eu
cd "$(dirname "$0")/.."
PORT=${PORT:-4173}
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app -e HOME=/tmp -e VITE_API_MOCK=1 node:22-alpine \
  sh -c 'npm ci --no-audit --no-fund >/dev/null && npx vite build --outDir dist-mock >/dev/null'
docker rm -f sp-preview >/dev/null 2>&1 || true
docker run -d --name sp-preview --network host -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app -e HOME=/tmp node:22-alpine \
  npx vite preview --outDir dist-mock --host 127.0.0.1 --port "$PORT" --strictPort >/dev/null
trap 'docker rm -f sp-preview >/dev/null 2>&1 || true' EXIT
sleep 4
WORK=$(mktemp -d)
cp screenshots/shoot.mjs "$WORK/"
docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$WORK":/work -v "$PWD/screenshots":/out \
  -e BASE_URL="http://127.0.0.1:$PORT" -e OUT_DIR=/out -w /work mcr.microsoft.com/playwright:v1.63.0-noble \
  sh -c 'npm init -y >/dev/null && npm i --no-audit --no-fund playwright@1.63.0 >/dev/null 2>&1 && node shoot.mjs'
rm -rf "$WORK"
