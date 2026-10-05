#!/bin/sh
# ui/ here and provenance-collector-pack's frontend/ are one codebase. This diffs the two trees
# and exits 1 on any difference outside the allowlist (2 if the upstream tree isn't found).
#
# Usage: ui/scripts/diff-upstream-frontend.sh [path/to/provenance-collector-pack/frontend]
#   default: $UPSTREAM_FRONTEND, else provenance-collector-pack/ next to this repo's checkout.
#
# Must match: src/, playwright/, public/, index.html, nginx.conf, docker/default.conf.template,
# docker/security-headers.conf, the eslint/vite/vitest/tsconfig/components/.npmrc files,
# .gitignore, .dockerignore, and
# package.json / package-lock.json apart from the package "name".
#
# Allowlist (per-pack packaging, not UI code): README.md, Dockerfile (image labels, default
# API_UPSTREAM), docker/05-security-posture.envsh (default API_UPSTREAM), .node-version (CI there
# reads it), screenshots/ (each repo shoots its own pages), the package "name".
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
up=${1:-${UPSTREAM_FRONTEND:-$here/../../provenance-collector-pack/frontend}}
if [ ! -d "$up/src" ]; then
  echo "upstream frontend not found: $up (pass its path as the first argument)" >&2
  exit 2
fi
up=$(cd "$up" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

status=0
for d in src playwright public; do
  diff -r -x node_modules "$here/$d" "$up/$d" >>"$tmp/out" 2>&1 || status=1
done
for f in index.html nginx.conf docker/default.conf.template docker/security-headers.conf \
  eslint.config.js vite.config.ts vitest.config.ts tsconfig.json tsconfig.app.json \
  tsconfig.node.json components.json .npmrc .gitignore .dockerignore; do
  [ -e "$here/$f" ] || [ -e "$up/$f" ] || continue
  diff "$here/$f" "$up/$f" >>"$tmp/out" 2>&1 || { echo "--- $f" >>"$tmp/out"; status=1; }
done
# package name sits on the root "name" lines (package.json line 2, lockfile lines 2 and 8)
for f in package.json package-lock.json; do
  sed '1,10s/^\( *"name": \)"[^"]*"/\1"*"/' "$here/$f" >"$tmp/a"
  sed '1,10s/^\( *"name": \)"[^"]*"/\1"*"/' "$up/$f" >"$tmp/b"
  diff "$tmp/a" "$tmp/b" >>"$tmp/out" 2>&1 || { echo "--- $f (ignoring the package name)" >>"$tmp/out"; status=1; }
done

if [ "$status" -ne 0 ]; then
  cat "$tmp/out"
  echo "ui/ and $up differ outside the allowlist" >&2
  exit 1
fi
echo "ui/ and $up match (allowlist: README.md, Dockerfile, docker/05-security-posture.envsh, .node-version, screenshots/, package name)"
