# syntax=docker/dockerfile:1
# ── build ────────────────────────────────────────────────────────────────────
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_API_MOCK=
ENV VITE_API_MOCK=${VITE_API_MOCK}
RUN npm run build

# ── runtime ──────────────────────────────────────────────────────────────────
# nginx-unprivileged: runs as uid/gid 101, listens on an unprivileged port. The -slim variant
# (~21 apk packages vs ~70) drops curl, libxml2/libxslt, gd/libavif/tiff and the njs/geoip/
# image-filter/xslt modules, none of which this config loads. Pinned by digest (Dependabot bumps
# tag + digest together); `apk upgrade` below picks up Alpine fixes published after the base.
FROM nginxinc/nginx-unprivileged:1.31-alpine-slim@sha256:1517d8c358e2e093957ebee087afa9eb19a32f5d7ecb711b7429e369cb998224
LABEL org.opencontainers.image.title="security-posture-ui" \
      org.opencontainers.image.description="Nebari Security Posture pack UI (static SPA + /api proxy)" \
      org.opencontainers.image.source="https://github.com/nebari-dev/nebari-security-posture-pack"

USER root
RUN apk upgrade --no-cache \
 && rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY docker/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY docker/05-security-posture.envsh /docker-entrypoint.d/05-security-posture.envsh
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod 0755 /docker-entrypoint.d/05-security-posture.envsh \
 && chmod -R a+rX /usr/share/nginx/html /etc/nginx
USER 101

ENV NGINX_PORT=8080 \
    API_UPSTREAM=security-posture-api:8000 \
    NGINX_ENVSUBST_OUTPUT_DIR=/tmp/nginx/conf.d \
    NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1 \
    NGINX_ENVSUBST_FILTER="^(NGINX_|API_UPSTREAM)"
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${NGINX_PORT}/healthz || exit 1
