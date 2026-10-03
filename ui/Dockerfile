# syntax=docker/dockerfile:1
# ── build ────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_API_MOCK=
ENV VITE_API_MOCK=${VITE_API_MOCK}
RUN npm run build

# ── runtime ──────────────────────────────────────────────────────────────────
# nginx-unprivileged: runs as uid/gid 101, listens on an unprivileged port.
FROM nginxinc/nginx-unprivileged:1.31-alpine
LABEL org.opencontainers.image.title="security-posture-ui" \
      org.opencontainers.image.description="Nebari Security Posture pack UI (static SPA + /api proxy)" \
      org.opencontainers.image.source="https://github.com/nebari-dev/nebari-security-posture-pack"

USER root
RUN rm -f /etc/nginx/conf.d/default.conf
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
