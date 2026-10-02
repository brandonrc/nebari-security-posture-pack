# security-posture-ui

React 19 + Vite 7 + TypeScript (strict) + Tailwind v4 SPA for the Nebari Security Posture pack,
built on the [Nebari design system](https://github.com/nebari-dev/nebari-design). Served by an
unprivileged nginx that also proxies `/api/` to the API service. Contract: `../docs/DESIGN.md`
§5 (API), §7 (UI), §11 (compliance reports) and `../docs/SCORING.md`.

## Container contract (for the chart)

| Item | Value |
|---|---|
| Base image | `nginxinc/nginx-unprivileged:1.27-alpine` |
| User | uid/gid **101** (`nginx`); works with `runAsNonRoot`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` |
| Listen port | **8080** (`NGINX_PORT`, default 8080). The chart Service maps **80 → 8080** (`targetPort: http`). |
| Writable paths | `/tmp` only (pid, temp dirs, rendered config in `/tmp/nginx/conf.d`). Mount emptyDirs at `/tmp` and `/var/cache/nginx`. |
| `API_UPSTREAM` | `host:port` of the API, scheme optional (`http://security-posture-api:8000` and `security-posture-api:8000` both work). Default `security-posture-api:8000`. |
| `/healthz` | static `200 ok` (unauthenticated public route) |
| `/icon.svg` | shield icon for the landing-page tile (public route) |
| `/config.json` | runtime config `{"apiBase": "/api/v1", "title": "Security Posture"}`; the chart ConfigMap is mounted over `/usr/share/nginx/html/config.json` (subPath). Served `no-store`. |
| Caching | `index.html` / SPA routes `no-cache`; `/assets/*` (content-hashed) `max-age=1y, immutable`; gzip on. |

How the config is rendered: `/etc/nginx/templates/default.conf.template` is processed by the
official image's envsubst entrypoint into `/tmp/nginx/conf.d` (`NGINX_ENVSUBST_OUTPUT_DIR`),
and `nginx.conf` includes it from there. `docker/05-security-posture.envsh` runs first: it strips
any scheme from `API_UPSTREAM` and, when `/etc/resolv.conf` carries a Kubernetes
`<ns>.svc.<domain>` search domain, qualifies a bare service name with it. The proxy uses a
variable upstream + `resolver` (from `/etc/resolv.conf`, via `NGINX_ENTRYPOINT_LOCAL_RESOLVERS`),
so nginx starts even before the API Service resolves and follows Service IP changes.

`/api/` is proxied with `Host $host`, all request headers (Authorization and the `NebariIdToken`
/ `IdToken*` cookies the API authenticates with), `proxy_read_timeout 120s`, and no buffering.

Verify locally (what the chart does):

```sh
docker build -t security-posture-ui:dev ui/
docker run --rm -p 8080:8080 --user 101:101 --read-only \
  --tmpfs /tmp:uid=101,gid=101 --tmpfs /var/cache/nginx:uid=101,gid=101 --cap-drop ALL \
  -e API_UPSTREAM=http://host.docker.internal:8000 security-posture-ui:dev
curl localhost:8080/healthz
```

## Development (Docker only — no host node required)

```sh
cd ui
alias dnode='docker run --rm -it -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app -e HOME=/tmp -p 5173:5173 node:22-alpine'
dnode npm ci
dnode npm run dev:mock      # http://localhost:5173 — fully demoable with MSW fixtures, no API needed
dnode npm run dev           # proxies /api to $API_PROXY (default http://localhost:8000)
dnode npm run lint          # eslint
dnode npm run typecheck     # tsc -b --noEmit
dnode npm test              # vitest (unit + MSW-backed component tests)
dnode npm run build         # dist/
```

`.npmrc` sets `legacy-peer-deps=true` (npm 10 crashes resolving the optional peer graph of
vitest/msw otherwise).

### Mock mode (`VITE_API_MOCK=1`)

`src/mocks/` holds an MSW worker + deterministic fixtures: 27 images (one with every scanner
failing → grade `?`; Clair `unsupported`/`timeout` and Grype `error` on others), ~220 consensus
findings drawn from real CVEs with per-scanner severity disagreements, 28 workloads across 11
namespaces, 16 posture checks with per-container results, a 30-scan history (one failed, one
cancelled), STIG rules in Open / NotAFinding / Not_Reviewed, NIST control coverage, and reports
in done / running / failed. `POST /scans` progresses over ~30 s (live progress + toast);
`POST /reports` completes after ~5 s; `PUT /settings` persists in memory.
Append `?mockAuth=401` or `?mockAuth=403` to any URL to see the session-expired / admins-only screens.

### Screenshots

`screenshots/run.sh` builds the mock bundle, serves it with `vite preview`, and captures
Overview, Images, Image detail, Compliance and Reports in light and dark (plus Overview at
900 px) with Playwright in `mcr.microsoft.com/playwright:v1.63.0-noble`.

## Design system

Nebari registry items are vendored as source (the registry's distribution model) and treated as
upstream-managed — don't edit them; customise at the call site:

- `src/index.css` — `@nebari/theme` (`globals.css`) verbatim, then the app-owned header tokens
  (`--header-action-hover`, `--notification-badge`, `--sign-out-foreground`) in separate blocks.
- `src/components/ui/*` — alert, badge, breadcrumb, button, card, checkbox, data-table, dialog,
  dropdown-menu, field, input, label, navigation-menu, select, sidebar, skeleton, spinner,
  switch, table, tabs, textarea, toast, tooltip.
- `src/hooks/*` — `use-theme-preference`, `theme-provider`; `src/lib/utils.ts` — `cn()`.
- `public/` — Nebari symbol/favicon and horizontal lockups, unmodified (CC BY-NC-ND 4.0).
- `@base-ui/react` is pinned to `~1.6.0` (the registry's tested version; 1.8 changes toast types).

Severity and grade colours use semantic tokens only (`src/lib/severity-styles.ts`):
critical → `destructive-foreground` solid, high → `destructive` soft, medium → `warning`,
low → `info`, negligible/unknown → `muted`; grades A/B → success, C → warning, D/F → destructive.
