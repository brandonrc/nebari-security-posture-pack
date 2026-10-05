# security-posture-ui

React 19 + Vite 7 + TypeScript (strict) + Tailwind v4 SPA for the Nebari Security Posture pack,
built on the [Nebari design system](https://github.com/nebari-dev/nebari-design). Served by an
unprivileged nginx that also proxies `/api/` to the API service. Contract: `../docs/DESIGN.md`
§5 (API), §7 (UI), §11 (compliance reports), §12 (supply-chain provenance), §13 (control evidence
engine) and `../docs/SCORING.md`.

## Container contract (for the chart)

| Item | Value |
|---|---|
| Base image | `nginxinc/nginx-unprivileged:1.31-alpine-slim` (digest-pinned, `apk upgrade` at build) |
| User | uid/gid **101** (`nginx`); works with `runAsNonRoot`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` |
| Listen port | **8080** (`NGINX_PORT`, default 8080). The chart Service maps **80 → 8080** (`targetPort: http`). |
| Writable paths | `/tmp` only (pid, temp dirs, rendered config in `/tmp/nginx/conf.d`). Mount emptyDirs at `/tmp` and `/var/cache/nginx`. |
| `API_UPSTREAM` | `host:port` of the API, scheme optional (`http://security-posture-api:8000` and `security-posture-api:8000` both work). Default `security-posture-api:8000`. |
| `/healthz` | static `200 ok` (unauthenticated public route) |
| `/icon.svg` | shield icon for the landing-page tile (public route) |
| `/config.json` | runtime config; the image ships `{"apiBase": "/api/v1"}`, and the chart ConfigMap (`{"apiBase", "title"}`) is mounted over `/usr/share/nginx/html/config.json` (subPath). Served `no-store`. All keys, including provenance-collector-pack's `keycloak` block, are listed under [Running against provenance-collector only](#running-against-provenance-collector-only). |
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
dnode npm run dev:mock-provenance  # same, provenance-only mode (mock Go dashboard, see below)
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
cancelled), STIG rules in Open / NotAFinding / Not_Reviewed, and reports in done / running / failed.
§12: provenance on every image (cosign keyless-verified upstream images, Docker official images with
BuildKit SBOM + SLSA v0.2 but no signature, a signed-but-unverified Bitnami image, unattested
third-party images, one private image whose checks couldn't run) with patch/minor/major updates, and 12
Helm releases (deployed / failed / pending-upgrade). §13: 33 assertions across pass / fail / unknown /
not-applicable with realistic evidence JSON, and a 79-control 800-53 rev5 slice over 13 families whose
statuses derive from the assertions (plus inherited and tailored-out controls). §14: three SCAP
benchmarks (RHEL 9 DISA, Ubuntu 22.04 SSG, PostgreSQL 15 DISA; 30 rules each) evaluated on eight
images (one with two benchmarks, one with a degraded rootfs), the rest "n/a". `POST /scans` progresses over ~30 s (live progress + toast);
`POST /reports` completes after ~5 s; `POST /compliance/assertions/run` finishes after ~4 s (the
Compliance page polls and toasts); `PUT /settings` persists in memory.
Append `?mockAuth=401` or `?mockAuth=403` to any URL to see the session-expired / admins-only screens.

### Screenshots

`screenshots/run.sh` builds the mock bundle, serves it with `vite preview`, and captures
Overview, Images, Image detail (Findings and Supply chain tabs), Supply chain, Compliance (Controls
tab with one control expanded, and STIG tab) and Reports in light and dark (plus Overview at
900 px) with Playwright in `mcr.microsoft.com/playwright:v1.63.0-noble`. Both containers use
`--network host` (preview on `127.0.0.1:$PORT`, default 4173); the script must never run
`docker network create`, which restarts MicroK8s on the grace host.

## Running against provenance-collector only

The same bundle can stand in for `frontend/` in
[provenance-collector-pack](https://github.com/nebari-dev/provenance-collector-pack): with only that
pack's Go dashboard behind `/api/`, the UI runs in **provenance-only mode**.

**Detection.** At startup the SPA probes `GET {apiBase}/summary` (`/api/v1/summary`). Any 2xx, 401,
403 or 5xx means the posture API is there (`posture` mode, every section, gateway cookies). A 404, an
HTML 200 (a static SPA fallback) or a network error means `provenance` mode. `"mode": "posture"` or
`"mode": "provenance"` in `/config.json` skips the probe; set it when the backend may be briefly
down at page load, since a gateway 502 counts as posture. `useCapabilities()` (`src/capabilities.ts`)
returns `{mode, features}`. The sidebar, routes, Overview, Images, image detail and Supply chain
read it.

**What provenance mode shows.**

| Section | Source | Notes |
|---|---|---|
| Overview | `GET /api/reports/{latest\|file}` | Supply-chain score ring, signed / verified / SBOM / provenance / update tiles, report metadata (cluster, collector, schema version, namespaces), collector warnings, last 5 reports, Run scan. |
| Images, image detail | same report, adapted | Provenance columns only (supply-chain grade, signed, SBOM, provenance, update, namespaces, workloads); filter, sort and paging run in the browser. Detail has the Used by and Supply chain tabs. |
| Supply chain | same report | Unchanged page (tiles, Helm releases, unsigned and outdated lists). |
| Reports | `GET /api/reports` | One row per collector run. **View** switches the dataset that Overview, Images and Supply chain show; a banner offers *Back to latest*. Downloads: JSON (`/api/reports/{file}`), CSV and Markdown (`/api/export?format=csv\|markdown&filename=`). Each download is a fetch with the bearer token, saved as a blob. A Δ column of unique images appears when `/api/me` sets `features.timelineDeltas`. |
| Scans | `POST /api/scan` + `GET /api/reports` | **Run scan** shows only when `/api/me` returns `canRunScan`. After the POST, the job name and namespace are shown and `/api/reports` is polled every 5 s for up to 5 min until a newer report appears; that report is then loaded. 409, 403 and 503 responses show a toast. History lists one row per report. |

Vulnerabilities, Workloads, Namespaces, Posture checks, Compliance, Settings and scan detail are
hidden, and their routes redirect to `/`.

**Report adapter** (`src/api/provenance-adapter.ts`). This maps the collector report
(`src/api/provenance-report.ts`, hand-written from `schema/report.schema.json` 1.x) onto
`ImageSummary.provenance`, `SupplyChainSummary`, `HelmRelease[]`, `Namespace[]` and `ImageDetail`.

- Images are grouped by reference, the collector's own `uniqueImages` key.
- The supply-chain score is computed with `lib/supply-chain.ts`. The cluster score is the mean of
  the image scores, weighted by container count.
- The collector counts signed, SBOM, provenance and update images per container record. The
  adapter recounts them per unique image, so percentages stay at or below 100%.
- The report omits `sbom`, `provenance` and `update` both when nothing was found and when the
  check is off. The adapter treats a check as on if any record in the report has that object. It
  then reads a missing object on an image with a resolved digest as a negative (no SBOM, up to
  date). Images whose digest could not be resolved show "not checked".
- `src/api/provenance-adapter.test.ts` walks the vendored schema and fails if a field has no
  mapping.

**Auth.** If `/config.json` has a complete `keycloak` block (`url`, `realm`, `clientId`, the
shape of provenance-collector-pack's `frontend-configmap.yaml`), keycloak-js logs in before the
first render, using `login-required`, PKCE `S256` and no session iframe. Every request then
carries `Authorization: Bearer`. The token is refreshed when less than 30 s of validity is left.
After a 401 the client forces a refresh and retries once. A second 401 shows the Session expired
screen. Sign out calls Keycloak logout.

Without a `keycloak` block the dashboard is assumed to run with auth disabled, and no header is
sent. In posture mode the gateway-cookie behaviour is unchanged.

`src/api/client.ts` is still the only fetch layer. It reads its auth from the strategy in
`src/auth/strategy.ts`. The browser adds `Sec-Fetch-Site: same-origin` to `POST /api/scan`, and
nginx forwards it.

**Runtime config** (`/config.json`; both packs' keys are accepted, unknown keys are ignored):

| Key | Default | Used by |
|---|---|---|
| `apiBase` | `/api/v1` | posture API base; also the capability probe |
| `provenanceApiBase` | `/api` | Go dashboard base (`/reports`, `/me`, `/scan`, `/export`) |
| `title` | per mode: "Security Posture" / "Supply-chain provenance" | header, sidebar, tab title |
| `mode` | `auto` | `auto` \| `posture` \| `provenance` |
| `keycloak.url`, `.realm`, `.clientId` | unset | provenance-mode PKCE login (all three required) |
| `logoUrl`, `logoUrlDark`, `faviconUrl`, `theme` | ignored | provenance-collector-pack branding; not implemented |

**Deploying in provenance-collector-pack's chart.** Set `frontend.image` to this image. That
chart mounts its own `nginx.conf` over `/etc/nginx/nginx.conf`, which proxies `/api/` to the
dashboard Service and serves `/healthz` locally, and its `config.json` over
`/usr/share/nginx/html/config.json`. Both work unchanged.

To use this image's nginx instead, mount only `config.json` and set
`API_UPSTREAM=<fullname>-web:<webUI.port>`. `location /api/` proxies `/api/reports*`, `/api/me`,
`/api/scan` and `/api/export` with the URI and all headers unchanged; `/healthz` stays local.

Checked against the real dashboard (`go run ./cmd/dashboard` with the golden report, auth off),
both behind this image's nginx:

- `/api/v1/summary` returns 404, so the UI starts in provenance mode.
- `POST /api/scan` without `Sec-Fetch-Site` returns 403. With `Sec-Fetch-Site: same-origin` it
  returns 503 ("not configured"), which shows the header is forwarded.
- In a browser, Overview, Images, Reports and the CSV export all work.

**Mock mode.** `VITE_API_MOCK=provenance` (`npm run dev:mock-provenance`, `npm run
build:mock-provenance` → `dist-mock-provenance/`) starts an MSW copy of the Go dashboard
(`src/mocks/provenance-backend.ts`). It serves the golden report (`src/mocks/fixtures/report.golden.json`)
plus two older runs, answers 404 for `/api/v1/*`, and uses a stand-in keycloak-js session whose
bearer the mock requires. A manual scan finishes after about 8 s. Add `?mockAuth=viewer` for a
user without `canRunScan`, `?mockAuth=401` for a rejected token, or `?mockAuth=noauth` for a
dashboard with OIDC off.

`npm run build:mock-preview` builds both mock bundles. Playwright runs `provenance.spec.ts`
against the provenance bundle on `PORT+1`, with `PROVENANCE_BASE_URL` to override:

```sh
dnode npm run build:mock-preview
docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/app -w /app \
  mcr.microsoft.com/playwright:v1.63.0-noble npx playwright test -c playwright/playwright.config.ts
```

**Not supported from their API.**

- There is no job-status endpoint (`GET /api/scan` returns 405), so a run is followed by polling
  for a new report. The job's pod status and logs are not shown, and a failed Job shows up only
  as the 5-minute timeout.
- `/api/me` returns `email` but no display name. The name comes from the ID token.
- Branding keys in `config.json` are ignored.
- The dashboard's `/healthz` is not proxied.

## API assumptions (§12 / §13)

The contract leaves these open; the UI uses the names below and reads every one defensively
(missing → the view degrades, never crashes). Types live in `src/api/types.ts`.

| Where | Field / behaviour | Notes |
|---|---|---|
| `ImageSummary.provenance` | `{signature?, sbom?, provenance?, update?, score?, grade?, deductions?, mutableTag?, checkedAt?}` | Sub-objects use provenance-collector-pack's JSON names (`signed`, `verified`, `error`, `hasSBOM`, `format`, `hasProvenance`, `predicateType`, `currentTag`, `latestInMajor`, `newestAvailable`, `updateAvailable`). A missing sub-object means "check not run" and is shown as a dashed "not checked" glyph with no score deduction. Absent `provenance` → no Supply chain data state. |
| `provenance.signature.mode` | `key` \| `keyless` | Optional; shown next to the signature status. |
| `provenance.sbom.downloadUrl` | root-relative or absolute URL | When present the Supply chain tab shows a Download button (mock: `GET /api/v1/images/{id}/sbom`). |
| `provenance.provenance.builder` | SLSA builder id | Optional. |
| `provenance.update.level` | `patch` \| `minor` \| `major` | Optional; otherwise derived by semver-comparing `currentTag` with `newestAvailable` / `latestInMajor` (unparseable tags → `patch`). |
| `provenance.score` / `deductions[]` | `[{reason, points}]` | Optional; when absent the UI recomputes the §12 score client-side (`src/lib/supply-chain.ts`). |
| `provenance.mutableTag` | bool | Optional; falls back to tag `latest`/missing. |
| `Summary.supplyChainScore` | number \| null | Present → the Overview shows the 0.6 / 0.25 / 0.15 split; absent → the pre-§12 0.7 / 0.3. |
| `GET /supply-chain` | `{signed, verified, withSbom, withProvenance, withUpdates, unique, helmReleases, helmWithUpdates, score, grade}` | If it fails, `/supply-chain` derives the same numbers from `/images?pageSize=500` + `/helm-releases`; the Overview tile hides. |
| `GET /helm-releases` | `HelmRecord[]` (`releaseName, namespace, chart, version, appVersion, status, update?`) | Bare array or `{items}`. |
| `GET /compliance/controls` | §13 shape; `family`, `baseline`, `components`, `assertions` all optional | `baseline` is the **lowest** baseline containing the control (`low`/`moderate`/`high`; baselines nest) or an explicit list. Status spellings normalised: `satisfied`→implemented, `not-satisfied`/`planned`→not-implemented. A plain §11 list still renders (family from the id prefix). |
| `ControlAssertion.detail` | one-line summary | Shown under each assertion; otherwise a compact `key=value` rendering of `evidence`. `evidence` is any JSON, shown in a collapsible code block. |
| `GET /compliance/families` | as §13 | If it fails or is empty, the rollup is computed from `/compliance/controls`. |
| `POST /compliance/assertions/run` | 202 queued run row `{id, status, createdAt, startedAt?}` | The UI then polls `GET /compliance/assertions` every 2 s until the newest `checkedAt` ≥ `createdAt` (falls back to `startedAt`, then the click time; 3 min cap), toasts the pass/fail tally and refetches the compliance queries. |
| Settings `provenance` | flat, matching the API model: `{enabled, verifySignatures, cosignPublicKey, cosignCertificateIdentityRegexp, cosignCertificateOidcIssuerRegexp, checkSbom, checkProvenance, checkUpdates, updateLevel, skipPrerelease, helmReleases (bool), recheckHours}` | Missing keys get defaults before editing. Key vs keyless is a UI-only choice: key mode = non-empty `cosignPublicKey` (required when chosen); switching to keyless clears it. |
| Settings `controlsEngine` | `{enabled (read-only, Helm), baseline, adminSubjects[]}` | Baseline drives the Controls coverage tile ("x/y (moderate baseline)"). |
| Reports | types `oscal-ssp`, `oscal-component-definition` | Listed from `/reports/types` like every other type; "Compliance package" queues `poam.xlsx`, `stig-checklist.cklb`, `sar.pdf`, `oscal-ar.json`, `oscal-ssp.json` (cluster scope), skipping any the API doesn't offer. |

§14 SCAP field names and fallbacks are listed in `../docs/DECISIONS.md` (2026-10-05, "UI for the
SCAP scanner"); every view is posture-mode only and hidden when the API serves no SCAP data.

The Control catalog is composed from table-kit + the Nebari `Table` primitives rather than
`DataTable`, because the vendored DataTable has no row-expansion slot.

## Design system

Nebari registry items are vendored as source (the registry's distribution model) and treated as
upstream-managed — don't edit them; customise at the call site:

- `src/index.css` — `@nebari/theme` (`globals.css`) verbatim, then the app-owned header tokens
  (`--header-action-hover`, `--notification-badge`, `--sign-out-foreground`) in separate blocks.
- `src/components/ui/*` — alert, badge, breadcrumb, button, card, checkbox, code-block, data-table, dialog,
  dropdown-menu, field, input, label, navigation-menu, select, sidebar, skeleton, spinner,
  switch, table, tabs, textarea, toast, tooltip.
- `src/hooks/*` — `use-theme-preference`, `theme-provider`; `src/lib/utils.ts` — `cn()`.
- `public/` — Nebari symbol/favicon and horizontal lockups, unmodified (CC BY-NC-ND 4.0).
- `@base-ui/react` is pinned to `~1.6.0` (the registry's tested version; 1.8 changes toast types).

Severity and grade colours use semantic tokens only (`src/lib/severity-styles.ts`):
critical → `destructive-foreground` solid, high → `destructive` soft, medium → `warning`,
low → `info`, negligible/unknown → `muted`; grades A/B → success, C → warning, D/F → destructive.
