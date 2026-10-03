# security-posture-ui

React 19 + Vite 7 + TypeScript (strict) + Tailwind v4 SPA for the Nebari Security Posture pack,
built on the [Nebari design system](https://github.com/nebari-dev/nebari-design). Served by an
unprivileged nginx that also proxies `/api/` to the API service. Contract: `../docs/DESIGN.md`
§5 (API), §7 (UI), §11 (compliance reports), §12 (supply-chain provenance), §13 (control evidence
engine) and `../docs/SCORING.md`.

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
cancelled), STIG rules in Open / NotAFinding / Not_Reviewed, and reports in done / running / failed.
§12: provenance on every image (cosign keyless-verified upstream images, Docker official images with
BuildKit SBOM + SLSA v0.2 but no signature, a signed-but-unverified Bitnami image, unattested
third-party images, one private image whose checks couldn't run) with patch/minor/major updates, and 12
Helm releases (deployed / failed / pending-upgrade). §13: 33 assertions across pass / fail / unknown /
not-applicable with realistic evidence JSON, and a 79-control 800-53 rev5 slice over 13 families whose
statuses derive from the assertions (plus inherited and tailored-out controls). `POST /scans` progresses over ~30 s (live progress + toast);
`POST /reports` completes after ~5 s; `POST /compliance/assertions/run` finishes after ~4 s (the
Compliance page polls and toasts); `PUT /settings` persists in memory.
Append `?mockAuth=401` or `?mockAuth=403` to any URL to see the session-expired / admins-only screens.

### Screenshots

`screenshots/run.sh` builds the mock bundle, serves it with `vite preview`, and captures
Overview, Images, Image detail (Findings and Supply chain tabs), Supply chain, Compliance (Controls
tab with one control expanded, and STIG tab) and Reports in light and dark (plus Overview at
900 px) with Playwright in `mcr.microsoft.com/playwright:v1.63.0-noble`.

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
| `POST /compliance/assertions/run` | 202 `{status, startedAt?}` | The UI then polls `GET /compliance/assertions` every 2 s until the newest `checkedAt` ≥ `startedAt` (3 min cap), toasts the pass/fail tally and refetches the compliance queries. |
| Settings `provenance` | `{verifySignatures, cosign:{mode, publicKey?, certificateIdentity?, certificateOidcIssuer?}, checkSbom, checkProvenance, checkUpdates, updateLevel, skipPrerelease, helmReleases:{enabled}}` | Missing keys are filled with defaults before editing; key mode requires `publicKey`. |
| Settings `controlsEngine` | `{enabled, baseline, adminSubjects[]}` | Baseline drives the Controls coverage tile ("x/y (moderate baseline)"). |
| Reports | types `oscal-ssp`, `oscal-component-definition` | Listed from `/reports/types` like every other type; "Compliance package" queues `poam.xlsx`, `stig-checklist.cklb`, `sar.pdf`, `oscal-ar.json`, `oscal-ssp.json` (cluster scope), skipping any the API doesn't offer. |

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
