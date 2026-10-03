# nebari-security-posture-pack — Design Contract

Status: v0.1 (experimental). This document is the contract between the chart, API,
worker and UI. Implementation agents MUST follow it; deviations go in docs/DECISIONS.md.

## 1. Purpose

An **admin-only** Nebari software pack that continuously inventories every container
running in the cluster, scans each unique image with **Trivy, Grype and Clair**,
cross-correlates the three result sets, audits workload configuration (Kubernetes
posture checks), and presents a single **Security Posture rating** (0–100 score, A–F
grade) with drill-down, in a UI built on the Nebari design system.

Experimentation target: the `grace` MicroK8s node (single node, 40 CPU, 113 GB RAM,
KUBECONFIG=~/.kube-grace/config, local registry `localhost:32000`, sslip.io hosts).

## 2. Repository layout (monorepo for the experiment)

```
nebari-security-posture-pack/
  pack-metadata.yaml           # software-pack-dashboard schema
  README.md  LICENSE  CODEOWNERS  .editorconfig  .gitignore
  .github/workflows/{lint,test,build-images,release}.yaml   # template-style
  chart/                       # Helm chart (name: nebari-security-posture-pack)
    Chart.yaml                 # dep: nebari-app >=0.1.1 oci://quay.io/nebari/charts
    values.yaml
    templates/...
  api/                         # Python 3.12 FastAPI service + worker (package `posture`)
    pyproject.toml  Dockerfile.api  Dockerfile.worker  alembic/  src/posture/  tests/
  ui/                          # React 19 + Vite + TS + Tailwind v4 + nebari-design
    package.json  Dockerfile  nginx.conf  src/  components.json
  deploy/grace/                # grace-specific: values.yaml, build-push.sh, deploy.sh
  docs/DESIGN.md  docs/SCORING.md  docs/DECISIONS.md
```

Reference material (read-only clones) at
`/tmp/claude-1000/-home-geraci/a8c043a6-2ce9-493d-b5c3-2c0b8a63e889/scratchpad/`:
`software-pack-template/`, `nic/`, `nop/` (operator alpha.20), `nop-main/`,
`nebari-design/`, `libchart/nebari-app/`. Local packs for conventions:
`~/work/bifrost-pack`, `~/deploy/checkmaite-pack`, `~/build/checkmaite-frontend`.

## 3. Runtime topology (all in release namespace, default `security-posture`)

| Component | Image | Notes |
|---|---|---|
| `ui` | `security-posture-ui` (nginx:alpine, static SPA) | Only ingress target. Proxies `/api/` → `api:8000`. `/healthz` static 200. |
| `api` | `security-posture-api` (python:3.12-slim) | FastAPI on :8000. Reads Postgres. Validates JWT + admin group. |
| `worker` | `security-posture-worker` (api image + trivy, grype, clairctl, skopeo) | 1 replica, `--stages inventory,scan`, SA `<fullname>-scanner`. Inventory + CVE scans + scan scheduler (due from the DB). PVC `/cache`. Probes `:9000/healthz`. |
| `worker-privileged` | `security-posture-worker` | 1 replica, `--stages provenance,controls,reports`, SA `<fullname>-controls`. Claims `scanned` scans: provenance, posture snapshot, `done`, controls engine, queues auto reports. `worker.splitPrivileged=false` folds it into `worker`. |
| `report-worker` | `security-posture-api` | 1 replica, `python -m posture.report_worker`, no SA token. Generates queued reports (lease, child process per report); reports PVC shared with the api (podAffinity). |
| `trivy` | `aquasec/trivy:0.75.0` (digest-pinned) | `trivy server --listen 0.0.0.0:4954 --cache-dir /cache`, PVC 3Gi. |
| `clair` | `quay.io/projectquay/clair:4.9.0` (digest-pinned) | **opt-in** (`scanner.clair.enabled`). combo mode, config from Secret, database `clair` on its own `clair-postgres` StatefulSet (`clair.postgres.dedicated`). :6060 (api) :8089 (introspection). |
| `postgres` | `postgres:16.15-alpine` (digest-pinned) | StatefulSet, PVC, database `posture` (+ `clair` when not dedicated). Tuning from `postgresql.config` (ConfigMap, `-c`). Secret `<fullname>-db` keys `password`, `postgres-password`, created once by a hook Job or `postgresql.existingSecret`. Nightly `pg_dump -Fc` CronJob `<fullname>-backup`. Support `externalDatabase`. |
| hooks | `security-posture-api` | pre-install/pre-upgrade (Argo CD PreSync): `ensure-secrets` (weight -5) creates missing Secrets, `migrate` (pre-upgrade, weight 0) runs alembic under `pg_advisory_lock`. The api `migrate` init container covers first installs. |

Grype runs inside the worker (no server); its DB lives on the worker PVC and is
refreshed by `grype db update` on the worker's schedule (default every 12h).

Namespace must carry label `nebari.dev/managed: "true"` (operator ignores it otherwise).

### NebariApp

One NebariApp named `<fullname>` pointing at `ui` service port 80:

```yaml
nebariapp:
  enabled: false                       # true in deploy/grace/values.yaml
  hostname: '{{ fail "nebariapp.hostname is required" }}'
  service: { name: '{{ include "security-posture.fullname" . | toJson }}-ui', port: 80 }
  routing:
    routes: [{ pathPrefix: /, pathType: PathPrefix }]
    publicRoutes: [{ pathPrefix: /healthz, pathType: Exact }]
    tls: { enabled: true }
  auth:
    enabled: true
    provider: keycloak
    provisionClient: true
    enforceAtGateway: true
    forwardAccessToken: true
    scopes: [openid, profile, email, groups]
    groups: ["admin"]                  # grace operator enforces at gateway
  gateway: public
  landingPage:
    enabled: true
    displayName: Security Posture
    description: Container vulnerability & configuration posture across the cluster
    icon: <URL to shield icon served by the ui, e.g. https://<host>/icon.svg> 
    category: Platform
    priority: 20
    healthCheck: { enabled: true, path: /healthz, intervalSeconds: 30, timeoutSeconds: 5 }
```

Admin gating has three layers, all on by default:
1. `auth.groups` on the NebariApp (works on grace's operator build; upstream alpha.20 only
   uses it for landing-page visibility).
2. `adminGate.securityPolicy.enabled` (default **false**): chart renders its own Envoy
   `SecurityPolicy` with `jwt` provider + `authorization.defaultAction: Deny` + allow rule
   on `groups` claim (NIC Longhorn pattern). When enabled, set `auth.enforceAtGateway:
   false` to avoid two policies on one HTTPRoute. Document this in README.
3. API verifies the JWT itself (see §5) and requires an admin group. Always on unless
   `AUTH_MODE=disabled` (local dev only).

Values: `adminGroups: ["admin"]` feeds all three layers (`auth.groups`, SecurityPolicy
rule, `ADMIN_GROUPS` env). Group matching strips a leading `/` (NIC realm mapper emits
`/group`, grace's operator mapper emits `group`).

### RBAC: one ServiceAccount per privilege level (security review C1)
The earlier single ServiceAccount shared by api + worker (and its "no Secrets access" claim) is
gone: with `provenance.helmReleases.enabled` that SA could read every Secret in the cluster.
The chart now renders (see `chart/templates/rbac.yaml`):

| ServiceAccount | pods | access |
|---|---|---|
| `<fullname>-api` | api, ui | no RBAC, `automountServiceAccountToken: false` (the api never calls the Kubernetes API) |
| `<fullname>-scanner` | scan worker (inventory + CVE scanners) | `get/list/watch` pods, namespaces, nodes, replicasets, deployments, statefulsets, daemonsets, jobs, cronjobs, serviceaccounts, networkpolicies, `nebariapps.reconcilers.nebari.dev`. **No Secrets.** |
| `<fullname>-controls` | privileged worker (provenance, controls engine, reports) | the controls ClusterRole (read-only platform objects), `get` on the one Keycloak admin Secret (namespaced Role), and **only** with `provenance.helmReleases.enabled` + an explicit acknowledgement value: `get/list` on all Secrets for Helm release discovery (RBAC cannot filter by label) |

`worker.splitPrivileged=false` runs a single worker with `<fullname>-controls`, which then also
gets the inventory ClusterRole. Untrusted image content is parsed by the scanner subprocesses
(trivy, grype, clairctl, skopeo, cosign): they run with an allowlisted environment (no
`DATABASE_URL`/`DB_PASSWORD`/OIDC/Keycloak secrets), stdin closed, in their own process group,
and are killed (SIGTERM, then SIGKILL) on timeout or scan cancellation. imagePullSecrets are
still not discovered (private registries use `registries[].existingSecret` / `REGISTRY_AUTH_FILE`).
The controls engine prefers a dedicated view-only Keycloak client (`KEYCLOAK_CLIENT_ID` /
`KEYCLOAK_CLIENT_SECRET`, realm-management `view-realm`, `view-users`, `view-events`) over the
realm admin Secret, and never falls back to the `master` realm unless
`KEYCLOAK_ALLOW_MASTER_FALLBACK=true`.

**The mirror registry is a trust anchor.** Scanners pull the mirrored copy by digest
(`…@sha256:` from `skopeo copy --digestfile`), and a cached copy is reused only after its manifest
digest is checked against the source digest (`mirrorDigestVerified` on images), so pushing
content under a mirror tag cannot change scan results. Anyone who can write to the mirror can
still deny service (delete copies); restrict writes to the worker (auth or NetworkPolicy).

### NetworkPolicy
`api` accepts ingress only from `ui` and the workers; `postgres` only from
`api`, the workers, `report-worker`, the `migrate`/`backup` Jobs (and `clair` when it shares the
server); `clair-postgres` only from `clair`; `clair`/`trivy` only from `worker`. `ui` accepts from
`envoy-gateway-system`. The compat listener accepts only `grafanaPodSelector` pods in
`allowedNamespaces`. Both workers have an egress policy (`networkPolicy.workerEgress`): DNS, the
release's pods, `allowedNamespaces` (Keycloak, Loki, Prometheus, registry), TCP `ports`
(443/80/6443) to any address outside `exceptCidrs` (169.254.0.0/16). api/ui/report-worker egress
is unrestricted.

## 4. Worker pipeline

```
inventory  →  resolve unique images (by digest)  →  mirror  →  scan ×3  →  normalize  →  score  →  persist
```

1. **Inventory** (K8s API): every pod (all phases; "running" flag = phase Running) and
   each container/initContainer/ephemeral: `image` (as specified), `imageID` (resolved
   digest), owner chain (Pod → ReplicaSet → Deployment …), namespace, NebariApp (same
   namespace; via `app.kubernetes.io/instance`/helm release label match, else namespace
   fallback), securityContext snapshot for posture checks. Excluded namespaces from
   settings (default: none; `kube-system` IS scanned).
2. **Unique image key** = `registry/repo@sha256:digest` from `imageID` when present,
   else `image` string. Keep `tag` from `image` for display.
3. **Mirror** (default on, `scanner.mirror.enabled`): `skopeo copy --all docker://<ref>
   docker://<mirrorRegistry>/posture-mirror/<repo>@<digest>` where mirrorRegistry defaults
   to `registry.container-registry.svc.cluster.local:5000` (http, insecure). Rationale:
   one external pull per digest (Docker Hub anonymous rate limits), identical bytes for
   all three scanners, and Clair gets a single reachable registry. Ref rewriting:
   `localhost:32000/...` ⇒ mirrorRegistry (same registry on grace). If mirror fails,
   fall back to scanning the original ref directly and record a warning.
4. **Scan** each image with the three adapters, concurrently per image, N images in
   parallel (`scanner.parallelism`, default 3). Per-scanner timeout (default 10m).
   - trivy: `trivy image --server http://<trivy>:4954 --format json --insecure --scanners vuln --quiet <ref>`
   - grype: `grype <ref> -o json` with `GRYPE_REGISTRY_INSECURE_USE_HTTP=true`, `GRYPE_DB_CACHE_DIR=/cache/grype`, `GRYPE_DB_AUTO_UPDATE=false`
   - clair: `clairctl --host http://<clair>:6060 report --out json <ref>` (clairctl config enabling insecure http for mirror registry)
   Each adapter returns `ScanResult{scanner, version, dbUpdatedAt?, status: ok|error|timeout|unsupported, error?, findings[]}`.
5. **Normalize** findings to `{vulnId, severity(critical|high|medium|low|negligible|unknown),
   package, installedVersion, fixedVersion?, pkgType, cvss?, title?, url?, scanner}`.
   Severity mapping: Clair `Critical/High/Medium/Low/Negligible/Unknown`; Grype same +
   `Negligible`; Trivy `CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN`.
6. **Correlate**: group by `(vulnId, package)` → consensus record with `scanners[]`,
   `severity = max`, `agreement = len(scanners)/len(enabledScanners that succeeded)`.
7. **Score** per docs/SCORING.md; persist image score, workload score, namespace score,
   cluster snapshot in `scan_snapshots`.
8. **Posture checks** (config) evaluated from inventory at each scan, independent of
   scanner success.

Scheduler: APScheduler in worker; interval from settings (default 6h); manual trigger via
API enqueues a `scan` row the worker polls (Postgres as queue, `SELECT … FOR UPDATE SKIP
LOCKED`). Also `grype db update` + trivy server self-updates. Scan rescans only images
whose digest is new or whose last scan is older than `rescanAfterHours` (default 24)
unless `force`.

## 5. API (FastAPI, prefix `/api/v1`, JSON, camelCase fields)

Auth middleware: token from `Authorization: Bearer` or cookie `NebariIdToken` (or any
cookie starting with `IdToken`). Verify signature via JWKS at `OIDC_JWKS_URL` (asymmetric
algorithms only; a JWK's own `alg` must match the header), `exp`, `nbf`, and `iss` ∈
`OIDC_ISSUERS` (comma list; both internal and external Keycloak issuers). `OIDC_ISSUERS` is
**required** with `AUTH_MODE=oidc`: the API refuses to start without it. The token must also be
meant for this app: `aud` contains, or `azp` equals, one of `OIDC_CLIENT_IDS` (the chart passes
the operator client id `<namespace>-<fullname>`) ∪ `OIDC_AUDIENCES`; with both empty the check
is skipped and a warning is logged at startup. JWKS fetch/parse failures answer 401.
State-changing `/api/v1` requests that carry cookies must be same-origin (`Sec-Fetch-Site`
same-origin/none, or an `Origin` matching the host), else 403 (CSRF).
Groups claim `groups` (strip leading `/`); require intersection with `ADMIN_GROUPS`
else 403 `{detail:"admin group required"}`. 401 when no/invalid token. `/health` and
`/ready` are unauthenticated. `AUTH_MODE=disabled` bypasses (dev only; the API refuses to start
unless `POSTURE_DEV=1`).

Env vars (api & worker): `DATABASE_URL`, `AUTH_MODE` (`oidc`|`disabled`),
`OIDC_JWKS_URL`, `OIDC_ISSUERS`, `OIDC_CLIENT_IDS`, `OIDC_AUDIENCES`, `ADMIN_GROUPS`, `TRIVY_SERVER_URL`, `CLAIR_URL`,
`MIRROR_ENABLED`, `MIRROR_REGISTRY`, `MIRROR_INSECURE`, `SCAN_PARALLELISM`,
`SCAN_TIMEOUT_SECONDS`, `SCAN_INTERVAL_HOURS`, `RESCAN_AFTER_HOURS`,
`EXCLUDED_NAMESPACES`, `CACHE_DIR`, `LOG_LEVEL`.

Endpoints:

| Method/Path | Returns |
|---|---|
| `GET /health`, `GET /ready` | `{status:"ok"}` (ready checks DB) |
| `GET /me` | `{username,email,groups[],isAdmin}` |
| `GET /summary` | `{score,grade,vulnScore,postureScore,generatedAt,lastScan:{id,status,startedAt,finishedAt,imagesTotal,imagesDone,imagesFailed},counts:{critical,high,medium,low,negligible,unknown},fixable:{critical,high,...},images:{total,scanned,failed,running} (latest done scan's unique images; DECISIONS 2026-10-03),workloads,namespaces,scanners:[{name,version,dbUpdatedAt,healthy,lastError}],trend:[{scanId,finishedAt,score,grade,critical,high}] (last 30), topRisks:[{imageId,ref,score,grade,critical,high,workloads}] (10), checks:{passed,failed,total}}` |
| `GET /images?namespace=&grade=&severity=&q=&sort=&order=&page=&pageSize=` | `{items:[ImageSummary],total,page,pageSize}` |
| `GET /images/{id}` | `ImageDetail` = ImageSummary + `findings:[Finding]` + `usedBy:[ContainerRef]` + `scans:[ScannerRun]` + `postureFindings` |
| `GET /vulnerabilities?severity=&q=&fixable=&page=` | CVE-centric: `{items:[{vulnId,severity,scanners[],agreement,imagesAffected,workloadsAffected,fixAvailable,cvss,title,url}],total}` |
| `GET /vulnerabilities/{vulnId}` | detail + affected images |
| `GET /workloads?namespace=&kind=` | `[{namespace,kind,name,pack,score,grade,images:[{imageId,ref}],containers,posture:{passed,failed},counts}]` |
| `GET /namespaces` | `[{name,pack,managed,score,grade,workloads,images,counts,posture}]` |
| `GET /checks` | `[{id,title,severity,category,description,remediation,passed,failed}]` |
| `GET /checks/{id}` | `+results:[{namespace,kind,name,container,status,detail}]` |
| `GET /scans?page=` | `[{id,trigger(manual|scheduled),status(queued|running|done|failed|cancelled),startedAt,finishedAt,imagesTotal,imagesDone,imagesFailed,score,grade,requestedBy}]` |
| `POST /scans` body `{force?:bool,imageIds?:[],namespaces?:[]}` | 202 + scan row; 409 if a scan is running (unless `imageIds` targeted) |
| `GET /scans/{id}` | scan + `perScanner:{trivy:{ok,error},...}` + recent log lines |
| `DELETE /scans/{id}` | cancel |
| `GET /scanners` | `[{name,enabled,version,dbUpdatedAt,healthy,lastError,lastRunAt}]` |
| `GET /settings` / `PUT /settings` | `{scanIntervalHours,rescanAfterHours,excludedNamespaces[],scanners:{trivy:bool,grype:bool,clair:bool},parallelism,adminGroups[] (readOnly)}` |
| `GET /export?format=json|csv` | full current snapshot |

`ImageSummary`: `{id,ref,registry,repository,tag,digest,score,grade,counts{...},fixable{...},
scanners:{trivy:ScannerRunSummary,grype:…,clair:…},agreementIndex (0–1),
namespaces[],workloads,containers,running:bool,lastScannedAt,mirrored:bool,warnings[]}`
`ScannerRunSummary`: `{status,findings,durationMs,error?,version?}`
`Finding`: `{vulnId,severity,package,installedVersion,fixedVersion,pkgType,scanners[],
agreement,perScanner:{trivy:"high",grype:"critical"},cvss,title,url,fixable}`

Pagination default `pageSize=50`, max 500. Errors: `{detail}`.

OpenAPI at `/api/v1/openapi.json`, docs at `/api/v1/docs` (admin-gated).

## 6. Database (Postgres, SQLAlchemy 2 + Alembic)

Tables (minimum): `images`, `image_scans` (per image per scan per scanner, raw JSON kept
compressed/truncated), `findings` (normalized per scanner), `consensus_findings`,
`containers` (inventory snapshot per scan), `workloads`, `posture_results`, `scans`,
`scan_snapshots` (cluster/namespace/workload/image scores per scan), `settings` (single
row JSON). Keep raw scanner JSON ≤ 2 MB per row (truncate with flag).

## 7. UI (React 19 + Vite + TypeScript + Tailwind v4 + nebari-design)

- Vendor components from `nebari-design/registry/nebari/` (globals.css theme, ui/*,
  hooks/use-theme-preference) via `shadcn add @nebari/...` inside the Docker build or by
  copying sources (no node on host). Fonts: `@fontsource-variable/geist`,
  `@fontsource/ibm-plex-mono`. Apply the `nebari-ui` SKILL.md header recipe: shared
  Nebari header (`NavigationMenu` + `MenuBarBrand` with Nebari logo, light/dark logo
  swap), profile menu with theme radio group + sign out (`/logout`), `bg-canvas` body,
  Cards on top. Sidebar via `@nebari/sidebar` for section nav.
- Routes (react-router): `/` Overview, `/images`, `/images/:id`, `/vulnerabilities`,
  `/vulnerabilities/:vulnId`, `/workloads`, `/namespaces`, `/checks`, `/checks/:id`,
  `/scans`, `/scans/:id`, `/settings`.
- Overview: big grade tile (score ring, grade letter, delta vs previous scan), severity
  stat tiles (consensus counts, fixable sub-count), scanner health row (3 cards: trivy /
  grype / clair with version, DB age, last status), trend sparkline/area chart (score
  over last 30 scans), top-10 riskiest images table, posture checks pass/fail bar,
  "Scan now" button with live progress (poll `/scans/{id}` every 3s).
- Images: DataTable (TanStack) with grade badge, severity count chips, per-scanner
  mini-status (✓/!/–), agreement index, namespaces; filters namespace/grade/severity/text.
- Image detail: header (ref, digest, grade, score breakdown), tabs: Findings (table with
  per-scanner severity columns showing which scanner flagged it — the "three-scanner
  consensus" view is the headline feature), Used by, Scanner runs (raw status/errors),
  Posture.
- Vulnerabilities: CVE-centric table; Workloads/Namespaces: grouped tables with grades.
- Checks: catalogue with pass/fail bars; detail lists offenders with remediation.
- Scans: history + live progress; Settings: form bound to `/settings`.
- Severity colors use design tokens only: critical→`destructive` strong, high→
  `destructive` soft, medium→`warning`, low→`info`, negligible/unknown→`muted`.
  Grades: A→success, B→success soft, C→warning, D→destructive soft, F→destructive.
- Runtime config: `/config.json` from ConfigMap (`{apiBase:"/api/v1", title}`).
  TanStack Query for data. Vitest unit tests for score helpers; Playwright optional.
- Dev mode: `VITE_API_MOCK=1` serves fixtures (MSW) so UI can be built without the API.

## 8. Chart values (abridged; see chart/values.yaml for full)

```yaml
images: { api: {repository, tag}, worker: {...}, ui: {...}, trivy, clair, postgres }
adminGroups: ["admin"]
adminGate: { securityPolicy: { enabled: false } }
auth: { mode: oidc, jwksUrl: "http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80/auth/realms/nebari/protocol/openid-connect/certs", issuers: [] }
scanner: { parallelism: 3, timeoutSeconds: 600, intervalHours: 6, rescanAfterHours: 24, maxImageGB: 20,
           excludedNamespaces: [], trivy: {enabled: true}, grype: {enabled: true, maxConcurrent: 2}, clair: {enabled: false},
           mirror: { enabled: true, registry: registry.container-registry.svc.cluster.local:5000, insecure: true, rewrite: {"localhost:32000": "registry.container-registry.svc.cluster.local:5000"} } }
worker: { splitPrivileged: true, resources: {500m/4Gi -> 3/7Gi}, privileged: { resources: {...} } }
reportWorker: { enabled: true, timeoutSeconds: 1200 }
reports: { retention: { perType: 20, maxTotalBytes: 2Gi } }
history: { retainScans: 30 }
persistence: { storageClass: "", worker: 15Gi, trivy: 3Gi, postgres: 10Gi, reports: 2Gi }
postgresql: { enabled: true, existingSecret: "", config: {...}, backup: { enabled: true, retention: 7 } }   # externalDatabase.* alt.
serviceAccount: { create: true, names: { api: "", scanner: "", controls: "" } }
hooks: { migrate: { enabled: true } }
networkPolicy: { enabled: true, workerEgress: { enabled: true, ports: [443, 80, 6443] } }
resources: {...}   # per component; chart/values.schema.json validates the file
nebariapp: {...as §3}
```

## 9. Grace deployment

- Namespace `security-posture`, hostname `security.100-89-230-107.sslip.io`.
- Images pushed to `localhost:32000/security-posture-{api,worker,ui}:<git-sha>`.
- `deploy/grace/build-push.sh` (docker build all three, push), `deploy/grace/deploy.sh`
  (`kubectl create ns` + label, `helm dependency build`, `helm upgrade --install
  security-posture ./chart -n security-posture -f deploy/grace/values.yaml --wait`).
- Verify: NebariApp Ready/AuthReady/RoutingReady; `curl -k https://security.../healthz`;
  unauthenticated → redirect to Keycloak; login as alice (not admin) → 403; admin → UI.

## 10. Non-goals for v0.1
imagePullSecrets discovery, SBOM storage, policy enforcement/admission, multi-cluster,
notifications. Document these in README "Limitations".

## 11. Compliance reports (ATO / cATO support)

Goal: turn each scan snapshot into the artifacts an ISSO/ISSM uploads to eMASS or hands to
an assessor, so continuous scanning feeds continuous ATO. No manual re-keying.

### Report types

| type | format(s) | content |
|---|---|---|
| `poam` | `xlsx`, `csv` | **Plan of Action & Milestones** in the eMASS POA&M import column layout (see §11.3). One row per consensus finding per image (optionally rolled up per CVE), with NIST 800-53 control, scheduled completion from severity SLA, source scanner(s), status `Ongoing`, raw + residual severity, mitigation text (fixed version). Posture check failures are rows too (control CM-6/CM-7/AC-6). |
| `stig-checklist` | `ckl` (STIG Viewer 2.x XML), `cklb` (STIG Viewer 3 JSON) | Posture checks mapped to **Kubernetes STIG** (V2R2) / **Container Platform SRG** vuln IDs via a mapping table `reports/data/stig_mapping.yaml` (checkId → `{vulnId, ruleId, ruleTitle, severity(cat), stigId, benchmark}`). Each rule gets `NotAFinding` / `Open` / `Not_Reviewed` with finding details listing offending workloads, plus comments. Scope: cluster, namespace or workload. Unmapped STIG rules are `Not_Reviewed` so the checklist is complete and importable. |
| `sar` | `pdf`, `html` | **Automated Assessment Summary (input to the SAR)**; the SAR itself is the SCA's deliverable. Narrative: system name/date/scope, methodology (three scanners, consensus, scoring), hygiene index (grade, not an assessment result) and trend, inventory (namespaces, workloads, images with digests), findings by severity with agreement, posture results, scanner versions and DB freshness, limitations, appendix tables. Printable, Nebari-branded (logo, tokens). |
| `oscal-ar` | `json` | **OSCAL Assessment Results** 1.1.x: `assessment-results` with one `result` per scan, `observations` per finding (subjects = image/workload), `risks` with severity & deadline, `findings` tied to control ids (`ra-5`, `si-2`, `cm-6`, …), `local-definitions` listing scanner tools as components. Validated against the OSCAL JSON schema in tests. |
| `inventory` | `xlsx`, `csv` | **Hardware/Software inventory** (eMASS asset list style): image, digest, registry, version/tag, namespaces, workloads, pack, running count, base OS (from scanner metadata), scanner coverage. |
| `vuln-export` | `csv`, `json`, `cyclonedx-vex` (stretch) | Flat findings export for ingest into Nessus/ACAS-style trackers or Iron Bank VAT justification sheets: one row per (image, CVE, package) with all three scanners' severities. |

### NIST 800-53 control tagging
Every finding carries `controls[]` (corrected per docs/reviews/compliance-sme.md M4):
vulnerabilities → `SI-2` (overdue → SI-2(c)); privileged/root/privilege-escalation/capabilities →
`AC-6`, `CM-7`, `SC-39` (+ `AC-6(8)` for root / escalation); host namespaces/hostPath → `SC-39`,
`AC-6`, `CM-7`; writable root fs → `CM-6`, `CM-7`, `SI-7`; resource limits/requests → `SC-5`;
mutable tag → `CM-2`, `SI-7`; probes → no control (no POA&M row); automount SA token → `AC-6`,
`CM-7`; seccomp → `CM-6`, `CM-7`, `SC-39`; no NetworkPolicy → `AC-4`, `SC-7`. STIG-derived items
also carry the controls of their DISA CCIs. `reports/data/controls.yaml` is the single source
(API, UI and every report); the POA&M keeps only controls of the selected baseline.

### Severity → remediation SLA (configurable in settings `remediationSlaDays`)
critical 15, high 30, medium 90, low 180 days from first-seen. POA&M scheduled completion =
firstSeenAt + SLA. Overdue rows are flagged; `/summary` carries `slaOverdue:{critical,high,...}`.

### API
| Method/Path | Returns |
|---|---|
| `GET /reports/types` | catalogue `[{type,formats[],scopes[],description}]` |
| `GET /reports?scanId=&type=` | `[{id,type,format,scope:{kind:cluster|namespace|workload,name?},scanId,status(queued|running|done|failed),createdAt,createdBy,sizeBytes,filename,error?}]` |
| `POST /reports` body `{type,format,scope?,scanId? (default latest done),options?:{rollupByCve?:bool,systemName?:string,includeSystemNamespaces?:bool}}` | 202 + report row; generation runs in the API process via background task (reports are seconds, not minutes) |
| `GET /reports/{id}` | row; `GET /reports/{id}/download` streams the file with correct content-type and `Content-Disposition` |
| `DELETE /reports/{id}` | delete |
| `GET /compliance/controls` | control coverage summary `[{control,title,findingsOpen,checksFailed,status}]` |
| `GET /compliance/stig` | STIG rule status rollup for the latest scan `[{vulnId,ruleId,title,cat,status,offenders}]` |

Settings additions: `systemName` (default cluster name), `organization`, `remediationSlaDays`,
`reports.autoGenerate: [types…]` (generated automatically after every completed scan, default `[]`).

Storage: `reports` table (metadata) + file bytes on the worker/api PVC under `/data/reports/<id>.<ext>`
(or bytea column if ≤ 20 MB; pick one and document). Retention: keep last 50 per type.

### UI
Route `/reports`: table of generated reports (type, format, scope, scan, created, size,
download/delete), "Generate report" dialog (type → formats → scope → options), and a
**Compliance** tab/route `/compliance` with: NIST control coverage table (open findings per
control), STIG rollup (CAT I/II/III open counts, per-rule status with offenders), SLA overdue
tiles. Findings tables show `controls` chips; check detail shows the STIG rule id.

### Implementation split
`api/src/posture/reports/` is a pure package: `generate(report_type, fmt, snapshot:
ReportSnapshot, options) -> (bytes, filename, content_type)` where `ReportSnapshot` is a
pydantic model (system/org/scan metadata, images, findings, workloads, posture results,
scanner status) built by `reports/snapshot.py` from the DB. Generators: `poam.py` (openpyxl),
`stig.py` (ckl XML via `xml.etree`, cklb JSON), `sar.py` (Jinja2 HTML → PDF via WeasyPrint),
`oscal.py`, `inventory.py`, `vuln_export.py`. Data: `data/stig_mapping.yaml`, `data/controls.yaml`.

## 12. Supply-chain provenance (superset of provenance-collector-pack)

Goal: everything `nebari-dev/provenance-collector-pack` does, inside this pack, with
**drop-in API compatibility** so its Grafana dashboards and consumers keep working, and so
this pack can replace it in NIC. Reference clone:
`/tmp/claude-1000/-home-geraci/a8c043a6-2ce9-493d-b5c3-2c0b8a63e889/scratchpad/provenance-collector-pack/`
(see `internal/report/types.go`, `internal/verify/`, `internal/discovery/`,
`docs/src/content/docs/report-schema.md`, `examples/grafana-dashboard.json`).

### Checks (worker stage `provenance`, runs per unique image after inventory, before/independent of CVE scanning)
| check | how | result fields |
|---|---|---|
| signature | `cosign verify` (key/keyless per `provenance.cosign.*`), else `cosign tree`/referrers lookup for existence | `signature:{signed,verified,error}` |
| SLSA provenance | OCI referrers API / cosign attestation tags; predicateType `https://slsa.dev/provenance/v1` or v0.2 | `provenance:{hasProvenance,predicateType}` |
| SBOM | attestation with predicateType spdx/cyclonedx, or `.sbom` tag | `sbom:{hasSBOM,format}` |
| update check | `skopeo list-tags`, semver parse, `updateLevel` patch/minor/major, `skipPrerelease` | `update:{currentTag,latestInMajor,newestAvailable,updateAvailable}` |
| Helm releases | read `sh.helm.release.v1.*` secrets cluster-wide (optional RBAC, `provenance.helmReleases.enabled`, default true on grace) | `helmReleases[]` per their schema |

Tools in the worker image: `cosign` (pinned release binary), `skopeo` (already), `oras` optional.
Results stored per image per scan (`image_provenance` table) and surfaced on `ImageSummary.provenance`
and `ImageDetail`. SBOM attestations, when present, are downloaded and fed to grype as `sbom:` input
(faster; `provenance.useSbomForGrype`, default false).

### Compatibility API (served by our API: admin-gated like the rest on the main listener; a value
`provenance.compat.internalService` additionally exposes `/api/reports/*` and `/api/export` on a ClusterIP
Service for Grafana Infinity, like their `-web-internal` Service, but behind a static bearer token from a
Secret (`PROVENANCE_COMPAT_TOKEN_FILE`; Grafana sends it as a header). Without a token the api refuses to
start unless `PROVENANCE_COMPAT_ALLOW_ANONYMOUS=true`. The report list (newest 50) and the latest report
are cached and invalidated per scan.)
- `GET /api/reports` → `[{filename, generatedAt, sizeBytes}]`
- `GET /api/reports/latest`, `GET /api/reports/{filename}` → their report JSON **verbatim schema**
  (`metadata{generatedAt,collectorVersion,clusterName,namespacesScanned}`, `images[]`, `helmReleases[]`,
  `summary{totalImages,uniqueImages,signedImages,verifiedImages,imagesWithSBOM,imagesWithProvenance,
  imagesWithUpdates,totalHelmReleases,helmReleasesWithUpdates}`). `collectorVersion` = our version with
  suffix `+posture`. Generated from the latest done scan; one file per scan (`provenance-<ts>.json`).
- `GET /api/export?format=csv|json` → their flat export.
- `GET /api/me`, `POST /api/scan`, `GET /healthz` → aliases to ours.
Our native endpoints: `GET /api/v1/supply-chain` summary `{signed,verified,withSbom,withProvenance,
withUpdates,unique,helmReleases,helmWithUpdates,score,grade}`, `GET /api/v1/helm-releases`.

### Scoring and controls
Supply-chain score per image: start 100; −40 unsigned (−20 signed-but-unverified), −20 no SBOM,
−15 no provenance, −15 update available (−25 if major behind), −10 mutable tag w/o digest pin.
Cluster `supplyChainScore` = container-weighted mean. Cluster score becomes
`0.6 vuln + 0.25 posture + 0.15 supplyChain` (update SCORING.md). Controls: unsigned → CM-14, SR-4;
no SBOM → SR-4, SA-8(3)… no provenance → SR-3, SR-4, SA-10; update available → SI-2; Helm release
behind → SI-2, CM-3. Added to `controls.yaml` under `provenance:`.

### UI
- Images table: three glyph columns Signed / SBOM / Provenance (tooltips with details) and an "update"
  arrow with latest tag. Image detail: new tab **Supply chain**.
- New page `/supply-chain`: stat tiles (signed %, verified %, SBOM %, provenance %, updates), Helm releases
  table (release, namespace, chart, version → latest, status), unsigned/outdated image lists.
- Overview gains a supply-chain tile; Settings gains the `provenance.*` toggles, cosign key, updateLevel.

## 13. Control evidence engine (phase 2: 800-53 "top to bottom")

Goal: because NIC deploys the whole platform declaratively, assert **control implementation** for the
technical controls it provides and **collect evidence continuously** with live checks, producing an OSCAL
SSP draft + assessment results an assessor can *review*, with per-control evidence status and evidence. Package
`api/src/posture/controls_engine/`; router `routers/controls.py`; worker stage `controls` after each scan.

### Model
- `catalog`: NIST SP 800-53 rev5 OSCAL catalog (JSON, vendored, trimmed to id/title/family/class, plus
  the moderate baseline profile ids) → `GET /compliance/catalog?family=`.
- `components`: OSCAL component-definitions (YAML in `controls_engine/data/components/*.yaml`) for
  Keycloak, Envoy Gateway + nebari-operator SecurityPolicy, cert-manager, nebari-operator, Loki/Promtail,
  Prometheus/Alertmanager, Kubernetes (PodSecurity, RBAC, NetworkPolicy), container registry, this pack
  itself (RA-5, SI-2, CM-8, SR-4 …). Each: `implemented-requirements[]` with `control-id`, statement
  text, `inherited: true|false`, and `assertions[]` ids.
- `assertions`: python functions, each `{id, title, controls[], component, severity, evaluate(ctx) ->
  {status: pass|fail|unknown|not-applicable, evidence: {...}, detail}}`. Context gives K8s API clients,
  Keycloak admin client (realm admin secret ref from values `controlsEngine.keycloak.adminSecret`),
  HTTP client, and the latest scan snapshot. First-cut assertions (≥25):
  - Keycloak: brute-force detection enabled (AC-7); password policy set (IA-5(1)); admin group members
    have OTP/MFA required (IA-2(1)); SSO session idle/max timeouts ≤ policy (AC-12, AC-11); realm
    `rememberMe` off (AC-12); `registrationAllowed` off (AC-2); events + admin events logging enabled
    with retention (AU-2, AU-12); no users with `admin` realm role beyond allowlist (AC-6(5)).
  - Gateway: HTTPS listener present and HTTP redirects (SC-8, SC-23); TLS min version ≥1.2 on
    ClientTrafficPolicy (SC-8(1), SC-13); every NebariApp with `auth.enabled` has a SecurityPolicy or
    `enforceAtGateway:false` with a documented in-app check (AC-3, IA-2); landing visibility consistent.
  - cert-manager: ClusterIssuer exists and is Ready (SC-12, SC-17); no expired/near-expiry Certificates
    (SC-12(1)).
  - Kubernetes: every non-system namespace has `pod-security.kubernetes.io/enforce` ≥ baseline (CM-6,
    CM-7); a default-deny ingress NetworkPolicy per app namespace (SC-7(5)); no ClusterRoleBinding to
    `cluster-admin` for non-system subjects beyond allowlist (AC-6(1)); `default` ServiceAccounts have
    `automountServiceAccountToken:false` (AC-6(10)); no anonymous auth binding (`system:anonymous`) (AC-14);
    nodes on supported K8s version (SI-2); metrics-server/Prometheus scraping (AU-6); audit of API
    server not visible → `unknown` with explanation.
  - Logging: Loki (or lgtm) reachable and receiving logs from all namespaces within last 10 min (AU-2,
    AU-12, AU-4 retention value); Alertmanager has at least one receiver (SI-4(5), IR-6).
  - Registry: in-cluster registry not world-writable / requires auth or is cluster-internal only (CM-14,
    SR-4); image pull policy / mutable tags covered by posture checks.
  - This pack: scan ran within `scanIntervalHours`×2 (RA-5(2)); scanner DBs < 72h old (RA-5(2), SI-5);
    POA&M generated for open findings (CA-5); SLA overdue count = 0 (SI-2(c)).
- Status derivation per control (evidence status, compliance review M1-M3/M5): one derivation over the
  assertions (tagged with the SP 800-53A objectives they evidence), posture-check failures and open /
  SLA-overdue findings. `passing` only when every objective has passing evidence; `hybrid` when the
  platform's objectives pass and the rest is assigned to the program (CRM); otherwise `partial`
  ("n of m objectives"), `failing` or `not-assessed`. `inherited` only from a named, authorized common
  control provider; `org-provided-unverified` (opt-in) never counts; `not-applicable` only from AO
  tailoring. Rollup per family. Details: CONTROLS.md.

### API
- `GET /compliance/controls` (extend existing): per control `{control,title,family,baseline,status,
  responsibility,provider,objectives:[{id,state}],scanEvidence,components[],assertions:[{id,title,status,
  evidence,checkedAt}],findingsOpen,checksFailed}`.
- `GET /compliance/families` → `{baseline, items:[{family,title,total,passing,partial,failing,hybrid,
  inherited,orgProvided,notApplicable,notAssessed}], totals:{baseline:{name,total,...same keys},
  catalog:{...}}}` (items = the selected baseline; DECISIONS 2026-10-03).
- `GET /compliance/crm?baseline=` → `{baseline, runId, summary:{provider,shared,customer,org}, items:[...]}`.
- `GET /compliance/assertions`, `POST /compliance/assertions/run` (202, runs engine now), `GET
  /compliance/assertions/{id}` (history).
- Report type `oscal-ssp` (json): OSCAL 1.1.2 `system-security-plan` with `control-implementation.
  implemented-requirements[]` statuses + by-component + links to evidence; validate against official
  schema in tests. Report `oscal-ar` includes assertion observations from the same run. Add
  `oscal-component-definition` and the draft CRM (`GET /compliance/crm`, report `crm`).
- Settings: `controlsEngine.baseline` (low|moderate|high, default moderate), allowlists for admin
  subjects, `organization` inherited-controls statement text.

### UI
- `/compliance` gains tabs: **Controls** (family rollup bar chart + sortable catalog table with status
  badges, filter by family/status/baseline; row expands to evidence per assertion with "checked at" and
  raw evidence JSON), **STIG** (existing), **SLA** (existing). Overview gets a "Controls with passing
  evidence x/y (moderate)" tile. Reports dialog gains `oscal-ssp`, `oscal-component-definition` and `crm`;
  the one-click button is the "Evidence package".
