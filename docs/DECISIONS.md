# Decisions log

- 2026-10-02: No ArgoCD on grace. Inventory source is the Kubernetes API (pods, owners,
  NebariApps), not ArgoCD. This also works on NIC clusters that do run ArgoCD.
- 2026-10-02: Admin gate = NebariApp `auth.groups` (grace operator enforces at gateway)
  + optional chart-rendered SecurityPolicy for upstream operators + API-side JWT/group
  verification. Default admin group `admin` (exists in grace's realm).
- 2026-10-02: Monorepo (chart + api + ui) for the experiment. Nebari convention is code in
  separate repos; split later if promoted.
- 2026-10-02: Mirror-then-scan via skopeo into the in-cluster registry so all three
  scanners see identical bytes and Docker Hub is pulled once per digest.
- 2026-10-02 (api/worker): Mirror destination is
  `<mirror>/posture-mirror/<src-registry>/<repo>:sha256-<hex>` (registry in the path avoids
  collisions; a digest-derived *tag* keeps one copy per digest and stays scannable).
  Default copies only the node platform (no `--all`, which multiplied registry storage by
  the number of platforms); `MIRROR_ALL_PLATFORMS=true` restores `--all`. Refs whose
  registry is rewritten to the mirror registry (`localhost:32000` on grace) are scanned in
  place without copying.
- 2026-10-02 (api/worker): clairctl CLI order is `clairctl -c <cfg> report --host <url> --out
  json <ref>` (`--host` is a `report` flag in 4.9). clairctl falls back to http for
  `localhost`, `*.local` and private IPs only; for other insecure hosts the adapter pins the
  ref to the host's private IP. When Clair reports `Unknown` severity (e.g. Alpine secdb)
  and a CVSS enrichment exists, severity is derived from the CVSS base score.
- 2026-10-02 (api/worker): SCORING agreement multiplier is relative to the scanners that
  succeeded: a finding reported by every succeeded scanner gets 1.0; otherwise 1→0.6,
  2→0.85. So with 2 of 3 scanners up, 2/2 = 1.0 and 1/2 = 0.6.
- 2026-10-02 (api/worker): Posture checks are evaluated on one representative pod per
  workload (prefer a Running pod) so replicas do not multiply penalties; results are per
  (workload, container), pod-level checks have `container: ""`. Probe checks apply only to
  long-running containers (not Job/CronJob, not plain init containers); ephemeral
  containers are ignored. `no-netpol` is skipped when NetworkPolicies cannot be listed.
- 2026-10-02 (api/worker): Workload vuln part uses images of running containers, falling
  back to all its containers when no pod runs (completed Jobs); workload/cluster score is
  `null` (grade `?`) when no image of it has a score. Namespace/cluster weights use running
  containers.
- 2026-10-02 (api): `GET /me` requires a valid token but NOT the admin group (so the UI can
  explain a 403); every other endpoint except `/health`, `/ready` requires admin.
  `OIDC_ISSUERS` empty = issuer not restricted (signature still verified; warning logged).
  Optional `OIDC_AUDIENCE`. `aud` is not checked by default (operator-provisioned client id).
- 2026-10-02 (api/worker): Extra tables `scanner_status` (worker-observed versions/DB
  freshness; the api image has no scanner binaries) and `worker_heartbeat`. Raw scanner JSON
  is stored gzip-compressed in `image_scans.raw_gz` (truncated at 2 MB raw, `truncated`
  flag), raw blobs older than 14 days are dropped; inventory/posture/workload rows are kept
  for the last 10 completed scans. `consensus_findings` keeps `first_seen_at` across scans
  per (image, vulnId, package) for SLA tracking.
- 2026-10-02 (api/worker): Alembic lives inside the package (`src/posture/alembic`) so it
  ships in the wheel/image; `api/alembic.ini` points there for CLI use.
- 2026-10-02 (api/worker): Images run as uid/gid 10001 (chart contract), HOME=/tmp, read-only
  root fs; worker writes only to /cache (grype DB, trivy client cache, clairctl config,
  skopeo policy) and /tmp. Worker serves `GET :9000/healthz` `{status,lastHeartbeatAgeSeconds}`.
  Additional env vars beyond §5: `OIDC_AUDIENCE`, `TRIVY_ENABLED`, `GRYPE_ENABLED`,
  `CLAIR_ENABLED`, `MIRROR_REWRITE`, `MIRROR_ALL_PLATFORMS`, `REGISTRY_AUTH_FILE`,
  `GRYPE_DB_UPDATE_HOURS`, `SCAN_ON_START`, `WORKER_HEALTH_PORT`, `CLUSTER_NAME`.
- 2026-10-02 (integration): Report bytes live on disk (`REPORTS_DIR=/data/reports/<id>.<ext>`,
  PVC `persistence.reports`, 2Gi), metadata in `reports`. `POST /reports` validates
  (unknown type/format/scope/`poamVariant` → 422; PDF without WeasyPrint libs → 503; no
  completed scan → 409) then generates in a FastAPI BackgroundTask; generation failures
  become `status: failed` rows with `error`. Download of a row whose file is gone → 410.
  The worker generates `reports.autoGenerate` (cluster scope, default formats poam=xlsx,
  stig-checklist=cklb, sar=pdf, oscal-ar=json, inventory=xlsx, vuln-export=csv,
  `createdBy: "auto"`) after each completed scan, so it mounts the same PVC; with
  ReadWriteOnce the worker has a required podAffinity to the api pod and the api uses
  `strategy: Recreate`. Retention: newest 50 finished reports per type
  (`REPORTS_KEEP_PER_TYPE`). `GET /reports/types` adds `defaultFormat`; `/checks` items carry
  `stig: {vulnId, ruleId, cat, benchmark, all[]}`; `/compliance/stig` rows add `checkId`.
- 2026-10-03 (controls engine, §13): Package `controls_engine/` with assertions registered by a
  decorator (`@assertion(id, title, controls, component, severity)` on `async def evaluate(ctx)`);
  components in `controls_engine/data/components/*.yaml`; catalog trimmed from the official
  usnistgov/oscal-content rev5 files (5.2.0) by `data/build_catalog.py` (250 KB, controls +
  enhancements, family, class, NIST implementation level, LOW/MODERATE/HIGH membership).
  35 assertions: the §13 list, with Keycloak events split into login/admin events, the gateway
  HTTPS check split into listener/redirect, and four additions (`kc-ssl-required`,
  `k8s-workload-least-privilege` from the scan's posture checks, `pack-inventory-current` for
  CM-8, `log-retention` for AU-4/AU-11).
- 2026-10-03 (controls engine): One `not-implemented` status (OSCAL `planned`) instead of
  "planned/not-implemented". Added derivation rules: controls with assertions but no run yet are
  `unknown`; uncovered NIST organization-level controls are `inherited` (common controls) while
  settings `controlsEngine.inheritOrganizationalControls` is true (default), uncovered
  system-level controls are `not-implemented`; component requirements without an assertion are
  `unknown`. Organization-defined parameters (settings `controlsEngine.parameters`) default to the
  FedRAMP Moderate values (AC-7 3 attempts, AC-11 15 min, IA-5(1) 12 chars, AU-11 90 days).
- 2026-10-03 (controls engine): `GET /compliance/controls` is served by `routers/controls.py`;
  `status` is now the engine status and the §11 value (`not_assessed|open|satisfied`) moved to
  `findingStatus`. Default rows: the selected baseline, plus controls an assertion covers, plus the
  §11 scan-evidence controls (`includeAll=true` adds the rest of the scope). Extra routes:
  `GET /compliance/runs`, `GET /compliance/runs/{id}`. `POST /compliance/assertions/run` queues a
  `control_assertion_runs` row (returns the pending one instead of a duplicate; 409 when
  `controlsEngine.enabled` is false); the worker claims it in its poll loop and also runs the engine
  after every completed scan (after `reports.autoGenerate`, so `pack-poam-current` sees the new
  POA&M). Last 100 runs kept.
- 2026-10-03 (controls engine): Report types `oscal-ssp` and `oscal-component-definition` are
  cluster-scope only. report_jobs attaches the latest engine run to the snapshot for `oscal-ssp`.
  `oscal-ar` does not include assertion observations yet (deferred; the SSP embeds the evidence as
  back-matter resources). Migration `0003_controls_engine` follows `0002_provenance`.
- 2026-10-03 (controls engine): Keycloak admin client accepts master-realm or target-realm
  credentials (`adminRealm` empty = target realm first, then master) and client-credentials
  secrets. RBAC adds pods and serviceaccounts (needed by the namespace checks) to the §13 list.
  `tests/conftest.py` sets `CONTROLS_ENGINE_ENABLED=false` by default so the shared worker harness
  never reaches a live cluster; `tests/controls_engine` enables it with fake clients.

## Grace deployment status (2026-10-03, phase 2)

- Deployed: api/worker `10f6df7-1790990443` (phase 2: §12 provenance + §13 control evidence
  engine, `extraCACerts`), ui `72a5e81-1790990739` (findings pagination). Migrations
  `0001 -> 0002_provenance -> 0003_controls_engine` applied by the api `migrate` init container.
  Limits unchanged: api 4Gi, worker 16Gi, Clair 8Gi.
- Values (`deploy/grace/values.yaml`): provenance on with Helm releases and the Grafana compat
  Service (allowed from `monitoring`, `observability`); keyless cosign identity for
  `registry.k8s.io` (krel-trust / accounts.google.com); controls engine MODERATE with
  `adminSubjectsAllowlist: [admin]`, master-realm creds from `keycloak/nebari-realm-admin-credentials`,
  Loki/Prometheus/Alertmanager in `observability`. `extraCACerts.secretName: nebari-ca` (the
  cert-manager `nebari-ca-secret` CA, created by `deploy.sh`) fixed the `artifacts.*.sslip.io`
  x509 failure: `ray/ray-polars:2.56.0` now mirrors and scans with trivy, grype and Clair.
- Scan #6 (manual, force, 2026-10-03 01:24:53-01:31:13 UTC, 6m20s): 79 images, 79 scored,
  0 failed; trivy/grype/Clair 79/79 each (the six scan-#5 Clair 500s are gone). Cluster score
  27.7, grade F (vulnerability 8.2, configuration 74.8, supply chain 27.3 F); findings
  780 critical / 6,847 high / 12,403 medium / 3,536 low; posture checks 1,150 pass / 464 fail.
- Provenance (scan #6): 16 signed, 5 verified (all `registry.k8s.io`), 8 with SBOM, 34 with SLSA
  provenance, 57 with updates, 17 Helm releases (0 behind: no `chartRepos`, so "not checked";
  `deploy/grace/values.yaml` now lists them, verified against the live repos, not deployed yet),
  6 registry errors, all Docker Hub `429` (kiwigrid/k8s-sidecar, curlimages/curl:8.9.1,
  bitnami/redis, busybox:1.36, bitnami/postgresql, aquasec/trivy:0.75.0). Docker Hub 429 also
  failed the skopeo mirror for `rayproject/ray:2.56.0` and `bitnami/postgresql:latest`; both were
  scanned from the original ref. Signed-but-unverified (11) is expected: those images are signed
  with other keys/identities than the configured keyless identity.
- Control evidence engine (MODERATE): 35 assertions, 19 pass / 15 fail / 1 unknown
  (`k8s-api-audit-logging`, MicroK8s). Versus the dev-time table (18/16/1) the only change is
  `kc-admin-role-allowlist` (now pass: `admin` is allowlisted). Controls: 20 implemented,
  6 partial, 62 not implemented, 199 inherited of 287 (catalog view: 292 incl. 5 out-of-baseline,
  2 of them unknown).
- Compat API: `security-posture-web-internal:8080/api/reports/latest` returns their schema
  (`metadata`, `images` 99 per-workload entries / 78 unique, `helmReleases` 17, `summary`) from
  `monitoring` without auth; from `default` the connection times out (NetworkPolicy).
- Reports (scan #6, via the gateway): the 6 auto-generated reports completed; OSCAL SSP (0.43 MB,
  290 implemented-requirements) and component definition (9 components) validate against the
  OSCAL 1.1.2 schemas with 0 errors; the compliance package (POA&M xlsx 132 s, STIG cklb 30 s,
  SAR pdf 228 s, OSCAL AR 37 s, SSP 19 s, queued concurrently) completed with no api restart.
- Known issues:
  - Update check follows upstream Masterminds/semver ordering, so numeric non-release tags win
    "newest available" (e.g. cert-manager v1.16.2 -> `608111629`, grafana -> `9799770991`,
    postgres 16-alpine -> `18.6`); `latestInMajor` is sane. These images are counted as
    major-update-available. Fixed in master (candidate filter, see the 2026-10-03 update-check
    entry below); not deployed yet.
  - The image list and the Supply chain page include 7 images no longer running (old
    `localhost:32000/security-posture-*` tags, no provenance): "74 of 86 images" there vs 79
    in the scan. Overview "Images scored 73/73" counted only images with a Running pod (the 6
    completed-Job images were missing). Fixed in master (current-image set, see below); not
    deployed yet.
  - Docker Hub unauthenticated pull limits (see above); `registryAuth.existingSecret` would fix it.
- Grace hazard: creating or removing a docker network adds/removes a host IP; MicroK8s
  `apiserver-kicker` then regenerates certs and restarts kubelite and containerd, killing every
  pod for ~40 s (2026-10-03 00:45). Use `--network host`; leave `sp-shots` alone.
- Capacity: node memory requests are ~99% allocated; root filesystem 46 GB free (88%) after pruning superseded local images.
- 2026-10-03 (provenance, deviation from provenance-collector-pack): update candidates are
  filtered before the Masterminds/semver ordering. Only version-like tags count (optional `v`,
  2-3 numeric components, 4th tolerated, optional suffix; no bare integers, no MAJOR over 4
  digits, no dates unless the current tag is a date), candidates more than
  `provenance.maxMajorJump` (50, `PROVENANCE_MAX_MAJOR_JUMP`) majors above the current one are
  ignored, and a candidate must carry the current tag's variant suffix shape (`-alpine`,
  `-py3.12`, ...); real prereleases (rc/beta/dev/...) still follow `skipPrerelease`. Reason:
  upstream's ordering made CI build-number tags (`608111629`) the newest version and suggested
  other image variants, which charged a wrong major-update penalty. Details in PROVENANCE.md.
- 2026-10-03 (api/ui): one image set for counts: the *current* images are the unique images in
  the latest done scan's inventory (`views.current_image_ids`, the scan's `imagesTotal` on a full
  scan), including completed-Job images that have no Running pod; images seen only in older scans
  are *stale*. `/summary.images` = `{total: current, scanned: with a score, failed: no successful
  scanner, running: with a Running pod}` (severity counts and top risks stay on Running images, as
  the vulnerability score does). `/supply-chain` counts and lists default to current images
  (`?includeStale=true` restores all of the provenance scan's rows; `stale` = left out).
  `/images` items carry `current` and accept `?current=`; the UI Supply chain page asks for
  `current=true` and filters client-side too (also in its fallback summary).
- 2026-10-03 (api/ui, controls): `GET /compliance/families` returns `{baseline, items, totals:{baseline,
  catalog}}` instead of a bare list (the UI client accepts both). The Compliance tiles mixed
  denominators ("20/287" was the MODERATE baseline, "64 not implemented / 2 unknown" counted the
  292-control catalog view). Every tile (Compliance and the Overview controls tile) now shows the
  baseline numbers with the baseline name in the label; catalog numbers are in a tooltip. Clicking
  a status tile also filters the catalog table to the baseline so its row count matches.
- 2026-10-03 (security review fixes, api/worker code side; chart wiring is a separate change):
  - **Auth (H1, L4):** `AUTH_MODE=oidc` with empty `OIDC_ISSUERS` refuses to start; tokens must
    have `aud` containing or `azp` equal to one of `OIDC_CLIENT_IDS` ∪ `OIDC_AUDIENCES` (chart:
    `OIDC_CLIENT_IDS=<namespace>-<fullname>`, the NebariApp operator's client id; both empty =
    warning, no check). `AUTH_MODE=disabled` needs `POSTURE_DEV=1`. JWKS failures are 401; the
    JWKS lock no longer spans the fetch (single flight, stale-while-revalidate).
  - **Mirror (C2):** scan `…@<digest>` from `skopeo copy --digestfile`; reuse a cached copy only
    when its manifest digest equals the source digest or is one of the source index's platform
    manifests; images expose `mirrorDigestVerified`. The mirror stays an availability trust anchor.
  - **Compat listener (H2):** bearer token from `PROVENANCE_COMPAT_TOKEN_FILE` (chart mounts a
    Secret at `/etc/posture/compat/token`) or `PROVENANCE_COMPAT_TOKEN`; no token = refuse to
    start unless `PROVENANCE_COMPAT_ALLOW_ANONYMOUS=true`. Grafana's Infinity datasource must send
    `Authorization: Bearer <token>`. List/latest cached per scan, list capped at 50.
  - **Registry client (H3):** streamed caps (manifest 4 MiB, tags 8 MiB, blobs 16 MiB, token 1 MiB),
    manual redirects refused to private/loopback/link-local addresses (except configured insecure
    in-cluster registries), realm host = registry host / parent domain / `auth.docker.io` /
    `PROVENANCE_REGISTRY_AUTH_REALMS`. DNS-rebinding between check and connect is not prevented;
    the worker egress NetworkPolicy remains the backstop.
  - **Subprocesses (M2, M3):** OCI reference grammar on parse, `safe_ref_arg` before exec, `--`
    before the image argument (trivy, grype, clairctl, cosign, skopeo; checked against the worker
    image binaries), allowlisted env, stdin `/dev/null`, process-group SIGTERM→SIGKILL (10 s) on
    timeout and cancellation, scanner JSON streamed to `CACHE_DIR/tmp` and parsed from the file.
    There is no Python wrapper for the Go provenance collector in this tree (`provenance/collector.py`
    does not exist), so the go-maintainer §4 cancellation item has nothing to fix here yet; any
    future wrapper must use `scanners.base.run_proc`.
  - **Helm (M1):** decompressed release payload cap `PROVENANCE_HELM_MAX_RELEASE_BYTES` (16 MiB).
  - **Keycloak (M4):** `KEYCLOAK_CLIENT_ID` + `KEYCLOAK_CLIENT_SECRET`/`_FILE` (view-only
    `client_credentials` client) preferred, admin Secret password grant as fallback, `master` only
    with `KEYCLOAK_ALLOW_MASTER_FALLBACK=true`.
  - **CSV/XLSX (M5):** `reports.cells.safe_cell` prefixes `'` to `= + - @ \t \r` cells in POA&M,
    inventory and vuln-export. `routers/export.py` and the compat `export_csv` should adopt it.
  - **CSRF + headers (M6):** cookie-carrying unsafe `/api/v1` requests need `Sec-Fetch-Site`
    same-origin/none or a matching `Origin`. nginx adds `frame-ancestors 'none'` CSP, XFO DENY,
    nosniff, Referrer-Policy, Permissions-Policy, COOP; no script/style CSP until checked in a browser.
  - **Trust settings (L5):** `PROVENANCE_TRUST_SETTINGS_LOCKED=true` (chart default) makes the cosign
    key / identity / issuer env-only; `PUT /settings` answers 403. **Report deletion (L7)** is
    logged with the admin's username; report files outside `REPORTS_DIR` are never read or unlinked.
  - Env the chart must set: api `OIDC_ISSUERS` (required), `OIDC_CLIENT_IDS`,
    `PROVENANCE_COMPAT_TOKEN_FILE` (+ Secret mount) when the internal Service is on,
    `PROVENANCE_TRUST_SETTINGS_LOCKED=true` (api + worker); worker optional
    `KEYCLOAK_CLIENT_ID`/`KEYCLOAK_CLIENT_SECRET` (secretKeyRef), `KEYCLOAK_ALLOW_MASTER_FALLBACK`,
    `PROVENANCE_REGISTRY_AUTH_REALMS`, `PROVENANCE_HELM_MAX_RELEASE_BYTES`. Never set `POSTURE_DEV`.
