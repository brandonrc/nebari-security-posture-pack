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

## Grace deployment status (2026-10-03)

- Deployed tag `cefb217-1790989563` = phase-1 code (`ca2a6a7`) plus the POA&M xlsx fix
  (`663e268`, cherry-picked locally as `cefb217`); phase-2 code (§12/§13) is not deployed yet.
  API limit 4Gi (one POA&M xlsx peaks at ~1.06 GiB; nine concurrent reports OOMKilled it at 1Gi).
- Scan #5 (scheduled, 2026-10-02 20:33-20:40 UTC): 68 images, 67 scored, 1 failed; cluster
  score 28.2, grade F (vuln 8.3, configuration 74.6); 24,668 consensus findings
  (777 critical / 6,830 high / 12,410 medium / 3,541 low); posture checks 1,140 pass / 464 fail.
  Scans #1-#4 failed during the bring-up (worker/Clair OOMKills and redeploys).
- Scanner coverage on scan #5: trivy 67/68, grype 67/68, clair 61/68.
- Known failures:
  - `artifacts.100-89-230-107.sslip.io/ray/ray-polars:2.56.0`: all three scanners and the skopeo
    mirror fail with `x509: certificate signed by unknown authority`. The node's containerd trusts
    that registry through `certs.d/.../hosts.toml` (`ca = .../ca.crt`); the worker and Clair pods
    do not have the CA. Environment configuration, not an adapter bug; needs a CA-bundle mount
    (chart feature, not implemented).
  - Clair `unexpected return status: 500` on 6 images (artifact-keeper-backend,
    postgres:16-alpine, dependencytrack/apiserver, opensearch, 2x artifact-keeper-scanner-adapter):
    exactly the first parallelism-6 batch at 20:33:42, while the Clair Deployment was being
    rolled (helm revision 5 at 20:33:28 changed its memory limit). The new Clair pod never
    received those requests (its log has no 5xx), so the old, terminating pod answered them.
    Transient, not an adapter bug; the stale-on-scanner-error rule (`a1b71f3`) rescans these
    images on the next scan. The adapter does not retry 5xx.
- Report verification from scan #5 (admin via the gateway, sequential): every type/format
  generates; POA&M xlsx 86 s (previously >15 min, quadratic), SAR PDF 125 s / 199 pages, OSCAL AR
  81 MB valid against the OSCAL 1.1.2 schema.
- Grace hazard: creating a docker network (e.g. `ui/screenshots/run.sh` creates `sp-shots`) adds a
  host IP; MicroK8s `apiserver-kicker` then regenerates certs and restarts kubelite and containerd,
  killing every pod for ~40 s (2026-10-03 00:45). Use `--network host` or an existing network.
- Capacity: node memory requests are 99% allocated; the root filesystem (hostpath PVCs, local
  registry) is 98% full (7.7 GB free); the Clair database is 8 GB of the 10Gi postgres PVC.
