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

## Grace deployment status (2026-10-05, scan accounting)

- Deployed: helm revision 17 (2026-10-05 01:42:59 UTC), images `065cc06-1791164424` (api, worker,
  ui; built from a clean worktree of 065cc06: 297f923 scan accounting / scoped post-scan stages /
  event-scan hygiene, 6bc0547 chart `scanner.events.*`, 065cc06 docs). Chart `scanner.events`
  defaults (debounce 300 s, min pod age 120 s, Jobs ignored); values unchanged. Hooks: ensure-secrets
  and migrate Jobs completed; `alembic_version` = `0006_scan_accounting`; the api `migrate` init
  container then found nothing to apply (`migrate.done`). All pods rolled, 0 restarts, no
  warning/error log lines in api, worker, worker-privileged, report-worker 37 min after rollout.
- Rollout side effect: the old pod watcher queued event scan #35 for the new pack pods and it was
  failed by the shutdown (`worker shutting down`); the new watcher queued #36 at 01:45:37, ~2 min
  after the new pods started (min pod age).
- Scheduler before the upgrade: scheduled scans 20, 21, 24, 25, 29 each ran 6 h apart
  (23:23:55 ... 23:24:02, drift = previous scan's start). After manual scan #37 the next due is
  `2026-10-05T07:50:01Z` (= #37 start + 6 h).
- Scan rows (`/api/v1/scans`) carry the new counts; rows before 0006 show null and the Scans page
  falls back to "done/total". Observed:
  - #36 event (rollout, ns security-posture): 6 targeted · 3 rescanned · 3 fresh, 88 inventoried;
    provenance 4 checked / 84 carried; controls ran (previous scan had no posture hash); reports
    skipped ("event scan (targeted)").
  - #37 manual, not forced (the scheduled scan was 3.5 h away): 0 rescanned · 88 fresh · 88 in
    inventory, `imagesTotal` 0, 3m13s; provenance 1 checked (the image whose last check errored)
    / 87 carried; controls ran (full scan); 6 reports auto-queued and done (SAR 124 s, others
    8-18 s) because the previous full scan (#29) predates 0006 and has no `inventory_hash` (unknown
    counts as changed; the image set had also changed by the three new pack tags). The
    "0 rescanned, inventory unchanged -> reports skipped" path of a full scan was not observed yet
    (next chance: the 07:50 scheduled scan).
  - Scans page: "0 rescanned · 88 fresh · 88 in inventory", "6 targeted · 3 rescanned · 3 fresh",
    "2 targeted · 2 rescanned · 0 fresh", "2 targeted · 1 rescanned · 1 fresh"; while #36 ran it
    showed "6 targeted · 3/3 rescanned · 3 fresh".
- Churn test (ns default):
  - `busybox:1.37` pod: no event scan in 5.5 min. Correct: the watcher only reacts to digests no
    scan has seen, and that digest is image 7 (scanned 2026-10-04 20:46). New digests were built
    instead (`localhost:32000/churn-test:1..4`, `FROM alpine:3.20` + a label).
  - `churn-test` (churn-test:1) created 02:00:11 -> #38 queued 02:02:21 (130 s, min age 120 s).
    `churn-test2` (churn-test:2) created 02:00:56 was still younger than 120 s, but #38 is
    namespace-targeted and its inventory scanned both new images: 2 targeted · 2 rescanned ·
    0 fresh; no second scan was queued for churn-test2. Provenance 3 checked / 87 carried; controls
    ran (two new workloads changed the posture hash, as designed); reports skipped.
  - `churn-test` replaced (same pod/container name, churn-test:3) at 02:09:59 -> #39 queued
    02:12:09 (130 s; 9m48s after #38): 2 targeted · 1 rescanned · 1 fresh (only churn-test:3
    scanned); provenance 1 checked / 89 carried (stage 51 s); `controls engine skipped: targeted
    scan; workloads and security contexts unchanged`; reports skipped.
  - Jobs: `churn-job` (sleep 200) and `churn-job2` (sleep 600) with the new digest churn-test:4,
    created 02:13:28/02:13:41: no event scan by 02:20:55 (past min age and the debounce window).
    The 03:17 backup CronJob was not observed under the new watcher.
  - No reports were queued after 01:53:14 (only #37's six). Pods and Jobs deleted afterwards.
- Metrics (port-forward to :9000): scan worker `posture_scan_image_selection_total`
  {event: rescanned 6, skipped_fresh 4; manual: rescanned 0, skipped_fresh 88};
  worker-privileged `posture_post_scan_stage_total` {controls run 3, skipped 1; reports run 1,
  skipped 3}, `posture_provenance_images_total` {checked 9, carried 347};
  `posture_scan_images{status=inventoried|rescanned|skipped_fresh}` 88/0/88 (latest full scan
  #37). Each counter lives on the pod that runs that stage (selection on the scan worker, post-scan
  stages and provenance on worker-privileged). Prometheus-side scrape of the new series not checked.
- Known issues: the provenance stage still takes 51-193 s with 1-4 images checked (#36 190 s,
  #37 182 s, #38 193 s, #39 51 s), so "finish the stage in seconds" (scan-accounting entry) does
  not hold on grace. Not timed per step; the likely cost is the Helm chart update check, which
  runs every scan with a fresh `ChartRepos` (every `index.yaml` re-downloaded and parsed) and, for
  the charts no repo publishes, walks every repo down to the `oci://docker.io` tag list (429). The pack's own images score 0.0 (F) (api 320, ui 225, worker 495 findings). Docker Hub
  429 remains (1 provenance registry error on #36/#37). Items from the section below not
  re-checked here are unchanged.

## Grace deployment status (2026-10-03, hardened pack; superseded by the section above)

- Deployed: chart `nebari-security-posture-pack-0.1.0` (this repo), helm revision 16, images
  `cc63640-1791050439` (api, worker, ui; the report-worker and the hook Jobs run the api image).
  Rev 13 (319c484) replaced rev 12 (`provenance-collector-0.2.0` from the fork) with a plain
  `helm upgrade`: no uninstall, no `nameOverride` (the fullname collapses to the release name and
  the selector label `app.kubernetes.io/name: nebari-security-posture-pack` was already the old
  chart's); PVCs, DB and the `-db` Secret were kept (DB not reset). Revs 14-16 carried the fixes below.
- Upgrade path: the hooks ran (ensure-secrets patched `security-posture-db`, created
  `security-posture-compat-token`). On rev 13 the migrate hook could not reach Postgres (the
  *old* NetworkPolicy admits only api/worker/clair; hooks run before the new one is applied) and
  exited 0 after its 120 s wait; the api `migrate` init container applied `0004_ops_scale` and
  `0005_control_status_detail`, and the report-worker logged one loop error (missing column) before
  that. From rev 14 on the migrate hook connects (`migrate.done`). One-time effect of upgrading
  from a pre-hook chart.
- Fixed during the deploy: backup PVC stayed Pending under WaitForFirstConsumer and `helm --wait`
  hung (9d2f941; rev 13 was unblocked with a manual backup Job); metrics gauges took targeted event
  scans as "latest scan" (5ba5d13); `vuln_rollup.kev` always false (255202d); `pack-scan-recent` /
  `pack-poam-current` judged event scans (0254df4, cc63640); grace values need
  `allowMasterFallback: true` since M4, else all 12 kc-* assertions were unknown (d6cc06e).
- Security fixes, observed live: api, ui and report-worker pods (SA `security-posture-api`) have no
  `/var/run/secrets/kubernetes.io/serviceaccount`; `can-i list secrets -A`: api no, scanner no,
  controls yes (`iUnderstandClusterSecretsRead`); NetworkPolicies `worker-egress` and
  `workers-ingress` present; compat listener from a Grafana pod in `observability`: no token 401,
  wrong token 401, token 200 (69 KB); from `default` with the token: connection timeout;
  anonymous -> 302 to Keycloak; alice -> 403 (gateway); admin -> 200; cookie POST with
  `Origin: https://evil.example` -> 403 `cross-site request blocked`, same-origin -> 202; UI and
  API responses carry CSP `frame-ancestors 'none'`, XFO DENY, nosniff, Referrer-Policy,
  Permissions-Policy, COOP (no HSTS from nginx).
- Scheduler: `scheduler.next_scan due=<max(started_at) of done full scans> + 6h` (to the
  microsecond of scan 10, later scan 13), not worker start. Event scans (pod watcher) run and do not
  move it.
- Scan #13 (manual, force, 17:23:50-17:41:00 UTC, 17m10s: scan stage 13m57s, privileged stage
  3m13s): 80 images, 80 scored, 0 failed; trivy/grype/Clair 80/80 each. Split hand-off seen in the
  logs: worker `status=scanned` -> worker-privileged `scan.finalize`, provenance, `done`, controls
  run, 6 reports auto-queued. Cluster 30.4 F (vulnerability 8.1, configuration 76.2, supply chain
  43.0 F); 781 C / 6,915 H / 12,411 M / 3,550 L; checks 1,248 pass / 468 fail. KEV exposure: 10
  findings, 7 CVEs, all past due (catalog 2026.10.02). `mirrorDigestVerified` 54/80: 13 Docker Hub
  images hit 429 during the forced re-mirror (cached single-platform copies no longer match the
  index digest, the re-copy is rate-limited, scanned from the original ref), 9 `localhost:32000`
  images are scanned in place (flag false by definition), 4 are mirrored by digest but have no
  image digest recorded (flag false). Provenance: 13 signed, 5 verified, 3 SBOM, 28 provenance,
  23 registry errors (Docker Hub 429; scan 11 an hour earlier had 19/10/36/0).
- Storage: raw JSON gzip for all 240 image_scans rows (trivy 10 MB gz / 132 MB raw, grype 6.9 / 119,
  Clair 4.2 / 25); the dask-kubernetes-operator image's trivy (43 MB) and grype (59 MB) outputs
  exceed `RAW_MAX_GZ_BYTES` and are stored as valid `{"truncated": true, ...}` summaries.
  `vuln_rollup` 7,984 rows. `/vulnerabilities` page 1: 63-79 ms, 25 KB; `?kev=true` 7 CVEs.
  `/images/28` (10,466 findings) page 1 257 ms / 46 KB, page 2 149 ms.
- Control evidence (MODERATE, run 14, 39 assertions: 17 pass / 21 fail / 1 unknown
  `k8s-api-audit-logging`): 287 controls = 2 passing (AC-6(5), RA-5(2)), 5 hybrid, 8 partial,
  32 failing, 0 inherited, 5 org-provided-unverified (PE), 0 not-applicable, 235 not assessed
  (catalog view 288: + AC-6(8) failing). CONTROLS.md's re-derived prediction was 2/5/8/31/5/236/0;
  the extra failing control has no per-control list to diff against; 5 baseline controls fail on
  scan posture-check evidence alone (AC-4, CM-2, SC-5, SC-39, SI-7). CRM 287 rows (org 199,
  customer 46, shared 38, provider 4). `/compliance/stig`: 92 Kubernetes STIG rows, no SRG rows,
  90 Not_Reviewed / 2 Open; V-242383 Not_Reviewed; V-233234 (SRG) Not_Reviewed in a checklist
  generated with `includeSrg`.
- Reports (report-worker pod, one at a time, `report.processed` logged): POA&M xlsx 10 s, STIG
  cklb 8 s, SAR pdf 122 s, OSCAL AR 18 s (26 MB), SSP 9 s, OSCAL POA&M 9 s, CRM 8 s. OSCAL AR,
  POA&M and SSP validate against the 1.1.2 schemas in the test fixtures with 0 errors; SSP
  `import-profile` = NIST MODERATE profile, 11 `set-parameters`; POA&M xlsx 101 items (66 SI-2
  vulnerability groups, 21 control-assertion, 14 posture-check), was 24k-row scale before.
  Retention was not exercised (max 15 per type, 1.0 GB total, below 20 / 2 GiB): no pruning log.
- Monitoring: Prometheus scrapes api (:8000) and the three worker pods (:9000), all `up=1`;
  `posture_scan_images` 80/80/0 after 5ba5d13; PrometheusRule loaded (5 rules, health ok);
  `PostureReportFailed` fires on 9 failed reports from 00:33-00:48 (pre-hardening OOM/restart
  orphans), clears 24 h later.
- Backup: CronJob present; two manual runs wrote 87 MB / 112 MB dumps; the 03:17 schedule not yet observed.
- Known issues / not verified: Docker Hub 429 (needs `registryAuth.existingSecret`); retention
  pruning; scheduled-scan execution under the new scheduler (next due 23:23:50 UTC); reports
  requested while an event scan is newest are stamped with that scan id (#15), not the last full
  scan; event scans re-run provenance for all images (~3 min); the UI has no CRM tab (report
  only); Keycloak view-only client (M4) not set up, grace uses the master super-admin;
  Grafana Infinity datasource not yet given the bearer token.
- Grace hazard: creating or removing a docker network adds/removes a host IP; MicroK8s
  `apiserver-kicker` then regenerates certs and restarts kubelite and containerd, killing every
  pod for ~40 s (2026-10-03 00:45). Use `--network host`; leave `sp-shots` alone.
- Capacity: node memory requests ~99% allocated; root filesystem 29 GB free (93%) after pruning
  superseded local images.

## Grace deployment status (2026-10-03, phase 2; superseded by the section above)

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

## 2026-10-03: chart, RBAC and operations (architecture B1, B2, B4, M1, M2, M5, M6, M9, m2-m5; security C1/H2 chart side)

- **ServiceAccounts per privilege level.** `<fullname>-api` (api, ui, report-worker; no RBAC, no
  token), `<fullname>-scanner` (scan worker; reader ClusterRole, no Secrets), `<fullname>-controls`
  (privileged worker; controls ClusterRole, the Keycloak admin Secret Role unless
  `controlsEngine.keycloak.viewClient.clientId` is set, and the all-Secrets ClusterRole only with
  `provenance.helmReleases.enabled` **and** `iUnderstandClusterSecretsRead: true`, else the render
  fails). `serviceAccount.name` is replaced by `serviceAccount.names.{api,scanner,controls}` (the
  render fails with a pointer when the old key is set).
- **Worker stages.** `python -m posture.worker --stages ...` (`WORKER_STAGES`; default all).
  `worker.splitPrivileged: true` renders `<fullname>-worker` (`inventory,scan`) and
  `<fullname>-worker-privileged` (`provenance,controls,reports`). Hand-off through the scan row:
  the scan worker stores the inventory as a `scan_snapshots` row `level=inventory` and sets
  `status=scanned` (finished_at stays empty); the privileged worker claims `scanned` with SKIP
  LOCKED (`finalizing`), runs provenance (after scanning now, no longer concurrently), writes the
  posture snapshot, deletes the hand-off row, sets `done`, then runs controls and queues reports.
  Restart recovery is per role: `running` -> failed (scan side); `finalizing` -> `scanned` again,
  or `done` if the cluster snapshot was already written. The API treats `scanned`/`finalizing` as
  in flight (409 on a second full scan, cancellable) and shows them as `status: running` with
  `phase: <raw status>` (the UI is unchanged). Heartbeat rows: id 1 scan side, id 2 privileged.
- **Scheduler from the DB (B2).** No APScheduler interval job for scans. Every loop computes
  `next_scheduled_scan()`: `scan_interval_hours` after `max(started_at)` of `done` full scans;
  immediately when none ever finished (`SCAN_ON_START=false`: one interval after worker start); a
  newer failed/cancelled full scan pushes the next attempt to `min(interval, 1h)` after it, so a
  failing scan retries hourly instead of every poll. APScheduler still drives the grype DB update
  and scanner status refresh on the scan side only.
- **Secrets without `lookup` (B1).** Hook Job `<fullname>-ensure-secrets` (pre-install,pre-upgrade,
  weight -5; Argo CD PreSync) runs `python -m posture.bootstrap ensure-secret` from the **api
  image**: create `<fullname>-db` / `<fullname>-compat-token` with random alphanumerics only when
  missing, add missing keys, never rewrite values, and annotate `helm.sh/resource-policy: keep` +
  `argocd.argoproj.io/sync-options: Prune=false` (also patched onto the Secret older charts created,
  which Argo CD would otherwise prune once the chart stops rendering it). Deviation from "kubectl
  image pinned by digest": `registry.k8s.io/kubectl` has no shell, so "create if missing" cannot
  be scripted with it; the api image already carries the kubernetes client and is the image the
  release runs anyway. The hook SA/Role/RoleBinding (weight -10) use `before-hook-creation` only, so
  they exist for the whole hook phase under both Helm and Argo CD; the Role allows `create` on
  Secrets (cannot be name-scoped) and `get/patch` on the two names. `postgresql.existingSecret`
  remains the GitOps recommendation.
- **Migrations (m2).** `alembic/env.py` holds `pg_advisory_lock(724100)` for the upgrade. Hook Job
  `<fullname>-migrate` (pre-upgrade, weight 0) runs `posture.migrate --if-reachable 120`, which
  exits 0 without migrating when the DB is unreachable: Argo CD maps pre-upgrade to PreSync, which
  also runs on the first sync before the bundled Postgres exists. The api `migrate` init container
  stays as the first-install path (a no-op afterwards). `tests/test_migrations.py`: `alembic check`
  against the test DB, three racing `posture.migrate` processes, and a static check that every
  `models.py` with tables is imported by env.py (the provenance models were missing).
- **report-worker.** With `reportWorker.enabled` (default) the chart deploys
  `<fullname>-report-worker` (api image, no token, reports PVC, required podAffinity to the api
  because the PVC is RWO) and sets `REPORT_WORKER_EMBEDDED=false` on the workers; the privileged
  worker then mounts no reports volume and has no affinity. The api still serves downloads from
  the reports PVC, so it keeps `strategy: Recreate` (RollingUpdate needs reports in the DB or object
  storage).
- **Sizing (M1) and Clair (M5).** Defaults from the architecture review §2 table; privileged worker
  100m/384Mi -> 1/1.5Gi; report-worker 100m/512Mi -> 1/3Gi. Clair is off by default; when on it gets
  its own `<fullname>-clair-postgres` StatefulSet (15Gi, `clair.postgres.dedicated`; `false` keeps
  the old shared layout). PVC defaults shrink (worker 15Gi, trivy 3Gi): PVCs cannot shrink, so
  existing installs must pin their installed sizes (grace does).
- **Postgres (M6).** `postgresql.config` -> ConfigMap `<name>-config` -> `-c key=value` via a small
  sh wrapper around `docker-entrypoint.sh` (checksum rolls the pod), `/dev/shm` 256Mi emptyDir.
  Backup CronJob `<fullname>-backup` (default on, 03:17 daily, `pg_dump -Fc --no-owner` of the
  posture DB to PVC `<fullname>-backup` 5Gi with resource-policy keep, newest 7 kept; Clair's DB
  is not backed up).
- **Images (m5).** postgres `16.15-alpine`, trivy `0.75.0`, clair `4.9.0` pinned by index digest
  (resolved with `docker buildx imagetools inspect`; `skopeo inspect` / `crane digest` give the
  same). `nebari-app` dependency pinned to `0.1.1`. `values.schema.json` (types, enums, digest
  pattern, `additionalProperties: false` on chart-owned objects, so typos fail the render).
- **extraCACerts in the api (m4)**: same ca-bundle init container as the workers.
- **Compat listener (H2 chart side).** Token Secret mounted at `PROVENANCE_COMPAT_TOKEN_FILE`
  (`/etc/posture/compat/token`); `tokenSecret` names an existing one. NetworkPolicy peer is
  `allowedNamespaces` AND `grafanaPodSelector` (default `app.kubernetes.io/name: grafana`, which
  matches both Grafanas on grace). Render fails with `networkPolicy.enabled=false` unless
  `allowAnonymousNetwork: true`.
- **Worker egress (M8/H3 chart side).** `networkPolicy.workerEgress` (default on) selects both
  workers: DNS (53 any), release pods, `allowedNamespaces` (keycloak, monitoring, observability,
  container-registry), TCP `ports` [443, 80, 6443] to 0.0.0.0/0 except 169.254.0.0/16, an external
  DB port when `postgresql.enabled=false`, plus `extraRules`. The API server port must be listed
  when it is not 443/6443 (MicroK8s 16443: grace adds it, and 8443 for the tailscale endpoint).
- **Env wired by the chart:** `WORKER_STAGES` (as `--stages`), `OIDC_CLIENT_IDS`
  (`auth.clientIds`, else `<namespace>-<fullname>` with nebariapp), `OIDC_AUDIENCES`,
  `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET_FILE`, `KEYCLOAK_ALLOW_MASTER_FALLBACK`,
  `PROVENANCE_COMPAT_TOKEN_FILE`, `PROVENANCE_TRUST_SETTINGS_LOCKED` (default true),
  `GRYPE_MAX_CONCURRENT`, `SCAN_MAX_IMAGE_GB`, `REPORT_WORKER_EMBEDDED`, `REPORT_TIMEOUT_SECONDS`,
  `REPORT_WORKER_ISOLATION`, `REPORTS_RETENTION_PER_TYPE` (20), `REPORTS_RETENTION_MAX_TOTAL_BYTES`
  (`2Gi`; config accepts quantities), `HISTORY_RETAIN_SCANS` (30). `auth.issuers` defaults to the
  in-cluster issuer (the API refuses an empty list); `auth.mode=disabled` fails the render because
  the chart never sets `POSTURE_DEV`.
- **Wired ahead of the code (architecture M7/m11, in progress):** `MIRROR_MODE`
  (`scanner.mirror.mode`, "" = `registry` with Clair, else `local`), `IMAGE_CACHE_MAX_BYTES`
  (`scanner.mirror.imageCacheMaxBytes` 8Gi, below the 15Gi worker PVC; the code default of 20 GiB
  would not fit), `EVENT_SCANS_ENABLED` / `EVENT_SCAN_DEBOUNCE_SECONDS` (`scanner.events`), scan
  worker only. The reader ClusterRole already has `watch` on pods.
- **grace values:** split workers, report-worker 4Gi, Clair on (8Gi) with
  `clair.postgres.dedicated: false` (no re-ingest of its 8 GB DB), main Postgres 2 CPU / 2Gi with
  512MB shared_buffers, PVC sizes kept, `iUnderstandClusterSecretsRead: true`, requests kept small
  (node ~99% allocated). Not deployed yet. After the deploy, Grafana's Infinity datasource needs the
  bearer token header (`deploy.sh` prints the command).
- 2026-10-03 (architecture review fixes, api/worker side; details in docs/OPERATIONS.md):
  - **Reports (M3):** the api and the workers only queue `reports` rows; `posture.report_worker`
    claims them (SKIP LOCKED, lease + heartbeat, expired leases requeued, failed after
    `REPORT_MAX_ATTEMPTS`), one at a time, each in a child process with a minimal env and
    `REPORT_TIMEOUT_SECONDS` (20 min). `REPORT_WORKER_EMBEDDED` (default true) runs the same loop in
    the worker with the `reports` stage when no report-worker Deployment exists. Retention after
    every report: `REPORTS_RETENTION_PER_TYPE` (20, old `REPORTS_KEEP_PER_TYPE` still honoured) and
    `REPORTS_RETENTION_MAX_TOTAL_BYTES` / `REPORTS_MAX_TOTAL_BYTES` (2 GiB), each deletion logged.
  - **History (M6):** `HISTORY_RETAIN_SCANS` (30) prunes image_scans (raw JSON), scan_snapshots
    and compat_reports of older finished scans; the newest done scan and every image_scans row the
    current findings reference stay. Raw scanner JSON is stored gzip'd and never cut: past
    `RAW_MAX_GZ_BYTES` (4 MiB compressed) the row holds a `{"truncated": true, ...}` summary.
  - **List endpoints (M4):** per-scan `vuln_rollup` (pg_trgm index for `q`) serves
    `/vulnerabilities` with SQL filter/sort/offset or keyset (`cursor` / `nextCursor`);
    `/images/{id}` paginates findings in SQL; `/compliance/stig` reads posture_results and fixable
    findings directly; `/summary` reads counts / fixable / topRisks from the cluster snapshot.
    Measured on 500 synthetic images (172k findings, `api/tests/perf`): `/vulnerabilities` 63.9 s /
    1 GiB -> 31 ms / 0.8 MiB; `/images/{id}` (840 findings) 136 ms / 437 KiB -> 29 ms / 28 KiB per page.
  - **UI follow-up (findings paging):** `/images/{id}` without `page` still returns findings, capped
    at the first 500 (severity order) with `truncated: true` and `findingsTotal`, so the current UI
    keeps working but silently misses findings past 500 on huge images. The UI should switch the
    findings tab to server paging: `page`, `pageSize`, `severity`, `q`, `fixable`, `disagree`,
    `sort` (severity|cvss|vulnId|package|agreement|firstSeenAt), `order`, and take the summary line
    ("N flagged by all scanners") from `findingsSummary.flaggedByAll` instead of computing it over
    the loaded rows. `/vulnerabilities` items gained `kev` (always false until a KEV feed exists)
    and `firstSeenAt`; the UI can use `nextCursor` for "load more".
  - **Scan memory (M2):** `GRYPE_MAX_CONCURRENT` (2) caps grype processes independently of
    `parallelism`; grype/trivy JSON is streamed from the output file with ijson; images larger than
    `SCAN_MAX_IMAGE_GB` (20, manifest size probed once per digest into `images.size_bytes`) are
    scanned last, one at a time.
  - **Follow-up, not implemented: SBOM once, re-match daily.** The structural fix for 2,000 images:
    on a new digest, generate an SBOM once (syft / `trivy image --format cyclonedx`) and keep it
    (compressed, per digest, on the cache volume or in Postgres); daily rescans become
    `grype sbom:<file>` / `trivy sbom <file>` re-matches against the current DBs (~300 MB and a
    few seconds each instead of a full layer pull and unpack). Triggers: new digest (pod watcher),
    vuln-DB update (scanner DB timestamp changed), plus the daily full sweep. Cost: both scanners
    then share one cataloguer's package list, which lowers the independence the agreement score
    assumes; SCORING.md must say so, and Clair (indexes layers itself) stays independent.
  - **Mirror (M7):** `MIRROR_MODE` = `registry` (copy into MIRROR_REGISTRY, needed by Clair;
    grace) | `local` (default; per-digest OCI layout under `CACHE_DIR/images`, verified against the
    source digest like the registry mirror, scanned in place by trivy `--input` and grype
    `oci-dir:`, LRU by `IMAGE_CACHE_MAX_BYTES`) | `off`. Clair is skipped (logged) unless
    `registry`.
  - **m7/m9/m11:** grype DB updates and scans exclude each other; `images` rows are only written
    when a value changes (`last_seen_at` hourly); the scan worker's pod watcher
    (`EVENT_SCANS_ENABLED`, `EVENT_SCAN_DEBOUNCE_SECONDS` 60) queues one namespace-targeted
    `trigger=event` scan for new digests; such scans neither reset the schedule nor auto-generate
    reports.
  - **Compat (§1):** the worker renders the provenance-collector report once per scan into
    `compat_reports`; the compat routes serve the stored bytes.
  - **Metrics (M9):** `/metrics` on api :8000 (no auth; not proxied by the UI, NetworkPolicy only)
    and on the workers / report-worker :9000. Alert examples and the runbook: docs/OPERATIONS.md.
  - **Chart (done after 136e9a4; was "needs chart"):** values `monitoring.*` (the
    architecture note proposed `metrics.*`; one block for monitors, rule and network peer is
    simpler):
    - `monitoring.enabled` (default false, true on grace) renders a `ServiceMonitor` for the api
      Service port `http` (:8000) `/metrics` and a `PodMonitor` for `worker`,
      `worker-privileged`, `report-worker` on the named container port `metrics` (9000,
      `/metrics`; the probes use the same port, renamed from `health`). Both in the release
      namespace with `monitoring.labels` (grace: `release: kube-prom-stack`, whose Prometheus in
      `observability` has `release`-label selectors and empty namespace selectors).
    - `monitoring.rules.enabled`: `PrometheusRule` with the five alerts of docs/OPERATIONS.md,
      `runbook_url` = `monitoring.rules.runbookBaseUrl` (default: Chart.yaml `home` +
      `/blob/master/docs/OPERATIONS.md`) + anchor.
    - NetworkPolicy: the api admits `monitoring.namespace` (optionally narrowed by
      `monitoring.podSelector`) on :8000; a new `<fullname>-workers-ingress` policy selects
      worker, worker-privileged and report-worker and admits only that peer on :9000, or nothing
      when monitoring is off (they served unauthenticated `/metrics` to any pod before).
    - Probes on `:9000/healthz` were already rendered for all three (shared worker template,
      report-worker.yaml); unchanged apart from the port name.
    - Optional env: `scanner.rawMaxGzBytes` -> `RAW_MAX_GZ_BYTES` (scan worker),
      `reports.leaseSeconds` / `reports.maxAttempts` -> `REPORT_LEASE_SECONDS` /
      `REPORT_MAX_ATTEMPTS` (report-worker, or the worker with the embedded reports stage); null =
      application defaults (4Mi, 120, 2). Already wired: GRYPE_MAX_CONCURRENT, SCAN_MAX_IMAGE_GB,
      MIRROR_MODE, IMAGE_CACHE_MAX_BYTES, EVENT_SCANS_*, REPORT_WORKER_EMBEDDED / ISOLATION /
      TIMEOUT, REPORTS_RETENTION_*, HISTORY_RETAIN_SCANS.

## 2026-10-03: scoring edge cases and Windows pods (quality m5, B2)

**Scoring edge cases (quality m5), for the scoring/compliance owner.** `api/tests/test_q_scoring_edges.py`
records each case. Strict `xfail` tests describe the recommended behaviour: when it lands, the
test XPASSes, CI fails on the strict marker, and the marker has to be removed.

| Case | Today | Recommendation | Test |
|---|---|---|---|
| GHSA vs CVE alias for the same issue | Two findings, each at 1/3 agreement (with 3 scanners succeeded). This lowers the agreement multiplier and double-counts the penalty. | Carry aliases on `Finding` (trivy `VendorIDs`, grype `relatedVulnerabilities`) and key on the CVE when one exists. | xfail |
| GHSA id case | `GHSA-abcd-…` is upper-cased to `GHSA-ABCD-…`. Merging still works, but the id no longer matches GitHub's canonical form (`GHSA-` plus lowercase segments). | Canonicalise to `GHSA-` plus lowercase segments. | xfail |
| A scanner not in `succeeded` reports a finding | It still counts toward agreement. For example, trivy and clair report it with succeeded = {trivy, grype}, which gives 1.0. | Count only scanners in `succeeded` (and keep the stray result out of `per_scanner`). | xfail |
| `finding_penalty` receives a non-normalized severity (`"CRITICAL"`) | It is treated as `unknown` (0.05 instead of 10.0). Harmless today because every parser calls `normalize_severity`. | Normalize inside `finding_penalty`, or raise. | xfail |
| Debian `unimportant` | Maps to `unknown`. | Map to `negligible`. | xfail |
| `normalize_package("a_")` vs `"a"` | `"a-"` ≠ `"a"`. | Keep as is: this is PEP 503 normalization, and PEP 508 names cannot end with a separator. | pinned |

**Windows pods (quality B2).** The inventory adapter now records `pod.os` (from `spec.os.name`, falling
back to the `kubernetes.io/os` nodeSelector) and the effective `windowsOptions.hostProcess`.
- On Windows pods, five checks are n/a (not fail): `privilege-escalation`, `added-capabilities`, `capabilities-not-dropped`, `writable-rootfs` and `seccomp-unconfined`. The kubelet ignores these Linux-only fields, or the API rejects them.
- `run-as-root` fails only for an explicit `runAsUserName: ContainerAdministrator`. It is n/a when the image default user applies, because `runAsUser` does not exist on Windows.
- `privileged` fails on `hostProcess: true`, which is the Windows equivalent of privileged.
- SCORING.md's check table still describes Linux semantics only. Add a Windows column when the doc is next revised.

## 2026-10-05: scan accounting, post-scan stage scoping, event-scan hygiene

Observed on grace over 48 h: scheduled scans (every 6 h, `rescanAfterHours` 24) rescanned only
stale images, so the scan row read `images_total: 0` (scans 20, 21, 24) or `1` (25) with ~80
images deployed; every scan, including each event scan, still re-ran the provenance stage over
all ~85 images (3 min), a full controls-engine run and 6 auto-reports (scans 30-33: four times
in 7 min); event scans fired for CronJob pods (`bitnami/postgresql:latest` backups) and
short-lived verify pods.

- **Scan accounting** (migration `0006_scan_accounting`): `scans.images_inventoried`,
  `images_rescanned`, `images_skipped_fresh`, `images_targeted` (nullable; null = older row),
  exposed as `imagesInventoried` / `imagesRescanned` / `imagesSkippedFresh` / `imagesTargeted`
  on `/scans` and `/scans/{id}`. `images_total` keeps its meaning (images the scan attempted;
  `progress` denominator). The snapshot already covered the whole inventory (`_persist_snapshot`
  aggregates every image of `key_to_id`, rescanned or not); a regression test now pins it
  (`test_scan_accounting.py`). UI: "68 rescanned · 12 fresh · 80 in inventory"; event scans
  "3 targeted · 1 rescanned · 2 fresh" (`ui/src/lib/scan-counts.ts`).
- **Hashes on the scan row**: `inventory_hash` = sha256 of the sorted unique image keys;
  `posture_hash` = sha256 of (namespace, workload kind, workload name, container, container
  type, security context) per container. Pod names, replica counts and image digests are left
  out, so restarts and image rollouts keep the posture hash.
- **Provenance scoping**: the stage registry-checks only the images (re)scanned by this scan,
  plus images without a reusable previous result (never checked, last check errored, check
  configuration changed). A forced full scan (`force` and no targets) checks everything. Every
  other inventory image is *carried*: its previous `image_provenance` row is copied into the
  scan (`details.carried`, `details.carriedFromScan`) without a registry call, so
  `/supply-chain`, the compat report and the supply-chain score still cover the whole inventory
  and the 10-scan row retention never drops a long-fresh image. Trade-off: per-tag update checks
  (new upstream tags) refresh when the image is rescanned, i.e. once per `rescanAfterHours`,
  instead of on every scan. Helm release discovery still runs every scan (one Secrets list).
  Split workers carry the scope in the inventory hand-off (`provenanceScope`); a hand-off from an
  older scan worker without it means "check all".
- **Controls engine** after a done scan: always after a full (untargeted) scan; after a
  targeted / event scan only when `posture_hash` differs from the previous done scan's (or
  either is unknown). Otherwise it is skipped with a log line (`controls.skipped`, and in the
  scan log). On-demand runs (`POST /compliance/assertions/run`) are unchanged.
- **Auto-reports** (`reports.autoGenerate`): never after targeted / event scans; after a full
  scan only when it rescanned at least one image or its `inventory_hash` differs from the
  previous done full scan's. Skips are logged (`reports.auto_skipped`, scan log).
- **Metrics**: `posture_scan_image_selection_total{trigger,result=rescanned|skipped_fresh}`,
  `posture_provenance_images_total{result=checked|carried}`,
  `posture_post_scan_stage_total{stage=controls|reports,action=run|skipped}`, and
  `posture_scan_images{status=inventoried|rescanned|skipped_fresh}` for the latest full scan.
- **Event-scan hygiene** (chart `scanner.events.*`):
  - `includeJobs` / `EVENT_SCANS_INCLUDE_JOBS` (false): pods with a Job / CronJob owner are
    ignored. The scheduled scan still covers their images.
  - `minPodAgeSeconds` / `EVENT_SCANS_MIN_POD_AGE_SECONDS` (120): a younger pod is held until it
    reaches that age (from `creationTimestamp`) and dropped on its DELETED event. Pods that
    already terminated (Succeeded / Failed) are ignored. Pods without a timestamp count as old.
  - `debounceSeconds` / `EVENT_SCANS_DEBOUNCE_SECONDS` (300, was 60): at most one event scan per
    interval across namespaces. The chart value now maps to this variable. The old
    `EVENT_SCAN_DEBOUNCE_SECONDS` (60) stays as the collection window after the first new
    digest and is no longer set by the chart.
  - No event scan while a full scan is in flight: a queued full scan absorbs the new digests
    (its inventory sees them; nothing is queued). With a running full scan the digests wait,
    re-checked every 30 s; once it finished, digests it scanned are dropped and the rest go into
    one event scan. ("Merging" into a running full scan is not possible after its inventory
    was taken.)
- **Expected effect on grace** (4 scheduled scans/day, K event scans/day before the change):
  - Provenance registry passes: before, 4 + K full passes/day (~85 images, ~3 min each). After,
    each image is re-checked about once per day, when it goes stale (~85 checks/day in total,
    plus new digests); scans with nothing rescanned finish the stage in seconds.
  - Auto-reports: before, 6 per scan (24/day from scheduled scans alone, plus the burst seen
    with scans 30-33). After, 6 only for scheduled scans that rescanned something or saw a
    different image set. On the observed pattern (3 of 4 scheduled scans rescanned 0), that is
    roughly 6-12 per day.
  - Controls engine: before, 4 + K runs/day. After, 4 plus the event scans that add a workload or
    change a securityContext.
  - Event scans: CronJob pods and verify pods no longer trigger them, and bursts collapse into one
    per 5 min, so K should drop to a handful a day, around deployments.


## 2026-10-05: UI provenance-only mode (replacing provenance-collector-pack's `frontend/`)

- **One bundle, two backends.** The SPA probes `GET {apiBase}/summary` at startup. Any 2xx, 401,
  403 or 5xx means `posture` mode. A 404, an HTML 200 or a network error means `provenance` mode:
  only provenance-collector-pack's Go dashboard is behind `/api/` (`/api/reports*`, `/api/me`,
  `/api/scan`, `/api/export`).
  - 5xx counts as posture so that an unhealthy posture API still shows its error states.
  - The cost is that a gateway 502 at page load against the Go dashboard would pick posture. A
    deployment that knows its backend sets `"mode"` in `/config.json` to skip the probe.
  - `useCapabilities()` gates the sidebar and routes; hidden routes redirect to `/`.
  - In provenance mode Overview, Scans and Reports render separate pages
    (`ui/src/pages/provenance/`). Images, image detail and Supply chain are the existing pages,
    fed by an adapter.
- **Adapter, not a second UI.** `ui/src/api/provenance-adapter.ts` maps report schema 1.x onto
  the existing `ImageSummary.provenance`, `SupplyChainSummary`, `HelmRelease[]`, `Namespace[]`
  and `ImageDetail` shapes. `api.images`, `api.image`, `api.namespaces`, `api.supplyChain`,
  `api.helmReleases` and `api.me` in `client.ts` switch to it in provenance mode, so the existing
  pages need only small changes: column and tab gating, and wording.
  - Images are keyed by reference, the collector's `uniqueImages` key.
  - Counts are recomputed per unique image; the collector counts signed, SBOM and so on per
    container record.
  - The score comes from `lib/supply-chain.ts`, and the cluster value is the mean of the image
    scores weighted by container count.
- **"Not found" vs "not checked".** The report omits `sbom`, `provenance` and `update` in both
  cases. The adapter treats a check as enabled if any record in that report has the object. It
  then reads a missing object on an image with a resolved digest as a negative. Images with no
  digest never reached the registry checks and stay "not checked", with no score deduction.
- **History.** "View" on a `/api/reports` row switches the active dataset, a module store
  (`setDataset`), and invalidates every query except the list. Timestamped reports are cached for
  the session; `latest` is cached for 15 s.
- **Scans without a status endpoint.** The dashboard only has `POST /api/scan`, and `GET` returns
  405. After a successful POST, the UI shows the job name and namespace, then polls
  `/api/reports` every 5 s for up to 5 min. A report newer than the one present at request time
  completes the job and becomes the active dataset. This is the same approach as the old
  frontend's `useRunScan`. Pod status and logs are not available.
  - In provenance mode a 403 is not a global "admins only" lock: reads are open to any
    authenticated user, and only Run scan is gated, on `canRunScan`. The UI shows a toast instead.
- **Auth plug.** `client.ts` stays the single fetch layer. It takes headers from an
  `AuthStrategy` (`ui/src/auth/strategy.ts`).
  - Posture mode uses gateway cookies and `/logout`.
  - Provenance mode with a `keycloak` block uses keycloak-js 26 with `login-required`, PKCE S256
    and no session iframe, matching the old `frontend/src/auth/keycloak.ts`. The token is
    refreshed when less than 30 s remain. After a 401 the client forces a refresh and retries
    once. Sign out calls Keycloak logout.
  - Provenance mode without a `keycloak` block sends no auth header (dashboard OIDC disabled).
  - The PKCE test runs the real keycloak-js against a fake Keycloak realm in MSW. The fake
    realm checks `SHA-256(code_verifier)` against the challenge from the authorize URL and checks
    the nonce.
- **Config.** `/config.json` accepts both packs' keys: `apiBase`, `title`, `mode`,
  `provenanceApiBase` (default `/api`), and `keycloak.{url,realm,clientId}`. The branding keys
  `logoUrl`, `logoUrlDark`, `faviconUrl` and `theme` are ignored. The baked `config.json` no
  longer pins `title`; the default title depends on the mode.
- **nginx.** No change was needed. The variable `proxy_pass` under `location /api/` already
  forwards the URI and all headers unchanged, including Authorization and Sec-Fetch-Site, and
  `/healthz` stays local. This was verified against `go run ./cmd/dashboard`.
  provenance-collector-pack's chart mounts its own `nginx.conf` and `config.json` over the image's
  copies, which also works.
- **Mock / e2e.** `VITE_API_MOCK=provenance` serves an MSW copy of the Go dashboard built from
  the vendored golden report and schema (`ui/src/mocks/fixtures/`).
  - `build:mock-preview` now also builds `dist-mock-provenance`, so the CI e2e job runs the new
    `playwright/provenance.spec.ts`, a second Playwright project on `PORT+1`, without a workflow
    change.

## 2026-10-05: UI for the SCAP scanner (DESIGN §14)

- **Where.** Image detail gets a **STIG** tab (posture mode only; a `?tab=stig` deep link falls
  back in provenance mode). Compliance → STIG shows "Kubernetes STIG" (unchanged) above a new
  "Product STIGs" rollup (`#product-stigs`), each row linking to the new route
  `/stig/benchmarks/:id` (gated on the `compliance` feature, so provenance mode redirects).
  The Overview gets a Product STIGs tile (from `summary.stig`, hidden when absent) and an
  OpenSCAP scanner card. The Images table gets a sortable STIG column plus a STIG filter, shown
  only when the API serves `stig` on images. Settings gets a SCAP card, shown only when the API
  returns `scap` or `scanners.scap`.
- **Shapes read** (aligned with `api/src/posture/routers/stig.py`, 5aed1b8). Everything goes
  through `ui/src/api/normalize.ts`, so missing or malformed fields degrade to empty states:
  - `GET /compliance/stig` is `{items, product: {benchmarks[], ...summary}}`. The pre-§14 bare
    list, `{kubernetes, product[]}` and `product: {items}` are also accepted. When `product` is
    missing, the rollup falls back to `GET /stig/benchmarks`. Rows with `id: null` (content that
    applies to no image) are not listed.
  - `GET /images/{id}/stig`: the image-level `status` (`evaluated | notApplicable | noContent |
    error | timeout | notEvaluated`) picks the empty state when `benchmarks` is empty. Rootfs
    fidelity comes from `benchmarks[].summary.rootfsFidelity`, then `rootfs.fidelity`. Warnings
    come from `rootfs.notes` and the `droppedXattrs` / `skippedDevices` / `unsafeEntries`
    counts. The tab shows sub-tabs from `benchmarks[]` and never sends `?benchmark=`, because
    the API would then drop the other benchmarks. `page/pageSize/result/severity/q` apply to
    every benchmark alike.
  - `GET /stig/benchmarks/{id}/rules` is `{benchmark, items, total}`. The page fetches every
    rule, in pages of 500 (up to 10 pages), and filters client-side (search, CAT, failing only).
    It lists the images behind a rule from `failing[]`; the API caps that list at 50, and the UI
    says so when there are more.
  - `GET /scanners`: the `scap` entry's `content[]` (title/file, version, source, sourceName,
    fetchedAt) is shown as content versions. The summary doesn't list `scap`, so the Overview
    adds the `scap` card from `/scanners` when it is enabled.
  - `summary.stig.coverage` is read as a percentage, or as a fraction when it is 1 or less.
- **Field names assumed beyond §14** (all optional; none is required to render):
  `ImageSummary.stig.{status, fidelity, error}` (served), `ImageStigSummary.cat{1,2,3}Open`
  (served; when absent the chips are counted from the rules, but only if the whole benchmark
  fits on one page), `StigBenchmark.cat{1,2,3}Open` (served), and `StigBenchmarkRule.title`
  (served), `.cci` and `.fixText` (not served; used when present). Also `images[]` / `passing[]`
  and arrays in `failingImages` / `passingImages` (not served; accepted). `ScapContentSource
  .version/.fetchedAt` are not served; versions are matched from the scanner `content[]` by
  `sourceName` (or file name), and a source with several datastreams lists each version.
  Open CAT counts are failing (image, rule) pairs, the same as the API's `cat1Open`.
- **API gap (for the backend).** `GET /images` ignores the UI's `sort=stig` (it falls back to
  the score sort) and the `stig=evaluated|na|cat1` filter. The column and filter render, and the
  MSW mock implements both, but against the real API they have no effect until `SORT_KEYS`
  gains `stig` (by `stig.score`, n/a last) and `filter_images` gains `stig`.
- **Bug fix on the way.** `normalize.imageSummary` turned the posture API's integer image ids into
  `''` (the defensive `str()` accepted strings only), which broke image links against the real
  API. Ids now go through `idStr()`, which keeps numbers as strings.
- **Mock.** `ui/src/mocks/scap.ts` has its own seeded PRNG, so the existing fixtures are
  unchanged. It has three benchmarks of 30 rules each: RHEL 9 (DISA V2R5), Ubuntu 22.04 (SSG
  0.1.76) and PostgreSQL 15 (DISA V1R2). Eight images have results: `security-posture-api`
  has two benchmarks, and calico/node has a degraded rootfs. The other 19 images are n/a.
  `/stig/benchmarks` also lists one content-only entry with `id: null`.

## 2026-10-05: provenance stage, chart update check cached and carried

Grace (see "Grace deployment status (2026-10-05, scan accounting)") spent 51-193 s in the
provenance stage while checking 1-4 images. Every scan built a fresh `ChartRepos`, so it downloaded
and parsed every configured `index.yaml` again. prometheus-community's index is 6.5 MB and grafana's
4 MB. The pure-Python PyYAML loader takes ~18 s for the prometheus index alone on a desktop CPU, on
the event loop. Charts that no repo publishes then fell through to the `oci://docker.io/envoyproxy`
tag list (Docker Hub, 429).

- **Disk cache** `CACHE_DIR/helm-index/` (`PROVENANCE_HELM_INDEX_TTL_HOURS`, default 12):
  - `index-<h>.json` holds the parsed chart -> versions map of one repo, with its `ETag` /
    `Last-Modified`. Within the TTL it is used without a request. After the TTL it is revalidated
    with `If-None-Match` / `If-Modified-Since` (all six grace repos send an ETag), and a 304 only
    refreshes the timestamp. A failed refresh falls back to the stale copy.
  - `oci-<h>.json` holds an OCI tag list, where an empty list means not found. It uses the same
    TTL. Errors are not cached.
  - TTL 0 disables reuse.
  - The cache is per pod: worker-privileged's `/cache` is an emptyDir, so a rollout starts cold.
  - Parsing uses libyaml (`CSafeLoader`, ~3x faster) in a worker thread, logged as
    `provenance.helm_index_parsed` (bytes, charts, ms).
- **Per-release carry-over** (`checks.json`), the same pattern as the image carry-over:
  - A release whose chart and version are unchanged since its last check, checked less than
    `rescanAfterHours` ago under the same repo list / `skipPrerelease` / `updateLevel` /
    max-major-jump, keeps its stored result (`update`, `chartSource`, `updateCheck`) without any
    request. Repo indexes are only loaded when some release actually needs a lookup.
  - Errors (repo unreachable with nothing cached, OCI 429) are not carried and are retried on
    the next scan.
  - A forced full scan re-checks every release. The index TTL still applies.
  - Trade-off: a new upstream chart version shows up within `rescanAfterHours` (24 h), not on the
    next scan.
- **No Docker Hub fall-through.** An `oci://` entry is either a prefix (`host/path/<chart>`) or the
  chart itself, when its last path segment is the chart name. On Docker Hub (`docker.io`,
  `index.docker.io`, `registry-1.docker.io`, `registry.hub.docker.com`) only the second form is
  used, so a chart that no other source publishes makes no Docker Hub request. Such a chart gets
  `updateCheck: not-configured`.
  - `HelmRelease.update_check` is `checked` | `not-configured` | `error` | `skipped`. It is stored
    in `checks.json` and counted in the scan log line. `helm_releases` has no column for it (no
    migration in this change). The API's `update` / `chartSource` are unchanged.
  - **Grace values need** `oci://docker.io/envoyproxy/gateway-helm` instead of
    `oci://docker.io/envoyproxy`. Otherwise gateway-helm reads "not checked".
- **Timing.** The stage logs `provenance.timing` once per scan, with ms for `load_ms` (previous
  rows), `images_ms` (registry checks), `helm_discovery_ms` (Secrets list + decode),
  `helm_updates_ms`, `carry_ms` and `persist_ms`, plus `collector_ms` (the whole stage). It also
  logs `helm_checked` / `helm_carried` / `helm_notConfigured` / `helm_errors` / `helm_requests`.
  The scan log line gains "chart update checks: N checked, M carried, K not configured, E
  error(s), R request(s)".
- **Expected on grace:**
  - Steady state: `helm_updates_ms` ~0 with 0 requests. `helm_discovery_ms` covers one Secrets list
    (72 Secrets, 15 MB; `kubectl` takes 2.5 s; the Python client probably 3-6 s). `images_ms` is
    1-4 image checks, a few seconds each unless Docker Hub rate-limits.
  - Total: ~5-15 s instead of 51-193 s.
  - Once a day (`rescanAfterHours`) and after a worker-privileged rollout, the releases are
    re-checked. That costs ~6 conditional GETs (304 when unchanged), or a download plus libyaml
    parse of the changed indexes (~10-30 s on grace), but is not repeated on every scan.

## 2026-10-05: SCAP scanner backend (DESIGN §14)

Implemented `api/src/posture/scap/`, the `scap` worker stage, migration `0007_scap`, the STIG
routes, product STIG reports, the worker image changes and the `scap-worker` chart component.
Choices and deviations from §14:

- **Hand-off**: same pattern as provenance. When its CVE stage finishes, the scan worker sets
  `scans.scap_status = queued` with `scap_image_ids` (images rescanned now plus inventory images
  never evaluated; every image on a forced full scan). `python -m posture.worker --stages scap`
  claims it (`FOR UPDATE SKIP LOCKED`, heartbeat row 3) and writes progress to
  `scans.scap_detail`, not the scan log (the scan log belongs to the other workers). The
  privileged worker waits for it before the posture snapshot (`SCAP_FINALIZE_WAIT_SECONDS`, 600);
  it does not wait when no scap-worker heartbeat is younger than 180 s. Otherwise the scan
  finishes with `scapStatus` still queued / running ("scap pending") and the snapshot uses the
  previous STIG results. `--stages all` and `SCAP_EMBEDDED=true` run the stage inline.
- **Capabilities**: `CHOWN, FOWNER, DAC_OVERRIDE, FSETID, SETFCAP, SYS_CHROOT`; not `SETUID` /
  `SETGID`. FSETID keeps setuid/setgid bits through chown/chmod. SETFCAP restores file
  capabilities. SYS_CHROOT is needed by OpenSCAP's rpm probes: on grace they failed on UBI 9 with
  "chroot failed: Operation not permitted". Justification: docs/CONTROLS.md.
- **Content refresh**: the scap-worker owns the content volume and refreshes it itself, not the
  privileged worker. This keeps content egress and the volume in one pod.
- **Image source**: the scap-worker has its own OCI cache (`persistence.scapWork`). With
  `MIRROR_MODE=registry` (grace) it copies the verified mirror digest, so upstream is not pulled
  twice. With `local` mode it pulls the source digest again: the scan worker's RWO cache PVC
  cannot be shared.
- **Statuses**: per image `evaluated | notApplicable | noContent | error | timeout`.
  `noContent` means a benchmark applies but its datastream is missing. It is kept apart from
  `notApplicable` so content gaps are visible. Manual STIGs (no OVAL) evaluate with every rule
  `notchecked`: status `evaluated`, score null.
- **`/compliance/stig`** is now `{items, product}`. `items` holds the Kubernetes rules (the UI
  already accepted `{items}`). `/scanners` lists `scap` after the three vulnerability scanners
  and carries its `content` catalogue. `views.SCANNERS` (consensus, freshness) is unchanged.
- **`/images`**: `sort=stig` and `stig=evaluated|na|cat1` are implemented as the UI entry above
  describes. Exact semantics are in DESIGN §14 ("Implemented shapes"). This closes that entry's
  "API gap".
- **POA&M SLA clock**: `scap_results.first_failed_at` is carried while a rule keeps failing on
  the same image. The column was added to 0007 after that migration had been pushed but before
  it was deployed anywhere.
- **Real-image findings (grace, worker image with openscap 1.3.7)**:
  - Debian's rpm macros put the rpmdb in `~/.rpmdb`. Without `/etc/rpm/macros.posture-oscap`
    (`%_dbpath /var/lib/rpm`), UBI 9 read as "not RHEL" and all 477 rules came back
    notapplicable.
  - Debian container images set `Dir::Cache::pkgcache ""` (docker-clean). libapt-pkg with
    `RootDir=<rootfs>` then fails, and OpenSCAP silently treats every package as absent, so
    package rules become false fails. Fix: an apt.conf.d drop-in, the apt directories and dpkg
    arch tables in the scratch rootfs, and a `var/lib/dpkg/status` built from `status.d` for
    distroless. Probe init failures OpenSCAP swallows are now surfaced on the summary.
  - skopeo converts Docker schema 2 manifests and configs to OCI when writing an OCI layout. The
    local image cache now verifies such copies by identical layers plus identical `diff_ids` of
    a hash-checked source config. Before this fix every Docker-v2 single-arch image failed with
    "not part of source", in local mirror mode too.
- **preferDisa on grace = false**: on UBI 9 keycloak the DISA RHEL 9 V2R9 benchmark gives 253
  fail / 68 pass. It has no container applicability, so host-only rules (services, kernel,
  boot, audit) fail inside an image. The SSG STIG profile marks those notapplicable and gives
  14 fail / 67 pass. The chart default stays `true` per §14. DISA content is still used where
  SSG has none (PostgreSQL manual STIG).
- **Not covered**:
  - Alpine has no SCAP content anywhere, so Alpine images are `notApplicable`.
  - SSG's Debian profiles are CIS / ANSSI / standard: there is no DISA Debian STIG, and
    Debian rules have no V-IDs.
  - The DISA PostgreSQL STIG is for 9.x and manual only.
  - SSG references the Debian security OVAL feed remotely. It is not fetched (no
    `--fetch-remote-resources`), so that one rule is `unknown`.

## 2026-10-05: image hardening (the pack's own images)

Goal: zero *fixable* CRITICAL/HIGH findings in the pack's three images. Every remaining unfixed
CRITICAL/HIGH is triaged in an OpenVEX document (Iron Bank-style justifications), and CI keeps it
that way.

**Measured** with trivy 0.75.0 (`image --severity CRITICAL,HIGH`) and grype 0.120.0, DBs of
2026-10-05. Counts are distinct (CVE, package, version) tuples: CRITICAL / HIGH (fixable C / H).
"Before" for api and ui is the grace build `065cc06`. For the worker it is the first OpenSCAP
build (`dd43f5c`, bookworm, openscap 1.3.7).

| image | trivy before | trivy after | grype before | grype after | after, with the VEX (trivy / grype) |
|---|---|---|---|---|---|
| ui | 2 / 40 (2 / 40) | 0 / 0 (0 / 0) | 21 / 87 (12 / 63) | 0 / 1 (0 / 0) | n/a (Alpine; the one zlib HIGH has no fix and no VEX statement) |
| api | 6 / 66 (0 / 1) | 0 / 44 (0 / 0) | 9 / 74 (0 / 1) | 0 / 57 (0 / 0) | 0 / 0 and 0 / 4 (1 CVE, under_investigation) |
| worker | 10 / 137 (3 / 57) | 1 / 57 (0 / 0) | 22 / 177 (6 / 59) | 9 / 102 (0 / 0) | 1 / 7 and 1 / 18 (11 CVEs, under_investigation) |

**ui**: `nginxinc/nginx-unprivileged:1.31-alpine-slim`, pinned by digest, plus `apk upgrade
--no-cache`. This supersedes Dependabot PR #1 (1.31-alpine), which builds, but the `-slim` variant
has 21 apk packages instead of 70. It drops curl, libxml2/libxslt, gd/tiff/libavif and the
njs/geoip/xslt/image-filter modules, and the config loads none of them. `node:22-alpine` (build
stage) is digest-pinned too. container-structure-test and an HTTP smoke test pass.

**api base**: measured with the same Dockerfile (apt-get upgrade, no pip):

| base | trivy C/H (fixable) | grype C/H (fixable) | notes |
|---|---|---|---|
| python:3.12-slim-bookworm + upgrade | 6 / 65 (0 / 0) | 9 / 73 (0 / 0) | glibc/perl/zlib criticals with no Debian 12 fix |
| python:3.12-slim-trixie + upgrade | 0 / 48 (0 / 0) | 0 / 61 (0 / 0) | |
| **python:3.13-slim-trixie** + upgrade, mount purged | 0 / 44 (0 / 0) | 0 / 57 (0 / 0) | chosen |
| gcr.io/distroless/python3-debian12 (bare base) | 2 / 56 (0 / 25) | 7 / 76 (2 / 34) | **not viable**: Python 3.11 (pyproject requires >= 3.12), no pango/harfbuzz/fontconfig for WeasyPrint, and the bare base alone has 25 fixable HIGHs that cannot be upgraded in place (no apt) |

The bare distroless debian13 base scores 0 / 26 and 4 / 39. WeasyPrint's native closure (pango,
harfbuzz, fontconfig, freetype, fribidi, glib) would have to be copied
into it by hand, with no package database left for the scanners to see. That is worse for
auditability than a slim image with dpkg metadata. 3.13 and 3.12 on trixie tie. 3.13 has the
longer support window and is already in the CI matrix. The full suite passes **inside** the
image (`python -m pytest` as uid 10001, dev deps from uv.lock into /tmp, throwaway
`postgres:16-alpine` on `--network host`): 956 passed, 2 skipped, 5 xfailed.

The runtime stage also removes pip/setuptools/wheel/ensurepip/idle/tkinter. The app runs from
/opt/venv, and pip's vendored urllib3/msgpack were the fixable HIGHs on the 3.13 base. It purges
`mount` (Priority required but neither Essential nor Protected; `login` is Protected in trixie
and stays). CST checks both.

**worker**: same base decision (3.13-slim-trixie, digest-pinned, apt-get upgrade, no pip, mount
purged). Changes:
- trivy 0.75.0 and grype 0.120.0 are already the latest releases. Their sha256 pins match the
  releases' `checksums.txt`.
- clairctl 4.9.0 (Dec 2025, Go 1.24.10, pgx 5.7.6) and cosign 3.1.3 (Go 1.26.4, grpc 1.82) are
  the latest releases, but their binaries carry 3 / 57 fixable CRITICAL/HIGH between them. They
  are now **built from their release tags** in a `gobuild` stage (`golang:1.27.1-trixie`, digest
  pinned). Each build checks that the tag resolves to the pinned commit, applies the minimum
  `go get` bumps (`*_GO_BUMPS`, exact versions; go.sum checked against sum.golang.org), then
  `CGO_ENABLED=0 go build -trimpath`. Both report their release version (`clairctl version
  v4.9.0`, cosign `GitVersion: v3.1.3`).
- skopeo: Debian's skopeo 1.18 is built with Go 1.24.4, and grype flags 23 stdlib HIGH/CRITICAL
  as fixable in it and in the CNI plugins it pulls in. It is replaced by skopeo **1.24.1**, built
  static from its tag the same way (`containers_image_openpgp`, no btrfs/devicemapper drivers).
  Every call site passes `--policy`, so containers-common's policy.json is not needed. This
  drops containers-common, containernetworking-plugins, gpgme and friends (170 to 146 packages).
  Smoke-tested in the image (`inspect --raw`, `copy` to an OCI layout).
- OpenSCAP follows the base to trixie's **1.4.2+dfsg-1** (from 1.3.7). `oscap-chroot` is still
  taken from the sha256-pinned `openscap-utils` .deb (`_all.deb` in trixie). Validation:
  - The real `oscap-chroot` test in tests/scap passes in the image, and all of tests/scap pass as
    root too (the scap-worker case).
  - A hand-written OVAL (dpkginfo + rpminfo, positive and negative) evaluated through
    `prepare_for_oscap` + `oscap-chroot` gives identical results under 1.3.7 and 1.4.2 on a Debian
    13 rootfs and a UBI 9 rootfs.
  - Differences: 1.4.2's rpm (4.20, Sequoia) logs `Verifying a signature using certificate ...
    (Red Hat release key 2)` errors while reading a UBI rpmdb. Results are unaffected, and
    `probe_warnings` does not match them. dpkginfo on a non-Debian rootfs returns `error`
    instead of `false`, which is irrelevant because RHEL content has no dpkginfo tests.
  - Re-check RHEL 9 STIG counts on grace after the rollout.
- Full suite in the image: 983 passed, 1 skipped (the root-only rootfs test, run separately as
  root), 5 xfailed. CST: 14/14.
- `.github/trivy/ignore.yaml` is now empty (`vulnerabilities: []`). The three clairctl
  exceptions and the ui openssl exception are fixed rather than excepted. The file stays as the
  place for reviewed, expiring exceptions.

**VEX** (`api/vex/posture-images.vex.json`, OpenVEX 0.2.0, 60 statements): 48 `not_affected`
with a justification and impact statement, 12 `under_investigation`. Products are version-less
OCI purls for both image names (`security-posture-{api,worker}` as in the chart/grace and
`nebari-security-posture-pack-{api,worker}` as published by build-images.yaml), with
`pkg:deb/debian/...` or `pkg:golang/...` subcomponents, so no statement applies to anyone
else's image. trivy and grype both honour them (verified: with `--vex`, api goes to 0 / 0 and
0 / 4). Evidence used:
- `nm -D` over the exported filesystems. No ELF imports strfmon, ns_printrr/fp_nquery or
  gzprintf/gzvprintf. libexpat1's only importer is libfontconfig, because CPython's pyexpat uses
  its bundled expat 2.8.5. libcurl's only importer is libopenscap, which uses it only for
  `--fetch-remote-resources`, never passed.
- Package contents: no Pod::Text / Archive::Tar in perl-base, no rpmbuild/rpmuncompress, no
  systemd-homed, no python3-libxml2.
- Chart security contexts: capabilities dropped, read-only root fs. The scap-worker runs as root
  with CHOWN/FOWNER/DAC_OVERRIDE/FSETID/SETFCAP/SYS_CHROOT and no SYS_ADMIN.

Marked `under_investigation`, because the input is untrusted scanned-image content reaching a
parser:
- libstdc++ CVE-2026-95619 (aligned operator new; HarfBuzz/OpenSCAP consumers);
- libxml2 x7 (OpenSCAP xmlfilecontent probes read XML from scanned images);
- librpm CVE-2026-103242 / CVE-2026-95520 (rpminfo reads the scanned image's rpmdb headers);
- libacl x2 in the worker (libopenscap `acl_extended_file`, librpm `acl_get_file` on scanned
  rootfs paths in the root scap-worker). In the API these two are `not_affected`, because their
  only consumers there are coreutils/tar/sed, which it never runs.

Review the VEX whenever the base digest moves. A statement whose CVE is fixed upstream should be
deleted once the image no longer carries the package version.

**VEX in the worker's own scans: not wired (documented instead)**. The worker scans what it
mirrored. In the default `MIRROR_MODE=local` the scanners get `oci-dir:<path>`, so trivy and
grype see a path, not `security-posture-*`, and product matching never fires. Doing this
properly needs the worker to recognise the pack's own images by `source_ref` and pass a per-scan
VEX with the product rewritten to the scanned artifact. Trivy server mode would also need
checking. That is a worker change with its own tests, while the scap stage is being changed in
the same files. Follow-up: `SCAN_SELF_VEX` (off by default), keyed on the chart's image
repositories. Until then the dashboard shows the pack's images without VEX, and CI and this file
carry the triage.

**CI** (`.github/workflows/image-scan.yaml`):
- Both scanners run with `--vex`.
- On pull requests the base branch's Dockerfiles are built too (same GHA cache scope), and a
  sticky comment (`<!-- image-scan-counts -->`, same-repo PRs) plus the job summary show before
  and after CRITICAL/HIGH (fixable) per image and scanner (`.github/scripts/image_scan_counts.py`).
- The gate is now any fixable **CRITICAL or HIGH** (was CRITICAL only), from trivy
  (`--ignore-unfixed`, minus ignore.yaml) and from grype (`--only-fixed --fail-on high`, pinned
  0.120.0 by sha256).
- The weekly schedule catches fixes published for unchanged images. Locally, all three new
  images pass both gates, and the old ui image fails the grype gate.

**Upkeep**:
- `*_GO_BUMPS` exist only because upstream releases lag. When clair, cosign or skopeo release
  with the fixes, drop the bumps. For clairctl/cosign, return to the sha256-pinned release
  binaries.
- Dependabot keeps tag+digest pins current for python/node/nginx. The Go builder image and the
  tool versions are manual (see .github/dependabot.yml).
