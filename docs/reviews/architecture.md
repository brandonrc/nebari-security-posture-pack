# Architecture / SRE review: `provenance-collector-pack` @ `security-posture-merge`

Reviewer stance: principal engineer / SRE. Repo read-only. All numbers below were measured on grace on 2026-10-03 (~04:40 UTC) unless marked as an estimate. Sources: `kubectl top`, read-only `psql`, Prometheus (`observability`, cAdvisor, 12 h window), the node kernel log (`journalctl -k`), and in-process timing of the API handlers inside the api pod. The timing scripts were removed afterwards.

## 0. Measured baseline (grace, scan #8: 79 images, parallelism 6)

| Metric | Value | Source |
|---|---|---|
| Scan wall time | 6m07s (#8), 6m19s (#6), 7m40s (#7) | `scans` |
| Avg / max per-image scanner time | trivy 2.0 s / 95 s; **grype 18.9 s / 148 s**; clair 8.4 s / 300 s | `image_scans.duration_ms` |
| Auto-report time after scan (6 types, serial, in worker) | 3m44s (04:16:14 to 04:19:58) | worker logs |
| Worker peak working set, 12 h | **7.28 GiB** (limit 16 GiB), CPU peak 7.6 cores (limit 8, so throttled) | Prometheus `max_over_time` |
| Clair peak | **7.53 GiB** (limit 8 GiB, 6% headroom), 3.8 cores. Idle: 52 MiB | Prometheus / top |
| API peak | 1.44 GiB, and it **stayed at 1.43 GiB for 30+ min** after report generation (heap not returned to the OS) | Prometheus |
| Postgres | 1.25 GiB peak, **2.0 cores, so CPU-throttled at its limit** during Clair ingest; `shared_buffers` 128 MB (default) | Prometheus, `pg_settings` |
| OOM kills since 10-02 | Clair x5 (at 4 GiB), worker x1 (6 GiB), API x1 (1 GiB) | kernel log |
| Worker OOM anatomy (10-02 20:21:54, 6 GiB) | grype 3.2 GiB + grype 2.0 GiB + grype 0.5 GiB + grype 0.15 GiB + python 0.32 GiB + 6 clairctl x ~26 MiB. `memory.oom.group` killed the whole container and with it scan #3 | kernel OOM table |
| DB `clair` | **7,973 MB** (`vuln` 4.72 M rows, 5.7 GB heap; OSV left out). Not proportional to image count | psql |
| DB `posture` | 147 MB: `image_scans` 75 MB (raw gz), `findings` 40 MB (71k rows), `consensus_findings` 19 MB (28k) | psql |
| Raw JSON per full scan | ~16 MB gz/scan (~205 KB/image). Max raw: grype 55 MB, trivy 41 MB (dask-operator, 10.4k findings). **109/1071 rows truncated at 2 MB, so they hold invalid JSON** | psql |
| Reports dir | 745 MB after 9 h. OSCAL AR **87 MB each**, vuln CSV 12-32 MB, POA&M xlsx 13.5 MB | `du`, `reports` |
| Scanner agreement | 3/3: 12,112 · trivy+clair 5,689 · trivy+grype 4,791 · grype 2,346 · trivy 2,224 · grype+clair 1,247 · **clair-only 58 (0.2 %, 0 crit/high)** | `consensus_findings` |
| Registry mix | docker.io 34 · quay 22 · localhost:32000 9 · ghcr 8 · registry.k8s.io 5 · private 1 | `images` |
| Scheduled scans | **Last scheduled scan was #5 at 2026-10-02 20:33. Scans #6, #7 and #8 were all manual: in 8 h, no scheduled scan has fired** | `scans` |
| `/api/v1/vulnerabilities` (page 1 of 7,979 vulns / 28k rows) | **5.0 s, RSS 85 to 375 MB** | in-pod timing |
| `/api/v1/images/{id}` (10,452 findings) | 0.8 s, **6.4 MB JSON**, not paginated by the server | in-pod timing |
| `/api/v1/compliance/stig` | **3.2 s, +113 MB per GET** (builds the full report snapshot to return 105 rows) | in-pod timing |
| `/api/v1/summary`, `/images` | 370 ms, 26 ms | in-pod timing |
| Compat `/api/reports/latest` | 186 ms, 67 KB | in-pod |
| Node root fs (hostpath PVCs) | 94 % used, 24 GB free. hostpath does not enforce PVC sizes, so overflow is invisible on grace | `df` |

---

## 1. One API + one DB vs. a separate Go provenance service

**Verdict: one data plane (one DB, one API contract) is right. One process and one ServiceAccount is wrong.**

- **Correlation.** The grade (0.6 vuln / 0.25 config / 0.15 supply chain), the per-control status (SR-3/SR-4/CM-14 from provenance, RA-5/SI-2 from CVEs, AC/IA/SC from assertions), the SSP and the POA&M all join on the image digest at a single point in time. With two services, a 0.1.x-style CronJob and the posture scan would run on different schedules. Every report would then join provenance from time T1 with CVEs from T2. Assessors ask "as of when?", and the answer has to be a single scan id. A UI calling two APIs also cannot help server-side report generation, which is where the joins happen. The merged code already treats the collector as an evidence producer whose JSON is ingested per scan (`provenance/collector.py`). That is the right relationship.
- **Auth consistency.** 0.1.x let any logged-in user in (in-browser PKCE). Posture uses gateway auth plus an in-API JWT check plus the admin group. Two services means two authorization models and two NetworkPolicies, so they drift. One API wins.
- **Failure isolation.** This is where the merge went too far. One api pod serves the UI, the authenticated provenance aliases, the unauthenticated Grafana listener (same event loop) and on-demand report generation. One OOM (measured: 1 GiB, 2026-10-03 00:35) takes down all four. One worker container runs inventory, mirror, 3 scanners, provenance, auto-reports and the controls engine. One grype spike kills all of it (`oom.group`) and fails the scan. Fix it with **process separation on the same image and the same DB**: api, scan-worker, controls/provenance worker, report-worker as separate Deployments, each with its own ServiceAccount. Splitting into separate services is not needed.
- **Upgrade coupling.** The coupling is in the chart, not the API. Reusing the published chart name means every `provenance-collector` consumer gets the whole stack on the next sync (see B3).
- **Compat `/api/reports` layer: keep it in Python, move it off the api pod.** It is a ~240-line read projection of the same tables. A Go shim would need either direct DB access (a second schema consumer, coupled to every migration) or a service credential to call the API. That adds more moving parts for no gain. Two changes instead: (a) materialize the compat JSON once per scan in the worker and serve stored bytes. `list_reports` currently rebuilds every scan's document on each Grafana poll. (b) Run the unauthenticated listener as its own tiny Deployment (`uvicorn posture.compat:app`, same image), with `automountServiceAccountToken: false` and a **read-only DB role**. Today the unauthenticated endpoint uses the owner role, which has DDL rights.

## 2. Footprint and fit for NIC clusters

Old 0.1.x: dashboard 50m/64Mi plus a CronJob 100m/256Mi while it runs (~320 MiB requested).
New defaults: **requests 1.12 CPU / 2.56 GiB, limits 11.2 CPU / 17.1 GiB, PVCs 42 GiB**.
Grace: limits ~34 GiB against ~2.8 GiB requests, a **12x overcommit**. Grace itself sits at ~99 % memory requests allocated.

**Every default limit that matters was OOMKilled on grace:** worker 6 GiB (at p=6; at the default p=3, three large images under grype at up to 3.2 GiB each is about 9.6 GiB), Clair 4 GiB (x5), API 1 GiB. The defaults are known-bad.

**Clair is not worth default-on.** It found 58 unique findings out of 28,467 (0.2 %), none critical or high. Its real effect is on the agreement multiplier: it lifts 5,689 trivy-only findings to 2/3 agreement. What it costs:
- 8 GB of Postgres, independent of cluster size
- a 7.5 GiB working-set spike, and 5 OOMs at 4 GiB
- Postgres CPU saturation during updater ingest
- updater egress to about a dozen distro feeds, which blocks air-gap
- scan start gated on updaters (`_wait_scanners_ready`)
- the max per-image time (300 s), and the "Clair 500 for 6 images" class of failure
- the HTTP-reachable mirror registry requirement (clairctl can only point Clair at a registry). This is the main reason the mirror design exists.

Make Clair **opt-in** (`scanner.clair.enabled: false`) and say in the docs that turning it on raises confidence, not coverage. Scoring already handles two scanners: the multiplier is relative to the scanners that succeeded.

**Trivy server vs. client-only.** Keep the server. It is cheap (89 MiB idle, 0.21 GiB peak, 0.05 cores) and keeps the trivy DB out of the worker. Cut its PVC (10 GiB to 2-3 GiB) and limit (4 GiB to 1-1.5 GiB). The trivy client still unpacks layers locally (`/cache/trivy-client` is 1.5 GB).

**Minimum viable sizing, 3-node cloud cluster** (e.g. 3 x 4 vCPU / 16 GiB, 200-500 images, Clair off, grype concurrency capped at 2, reports moved out of the API):

| Component | Requests | Limits | PVC |
|---|---|---|---|
| api (no report generation) | 100m / 384Mi | 1 / 1Gi | none |
| scan-worker (p=3, grype<=2) | 500m / **4Gi** | 3 / 7Gi | 15Gi (grype DB 3.0 GB, trivy client 1.5 GB, scratch) |
| report-worker (new, concurrency 1) | 100m / 512Mi | 1 / 3Gi | reports (see M6) |
| trivy server | 100m / 256Mi | 1 / 1.5Gi | 3Gi |
| postgres (no Clair) | 250m / 512Mi | 1 / 1.5Gi | 10Gi |
| ui | 20m / 32Mi | 200m / 128Mi | none |
| **Total (core)** | **~1.1 CPU / 5.7 GiB** | **~7.2 CPU / 14 GiB** | **~30 Gi** |
| Clair (opt-in) | +250m / 1.5Gi | +2 / 8Gi | +10Gi on its **own** Postgres |

Put requests near the real peak for the worker. A 1 GiB request with a 16 GiB limit on a shared NIC node means memory-pressure evictions of other tenants' Burstable pods during each scan.

**Postgres.**
- No backups at all: the README says so, and the chart ships no CronJob, WAL archiving or snapshot guidance. For a pack whose output is ATO evidence, that is a Major gap.
- Untuned: 128 MB `shared_buffers`, 64 MB `maintenance_work_mem`, 2-CPU limit saturated.
- With Clair, the default 10 GiB PVC is **81 % used on day 1** (8.1 GB). Grace only "fits" because hostpath does not enforce PVC sizes.
- Churn: `findings` and `consensus_findings` are delete+insert per image per rescan. Autovacuum keeps up today (0 dead tuples) but needs per-table `autovacuum_vacuum_scale_factor≈0.05` at 500+ images.
- Clair's 4.7 M-row `vuln` table at the default 20 % scale factor tolerates about 940k dead rows before a vacuum.
- `UPDATE images SET running=false` hits the whole table every scan, which bloats `images`.

**Growth per scan / steady state (estimate from measured per-image ratios).**
- Per image: raw ~205 KB gz per rescan (kept 14 d), `findings` ~0.43 MB (latest only), `consensus_findings` ~0.2 MB (latest only).
- Each image is rescanned about once a day (`rescanAfterHours=24`).

| Images | raw (14 d) | findings + consensus | posture DB | + Clair | OSCAL AR / report | reports @ keepPerType=50 |
|---|---|---|---|---|---|---|
| 79 | 0.23 GB | 0.06 GB | ~0.3 GB | +8 GB | 87 MB | ~5.8 GB |
| 500 | 1.4 GB | 0.32 GB | **~2 GB** | +8 GB | ~550 MB | **~35 GB** |
| 2,000 | 5.7 GB | 1.3 GB | **~7.5 GB** | +8 GB | ~2.2 GB | **~140 GB** |

`image_scans` rows (with raw nulled) and `scan_snapshots` are never pruned. That is about 6k + 3k rows a day at 2,000 images, roughly 1-2 GB a year.

## 3. Pipeline scalability

The cost model checks out against the data: per-image wall ≈ max(scanner) + mirror check ≈ 25-27 s, dominated by grype. 79 x 27 s / 6 ≈ 356 s, against a measured 367 s.

| Images | p=6 | p=3 (default) | grype capped at 2 concurrent (safe on 7 GiB) |
|---|---|---|---|
| 500 | ~38 min | ~75 min | ~80 min |
| 2,000 | ~2.5 h | **~5 h (about the 6 h interval)** | ~5.3 h |

On top of that, auto-reports scale linearly, run serially inside the worker loop, and block the next scan (3m44s at 79 images, so ~24 min at 500 and ~95 min at 2,000). The OSCAL AR would be ~2.2 GB built in memory. The controls engine is O(1) in image count (~1 s for 35 assertions) and is not a concern.

- **Why 6-parallel OOMed at 6 GiB:** grype, not trivy or clairctl. Two concurrent grype processes held 3.2 GiB and 2.0 GiB, which is 85 % of the cgroup. trivy is gone in 2 s and clairctl uses about 26 MiB. The Python parent also buffers full stdout: up to 55 MB raw, then `str`, then `json.loads`, which can transiently reach several hundred MB per big image. `parallelism` counts images, not memory weight. **Fixes, in order:**
  1. A per-scanner semaphore (grype ≤ 2).
  2. Admission weighted by image size from the manifest.
  3. The structural fix: **SBOM once, match many.** Generate an SBOM once per new digest and keep it. Run daily rescans as `grype sbom:` / `trivy sbom` rematches, each under ~300 MB and a few seconds. Images only get pulled again when a new digest appears. This is the only design that fits 2,000 images. It costs some cataloger independence, so say so in SCORING.md.
- **Docker Hub limits.**
  - 43 % of grace's images are on docker.io. Scan #6 hit 429 six times on provenance probes and twice on mirror copies.
  - The mirror protects only the scanners. Provenance probes (`.sig`/`.att`/`.sbom` manifest GETs, referrers, tag lists every scan) still go upstream: about 4-6 manifest requests per new digest per 24 h. At 2,000 images that is ~10k requests a day, ~4k of them to Docker Hub, which is impossible anonymously. `registryAuth.existingSecret` has to be a documented requirement above roughly 100 images.
  - **On multi-node NIC there is no `registry.container-registry.svc:5000` and no `localhost:32000`.** Both are MicroK8s-isms and both are chart defaults. Every mirror attempt fails and falls back, so each image gets pulled by trivy, grype and the Clair indexer separately. grype keeps no layer cache, so every daily rescan downloads the full image again: multi-GB for ray/jupyter.
  - The mirror also copies images pulled with private credentials into a registry the controls engine itself flags as anonymously readable. That is a confidentiality leak.
  - There is no GC of `posture-mirror/*`.
  - Without Clair, swap the registry mirror for a per-digest local OCI layout on the worker PVC (`skopeo copy docker://… oci:/cache/oci/<digest>`, then trivy `--input` / grype `oci-dir:`).
- **Postgres as queue.** `FOR UPDATE SKIP LOCKED` is fine and costs nothing at a few rows a day. The real limit is granularity: a scan is one monolithic unit run by one worker.
  - `recover_stale` fails every `running` scan at startup. That is correct only for exactly one replica: a second replica would fail the first one's scan.
  - Restart is cheap at image level, because persisted images are skipped via `rescanAfterHours`. But the failed scan writes no snapshot, posture, reports or controls, and the next attempt waits for the next scheduler tick.
  - Make the image the queue item: a `scan_items` table with a lease (`heartbeat_at` already exists on `scans`). That buys resume and N worker replicas.
- **The scheduler resets on every worker restart (Blocker B2).** `_sync_schedule` adds an APScheduler `interval` job with no `next_run_time`, so the first fire comes `intervalHours` after start. Restarts happen on every deploy, OOM and node drain. If they come more often than every 6 h, scheduled scans never run. That is happening now on grace: nothing scheduled since 20:33. The pack's own `pack-scan-fresh` (RA-5(2)) assertion only stays green because humans keep clicking "scan".
- **Report generation in the API.**
  - `POST /reports` runs `BackgroundTask` → `asyncio.to_thread` with no concurrency cap. Nine concurrent reports OOMKilled the API at 1 GiB, and the response was to raise the limit to 4 GiB.
  - CPU-bound openpyxl and WeasyPrint work in threads holds the GIL and starves the event loop, which also serves the liveness probe and the Grafana listener.
  - The API heap then stays at 1.43 GiB.
  - Stuck rows: `fail_interrupted` runs only at **API** startup and only for rows older than 15 min. Rows the worker leaves behind (auto-generate) or that are under 15 min old at restart stay `running` forever. That is the 8 "marked failed manually" rows in `reports`.
  - The `reports` table is already a queue: have the worker or report-worker claim rows (SKIP LOCKED plus a lease), concurrency 1, with streaming writers for CSV and JSON.

## 4. In-memory list endpoints

- `/vulnerabilities` loads every consensus row for running images as ORM objects, including the `per_scanner` JSONB. It then groups, filters, sorts and paginates in Python, on every page click and every filter keystroke. Measured: 28k rows took 5.0 s and +290 MB.
  - Linear projection: 500 images is ~180k rows, ~30 s and ~1.9 GB **per request**. Two concurrent users OOM the 4 GiB API.
  - 2,000 images is ~700k rows: past the nginx `proxy_read_timeout 120s` (504) and past any sane limit.
  - It falls over around 300-400 images.
- `/images/{id}` returns all findings: 6.4 MB for 10,452 of them, with pagination done in the client. Tolerable after gzip. Paginate in SQL anyway; the index `(image_id, severity)` is effectively there.
- `/compliance/stig` builds the full report snapshot (all findings) to return 105 STIG rows: 3.2 s and +113 MB per GET. It should read `posture_results` directly.
- **Fix:** write a per-scan `vuln_rollup` table (vuln_id, max severity, images, workloads, fixable, cvss, packages[]) at scan end. Then serve `/vulnerabilities` with SQL `WHERE/ORDER BY/LIMIT/OFFSET` (keyset pagination) and a `pg_trgm` index for `q`. `/images` can stay in memory up to ~5k images (26 ms at 93).

## 5. Chart quality

- **`lookup` secret generation (Blocker B1).** Under ArgoCD (`helm template`), `lookup` returns nothing, so every render produces new random passwords.
  - The documented install path is `examples/argocd-application.yaml`: `selfHeal: true`, bundled Postgres, **no `existingSecret`**. On it, ArgoCD shows the Secret permanently OutOfSync and re-applies a new password on every reconcile. The Postgres data dir keeps the first password, so api, worker and Clair fail auth on their next restart.
  - The README limitation note does not save the example from this, and CI does not catch it because it only does the first sync.
  - `helm.sh/resource-policy: keep` is ignored by ArgoCD.
  - Fix: a pre-install/PreSync hook Job that creates the Secret only if it is absent, with RBAC scoped to that one Secret name. Alternatively, make `existingSecret` required whenever `.Capabilities`/lookup show no cluster access.
- **`nameOverride` trick.** It works for grace (selectors and PVCs survive). It is a one-off. `fullname` collapsing on substring `contains` is fragile: a release named `posture` plus nameOverride `nebari-security-posture-pack` collapses, but `sp` would not.
- **Compat `fail`s.** Good UX: precise messages. But `config.namespaces` → fail removes a 0.1.x capability (namespace-scoped install) with no replacement.
- **Probes.**
  - The **worker has no probes at all.** It serves `:9000/healthz` with a staleness check, and nothing calls it. A wedged worker is never restarted.
  - The API liveness probe (5 s timeout) shares the event loop with GIL-heavy report threads, so it can flap during big reports.
- **PDB / HPA.** Absence is correct for single-replica, stateful-ish pods: a `minAvailable: 1` PDB would just block drains. HPA has nothing to scale: the API is not the bottleneck and the worker is a singleton.
- **updateStrategy.** api, worker and trivy all use `Recreate` because of RWO PVCs, so every upgrade means UI and Grafana downtime. The worker's **required** podAffinity to the api pod (shared RWO reports PVC) couples their scheduling: the worker cannot schedule while the api is Pending. Storing report bytes in Postgres (`bytea`/large object, ≤ 100 MB) or object storage removes the shared PVC, the affinity and `Recreate` on the api.
- **PVC retention on uninstall.** The Postgres VCT and the DB Secret are kept (good). The reports PVC is chart-owned and **deleted on uninstall**: generated POA&M, SAR and AR evidence disappears. The migration guide likewise says the 0.1.x PVC "is removed by the upgrade".
- **Migrations.** `alembic upgrade head` runs in the api init container, with 30 retries and no advisory lock. That is OK at `replicas: 1` thanks to Postgres transactional DDL, but racy above that. The worker can start new code against an old schema during the window. Use a PreSync/pre-upgrade hook Job with `pg_advisory_lock`. Migrations 0002/0003 are additive, so app rollback within 0.2.x is safe. There is no downgrade story to 0.1.x: data and PVC are gone.
- **NetworkPolicy.** Ingress only, and the peers are correct.
  - Clair's `/metrics` (enabled in its config) is reachable only from the worker, so Prometheus cannot scrape it.
  - The compat port allows a whole namespace (`monitoring`, `observability`), meaning any pod there gets unauthenticated inventory.
  - CI runs with `networkPolicy.enabled: false`, which exposes `:8081` cluster-wide.
  - There is no egress policy on the component that holds the most credentials (see M8).
- **Unauthenticated internal listener.** It is not a thread: it is a second `uvicorn.Server` task on the **same event loop** as the main API. A long report or a 5 s `/vulnerabilities` request delays Grafana, and an API OOM kills it. It also uses the owner DB role (see §1).
- **Extra CA mounting.** Well done for the worker: an init container concatenates the bundle into `SSL_CERT_FILE` for httpx, Go and cosign. Clair gets `SSL_CERT_DIR`. The **API does not get it**, so JWKS over `https` with a private CA would fail.
- **Resource defaults vs grace values.** Every value grace had to raise is a value the chart default should change (§2). The worker comment "~2Gi per parallel image" is wrong for grype: measured peak 3.2 GiB per process.
- **Misc.**
  - `nebari-app >=0.1.1` is an open range (the lock pins 0.1.1).
  - Images are pinned by tag, not digest, and `postgres:16-alpine` floats.
  - Worker tool binaries are amd64-only (`*_linux_amd64`), so there is no arm64/Graviton support.
  - No `values.schema.json`.

## 6. Operability

- **Observability.**
  - Logs: structured logfmt, good.
  - Metrics: none. No Prometheus endpoint on api or worker, no ServiceMonitor, no PrometheusRule. Clair's endpoint is blocked by the NetworkPolicy.
  - This review had to read the kernel log and cAdvisor to find the 7.3 GiB worker peak.
  - Minimum metric set: `posture_scan_duration_seconds`, `posture_last_successful_scan_timestamp`, `posture_scan_images_total{status}`, `posture_scanner_runs_total{scanner,status}`, `posture_scanner_db_age_seconds`, `posture_report_duration_seconds{type}`, `posture_queue_depth{kind}`.
  - Alerts: scan stale > 2x interval, scanner error ratio > 10 %, DB age > 72 h, report failed. These map one-to-one onto the pack's own RA-5(2) and SI-5 assertions, so the pack should alert on itself.
- **Scan progress.** `scans.log` is a 200-line deque, flushed every 3 s. At 500+ images the early per-image errors are rotated out before anyone reads them.
- **"Clair returned 500 for 6 images" today.** The operator path is: UI scan log (if not rotated) → image detail → scans tab (`image_scans.error`, a 1,500-char stderr tail from clairctl) → `kubectl logs` on Clair, with no request id to correlate. Clair introspection is blocked. There is no runbook and no "retry failed images" path, even though `target_image_ids` scans already exist.
  - Add: a `GET /scans/{id}/failures` view grouped by scanner and error, a "rescan failed" action, a request-id passed to clairctl, and RUNBOOK.md covering Clair 500/OOM, grype DB invalid, Docker Hub 429, stuck report/scan rows, PVC full, and restore from backup.
- **DB migrations and rollback.** Covered in §5. Add a backup step before migrate: a pre-upgrade `pg_dump` hook.
- **Upgrade path from 0.1.x** (`docs/src/content/docs/migrating.md`):
  - It is honest, but it describes a **breaking change on a minor bump of the same chart name**. Login moves from any user to admin only. The old PVC is deleted. The Grafana URL changes (unless `internalService.name` is set). The footprint goes from ~320 MiB to 2.5 GiB requested / 17 GiB limits, plus 42 GiB PVCs.
  - ArgoCD Applications with a loose `targetRevision` (`*`, `>=0.1`) will pull this automatically.
  - The merge proposal itself recommended renaming the chart; the implementation kept the name.
- **Multi-tenancy / scope.** Install-wide, cluster-wide and admin-only. There is no namespace-scoped install (`config.namespaces` now fails) and no per-namespace read role. That is at odds with the "program SSP inherits platform controls" story in ARCHITECTURE §3: program owners cannot see their own namespace without platform-admin.
- **Air-gap.** Unsupported (CHANGELOG says so).
  - Vendored: the OSCAL catalog (250 KB).
  - Online-only: trivy DB (`--db-repository` not exposed), grype DB (`GRYPE_DB_UPDATE_URL` not exposed), Clair updaters (no `clairctl import-updaters` flow), cosign TUF root and Rekor (`/cache/sigstore` populated from the internet), and upstream tag lists.
  - For a pack aimed at IL4/IL5/FedRAMP programs, egress-restricted clusters are the norm. Exposing the mirrors is about 2-3 days of work.
- **Schedule vs event-driven.** A 6 h interval plus the restart-reset bug means new workloads can go unscanned indefinitely, and normally for up to 6 h. The building blocks for events already exist:
  - A pod informer in the worker (the ClusterRole already has `watch`) can enqueue **targeted** scans (`target_image_ids`) for unseen digests within a minute.
  - Re-evaluation for new CVEs should be driven by **vuln-DB updates** (trivy/grype DB timestamps change), using SBOM rematch rather than image re-pulls.
  - Keep a daily full sweep as a safety net.

## 7. Verdict

**Repo: one monorepo is fine.** The Go collector stays its own module and image (`quay.io/nebari/provenance-collector` plus release binaries already exist). The JSON report schema is the shared contract, and both the collector and the posture worker already honor it.

**Packaging: two packs/charts from that repo, not one.**
1. `provenance-collector`: light and foundational (NIC alpha), unchanged contract, ~320 MiB.
2. `nebari-security-posture-pack`: heavy, experimental, opt-in. It embeds the collector binary, owns the DB, and serves the compat API for users who move over.

The merged *code* gets the correlation benefits. The merged *chart under the old name* forces a 10-50x footprint and a breaking auth change onto every foundational install, and puts two maturity levels in one artifact. If maintainers insist on one chart, it needs a `profile: provenance` default that renders only api + ui + postgres + worker with all scanners, Clair, the controls engine and reports off, plus a major version bump.

**Top 5 changes before production-grade**
1. **Fix release safety:** ArgoCD-safe Secret creation (B1), persistent scan scheduling (B2), a chart rename or major bump with a light default profile (B3), and an API without an SA token (B4).
2. **Split processes and privileges on one image:** api (no token, read-only DB role for compat), scan-worker (no Secrets access, egress only to registries and DB feeds), controls/provenance worker (the privileged SA), and a report-worker that claims `reports` rows with leases. Add per-scanner concurrency (grype ≤ 2) and worker probes.
3. **Push reads into SQL and stream writes:** `vuln_rollup` plus SQL pagination for `/vulnerabilities`, server-side pagination for `/images/{id}`, `/compliance/stig` from `posture_results`, and streaming CSV/JSON (OSCAL AR) report writers.
4. **Storage lifecycle:** Clair off by default and on its own DB when enabled; report retention by bytes and age, with reports stored in the DB or object storage instead of an RWO PVC; a `pg_dump` backup CronJob plus a pre-upgrade dump; Postgres tuning; pruning of `image_scans` and `scan_snapshots`; and a local OCI layout cache instead of the MicroK8s registry mirror.
5. **Operability:** Prometheus metrics and PrometheusRules, a failures view with "rescan failed", a runbook, air-gap knobs (trivy/grype DB repositories, Clair updater bundles, TUF mirror), and a pod-informer for targeted scans with SBOM rematch on DB updates.

---

## Prioritized findings

Effort: XS < 0.5 d, S ≤ 1 d, M 2-4 d, L 1-2 wk.

### Blocker

| # | Finding | Evidence | Fix | Effort |
|---|---|---|---|---|
| B1 | `lookup`-generated DB Secret is regenerated on every ArgoCD render. The documented ArgoCD example (selfHeal, no `existingSecret`) rotates the passwords underneath an initialized data dir, so pods fail auth on their next restart | `chart/templates/postgres.yaml`, `examples/argocd-application.yaml`, README limitation | PreSync/pre-install hook Job that creates the Secret if absent; or require `existingSecret` | S |
| B2 | Scheduled scans never fire when the worker restarts more often than `intervalHours` (interval job without `next_run_time`; state in memory) | grace: last scheduled scan 20:33, 8 h+ with only manual scans | Make scans "due" from the DB (`max(finished_at)` of scheduled/done) on startup and in each loop; or a Postgres APScheduler jobstore | XS-S |
| B3 | Reusing the `provenance-collector` chart name on 0.2.0 auto-upgrades foundational installs: auth any-user → admin, old PVC deleted, ~320 MiB → 2.5 GiB requests / 17 GiB limits / 42 GiB PVCs | `Chart.yaml`, `migrating.md`; proposal 0001 recommended a rename | New chart name (or 1.0.0 plus a light default profile); keep 0.1.x maintained for one cycle | S-M |
| B4 | The api pod automounts the shared ServiceAccount token. With `helmReleases.enabled` (on in grace and the ArgoCD example) that SA has **get/list on all Secrets cluster-wide** plus `get` on the Keycloak master-admin Secret. The API never calls the Kubernetes API | `api.yaml` `automountServiceAccountToken: true`; `rbac.yaml`; no k8s client in `routers/`; README "no cluster-wide Secret access" is wrong | `automountServiceAccountToken: false` on api (and ui); separate SAs per component | XS |

### Major

| # | Finding | Evidence | Fix | Effort |
|---|---|---|---|---|
| M1 | Default resources are known-bad: worker 6 GiB, Clair 4 GiB and API 1 GiB were each OOMKilled. Requests are 12-16x below limits, so scans overcommit shared nodes | kernel log; Prometheus peaks worker 7.3 / Clair 7.5 / API 1.4 GiB | New defaults per the §2 table; requests ≈ realistic peak | XS |
| M2 | Worker memory is governed by grype, but `parallelism` counts images. One grype spike plus `oom.group` kills the whole worker and fails the scan; Python buffers 55 MB stdout ×3 | OOM table: grype 3.2 + 2.0 GiB of 6 GiB | Per-scanner semaphores (grype ≤ 2), stream stdout to a temp file and parse from disk; later, SBOM-once / rematch | S (sem) / L (SBOM) |
| M3 | Report generation runs in the API (BackgroundTask threads, no cap, GIL-bound). Rows get stuck (`fail_interrupted` only at API start, >15 min); worker-created rows are never recovered; the API heap stays at 1.4 GiB | 8 rows "marked failed manually"; API OOM at 00:35 | Worker or report-worker claims `reports` rows (SKIP LOCKED plus lease/heartbeat), concurrency 1, streaming writers; the API only enqueues | M |
| M4 | List endpoints aggregate in Python: `/vulnerabilities` 5.0 s and +290 MB at 28k rows (≈30 s / 1.9 GB at 500 images, timeouts at 2,000); `/compliance/stig` 3.2 s / +113 MB per GET; `/images/{id}` 6.4 MB unpaginated | in-pod timing | `vuln_rollup` per scan plus SQL pagination and keyset; STIG from `posture_results`; server-side findings pagination | M |
| M5 | Clair is default-on for 0.2 % unique findings (0 crit/high) at the cost of an 8 GB DB, 7.5 GiB spikes, 5 OOMs, updater egress, scan gating, and the need for an HTTP registry mirror | §0 agreement table, `clair` DB size | `scanner.clair.enabled: false` default; when enabled, a separate Postgres or external DB | XS (+ docs) |
| M6 | Storage lifecycle. Reports: keepPerType 50 × 87 MB AR = 4.3 GB on a 2 GiB PVC (fills after ~17 auto-generated scans on enforcing CSI); deleted on uninstall. Postgres: no backups, 128 MB shared_buffers, 2-CPU limit saturated, 10 GiB PVC 81 % full with Clair. Raw JSON truncated to invalid JSON (10 %). `image_scans` and `scan_snapshots` unbounded | §0, §2 tables | Retention by bytes/age, reports in DB or object storage; `pg_dump` CronJob plus pre-upgrade dump; PG tuning (`shared_buffers` 25 %, autovacuum per table); store complete raw or none; prune | M |
| M7 | The mirror design is MicroK8s-specific (`registry.container-registry.svc:5000`, `localhost:32000` defaults). On NIC every mirror attempt fails, so each image is pulled by 3 scanners and grype re-downloads full layers on every rescan. Private images get copied into an anonymous registry. No GC. Provenance probes bypass the mirror (6 × 429 per scan with 34 Docker Hub images) | `mirror.py`, values, DECISIONS scan #6 | Default mirror off unless configured; local OCI layout cache on the worker PVC; require/document `registryAuth` above ~100 images; GC | M |
| M8 | Untrusted-input parsers (grype, trivy, skopeo, cosign on attacker-controllable images) run in the same pod/SA as cluster-wide Secret read, the Keycloak master-admin credentials and unrestricted egress | `worker.yaml`, `rbac.yaml`, NetworkPolicy (ingress only) | Split the scan-worker (no token, egress only to registries and DB feeds) from the controls/provenance worker (privileged, no image parsing); egress NetworkPolicies | M |
| M9 | No metrics, alerts or runbook. The worker has no probes (its `/healthz` is unused). The scan log is capped at 200 lines. Clair metrics are blocked by the NetworkPolicy | §6 | Metrics plus PrometheusRule, worker liveness/readiness on `:9000/healthz`, failures view, RUNBOOK.md | M |
| M10 | Monolithic scan unit: no per-image queue, so no resume, no horizontal worker scale-out, and `recover_stale` is unsafe for more than 1 replica. Auto-reports and controls run inline and block the next scan (~95 min at 2,000 images) | `worker.py` `run_scan`, `recover_stale`, `poll_once` | `scan_items` queue with leases; post-scan stages as separate queue items | L |
| M11 | Air-gap unsupported for a pack targeting IL4/5: trivy/grype DB, Clair updaters, cosign TUF/Rekor and tag lists are all online-only | CHANGELOG; no repository knobs | Expose `trivy --db-repository`, `GRYPE_DB_UPDATE_URL`, Clair updater import, `TUF_MIRROR`/trusted root; document an offline bundle | M |
| M12 | CI integration runs Clair, mirror, controls engine, NetworkPolicy and auth all **off**: the default-on stack is untested end to end, and the B1 drift is not caught (single sync only) | `.github/argo-apps/provenance-collector.yaml` | A CI profile with defaults on (Clair can stay off once M5 lands), a second ArgoCD sync/refresh, NetworkPolicy on | S-M |

### Minor

| # | Finding | Fix | Effort |
|---|---|---|---|
| m1 | Compat listener: same event loop as the API, owner DB role, `list_reports` rebuilds every scan's document per poll; whole-namespace allow | Separate tiny Deployment, read-only role, materialized per-scan JSON | S |
| m2 | Alembic in an init container without an advisory lock; worker may run new code on the old schema briefly; no pre-migrate backup | Hook Job plus `pg_advisory_lock`; pre-upgrade dump | S |
| m3 | Worker required podAffinity to api plus `Recreate` on api, both because of the shared RWO reports PVC | Reports in DB or object storage; drop affinity; RollingUpdate api | S (after M6) |
| m4 | `extraCACerts` not mounted in the API (JWKS over a private-CA https would fail) | Mount bundle plus `SSL_CERT_FILE` in api | XS |
| m5 | Open dependency range `nebari-app >=0.1.1`; third-party images by tag (`postgres:16-alpine` floats); worker tools amd64-only; no `values.schema.json` | Pin; digests; multi-arch build; schema | S |
| m6 | Two provenance engines remain (Go collector plus the full Python port, and update checks always in Python), which doubles maintenance. The proposal said to delete the port | Converge: fix updates in Go, delete the Python port behind a release | M |
| m7 | grype `db update` (APScheduler, 12 h) can overlap a running scan on the same `/cache/grype` | Skip while scan running, or update into a staging dir then swap | XS |
| m8 | Docs duplicated (`docs/*.md` and `docs/src/content/docs/*.md`, synced by a script); README contradicts RBAC when helm releases are on | One source; fix README | XS |
| m9 | `UPDATE images SET running=false` (full table) every scan; per-image delete+insert churn | Targeted update; per-table autovacuum settings | XS |
| m10 | No namespace-scoped read role or install; program owners need platform-admin to see their namespace (conflicts with the "program SSP inherits" story) | Group → namespace mapping in the API; namespace-scoped reports for non-admin groups | M |
| m11 | Schedule-only discovery (up to 6 h to see a new workload) | Pod informer → targeted scans; DB-update-driven rematch | M |
