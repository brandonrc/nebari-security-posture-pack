# Operations: metrics, alerts, runbook

Companion to `docs/reviews/architecture.md` (M9). Process layout: **api** (UI + JSON API),
**scan worker** (`python -m posture.worker --stages inventory,scan`), **privileged worker**
(`--stages provenance,controls,reports`), **report-worker** (`python -m posture.report_worker`),
Postgres, trivy server, optional Clair.

## Metrics

| Process | Endpoint | Auth |
|---|---|---|
| api | `:8000/metrics` (outside `/api/v1`) | none. The UI nginx proxies only `/api/`, so the gateway never routes it; the NetworkPolicy must admit only the monitoring namespace to :8000 |
| scan worker, privileged worker | `:9000/metrics` (next to `/healthz`) | none, same NetworkPolicy rule for :9000 |
| report-worker | `:9000/metrics`, `/healthz` | none |

Process metrics (reset on restart; use `rate()` / `increase()`), recorded where the work happens:

| Metric | Labels | Where |
|---|---|---|
| `posture_scan_duration_seconds` (histogram) | `trigger`, `status` | scan worker / privileged worker |
| `posture_scanner_runs_total`, `posture_scanner_duration_seconds` | `scanner`, `status` | scan worker |
| `posture_scan_images_deferred_total` | | scan worker (SCAN_MAX_IMAGE_GB admission) |
| `posture_grype_db_updates_total` | `status` | scan worker |
| `posture_event_scans_total` | | scan worker (pod watcher) |
| `posture_image_cache_bytes` | | scan worker (`MIRROR_MODE=local`) |
| `posture_report_duration_seconds`, `posture_reports_generated_total` | `type`, `status` | report-worker |

State gauges, read from Postgres by every process that serves `/metrics` (the api on each
scrape, at most every 10 s; workers every 30 s), so they survive restarts and do not depend on
which pod is scraped:

| Metric | Meaning |
|---|---|
| `posture_last_successful_scan_timestamp_seconds` | finish time of the newest `done` scan (0 = never) |
| `posture_scan_interval_seconds` | settings `scanIntervalHours` |
| `posture_scan_images{status=total\|done\|failed}` | latest done scan |
| `posture_scan_scanner_results{scanner,result=ok\|error}` | per-image scanner results of the latest done scan |
| `posture_scanner_db_age_seconds{scanner}`, `posture_scanner_healthy{scanner}` | `scanner_status` |
| `posture_queue_depth{kind}`, `posture_queue_running{kind}`, `posture_queue_oldest_age_seconds{kind}` | `kind` = scans, reports, controls |
| `posture_reports{status}`, `posture_reports_failed_last_24h` | `reports` table |
| `posture_assertions{status}` | latest control evidence run (pass, fail, unknown, not-applicable) |

Scrape config: the chart's `ServiceMonitor` / `PodMonitor` (see DECISIONS "needs chart"), or

```yaml
- job_name: security-posture
  kubernetes_sd_configs: [{role: pod, namespaces: {names: [security-posture]}}]
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_component]
      regex: api|worker|worker-privileged|report-worker
      action: keep
    - source_labels: [__meta_kubernetes_pod_container_port_number]
      regex: "8000|9000"
      action: keep
```

The DB gauges are reported by every process: aggregate them with `max()` (or scrape only the
api for them).

## Alert rules

These map onto the pack's own RA-5(2) (scan freshness) and SI-5 (feeds) assertions.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-posture
spec:
  groups:
    - name: security-posture
      rules:
        - alert: PostureScanStale
          expr: |
            time() - max(posture_last_successful_scan_timestamp_seconds) > 2 * max(posture_scan_interval_seconds)
            or max(posture_last_successful_scan_timestamp_seconds) == 0
          for: 30m
          labels: {severity: warning}
          annotations:
            summary: No successful security-posture scan for more than twice the scan interval
            runbook: docs/OPERATIONS.md#stuck-scans-and-reports
        - alert: PostureScannerErrorRate
          expr: |
            max by (scanner) (posture_scan_scanner_results{result="error"})
              / clamp_min(max by (scanner) (posture_scan_scanner_results{result="ok"})
                          + max by (scanner) (posture_scan_scanner_results{result="error"}), 1) > 0.10
          for: 15m
          labels: {severity: warning}
          annotations:
            summary: "{{ $labels.scanner }} failed on more than 10% of the images of the latest scan"
            runbook: docs/OPERATIONS.md#clair-500--oom
        - alert: PostureScannerDBStale
          expr: max by (scanner) (posture_scanner_db_age_seconds) > 72 * 3600
          for: 1h
          labels: {severity: warning}
          annotations:
            summary: "{{ $labels.scanner }} vulnerability database is older than 72 h"
            runbook: docs/OPERATIONS.md#grype-db-invalid--stale
        - alert: PostureReportFailed
          expr: increase(posture_reports_generated_total{status="failed"}[1h]) > 0 or max(posture_reports_failed_last_24h) > 0
          labels: {severity: info}
          annotations:
            summary: A compliance report failed to generate
            runbook: docs/OPERATIONS.md#stuck-scans-and-reports
        - alert: PostureQueueStuck
          expr: max by (kind) (posture_queue_oldest_age_seconds) > 6 * 3600
          for: 15m
          labels: {severity: warning}
          annotations:
            summary: "A {{ $labels.kind }} row has been queued or running for more than 6 h"
            runbook: docs/OPERATIONS.md#stuck-scans-and-reports
```

## Runbook

### Clair 500 / OOM

Symptoms: scan log `clair error: ... 500`, `PostureScannerErrorRate{scanner="clair"}`, Clair pod
restarts with `OOMKilled` (it peaks at ~7.5 GiB while indexing large images).

1. `kubectl -n security-posture logs deploy/<release>-clair --previous | tail -100`: an indexer
   panic or `context deadline exceeded` points at one image; OOM shows in `kubectl describe pod`.
2. Raise `clair.resources.limits.memory` (8Gi is the measured minimum with large images) or turn
   Clair off (`scanner.clair.enabled: false`): it adds confidence, not coverage (0.2 % unique
   findings on grace). Scoring adapts to two scanners.
3. Clair needs `MIRROR_MODE=registry`. With `local`/`off` it is skipped on purpose (scan log:
   "clair skipped").
4. Rescan only the failed images: `POST /api/v1/scans {"imageIds": [...], "force": true}` (ids from
   the image list filtered by scanner status).

### grype DB invalid / stale

Symptoms: `grype: vulnerability DB not ready` in the scan log, `PostureScannerDBStale`.

1. Worker log `grype.db_update.failed` shows the reason (network egress, disk full).
2. DB updates never run while a scan runs (`grype.db_update.deferred`); a long scan delays the
   update until it ends. Persistent deferral means scans never end: see stuck scans.
3. Force a refresh: `kubectl exec deploy/<release>-worker -- grype db update` (uses
   `GRYPE_DB_CACHE_DIR=/cache/grype`). A corrupt DB: delete `/cache/grype` and restart the worker
   (the first scan waits up to `SCANNER_READY_TIMEOUT_SECONDS` for the new DB).

### Docker Hub 429 (rate limit)

Symptoms: `toomanyrequests` in mirror / scanner / provenance errors.

1. Configure `registryAuth.existingSecret` (any Docker Hub account raises the limit); above ~100
   images this is required.
2. `MIRROR_MODE=local` (default) pulls each digest once into the cache; daily rescans read the
   local layout. Check `posture_image_cache_bytes` against `IMAGE_CACHE_MAX_BYTES`: a cache that is
   too small evicts layouts and re-pulls.
3. Event scans (pod watcher) only scan new digests; a rollout of many new digests at once still
   pulls each of them once.

### Stuck scans and reports

- **Scan `running` forever**: the scan worker heartbeats `scans.heartbeat_at` every 3 s. A dead
  worker's scan is failed when the worker starts again. `DELETE /api/v1/scans/{id}` cancels a
  running scan; a `queued` scan with no worker means the scan worker is down (`kubectl get pods`).
- **Scan `scanned` forever**: the privileged worker (`--stages provenance,controls,reports`) is
  not running.
- **Report `queued` forever**: no report-worker (and `REPORT_WORKER_EMBEDDED=false`). Check
  `posture_queue_depth{kind="reports"}` and the report-worker pod.
- **Report `running` forever**: cannot happen any more: the lease (`REPORT_LEASE_SECONDS`, 120 s)
  expires when the report worker dies and the row is requeued (failed after
  `REPORT_MAX_ATTEMPTS`); a report running longer than `REPORT_TIMEOUT_SECONDS` (20 min) is killed
  and failed. Reports that keep timing out: generate a narrower scope (namespace / workload).

### Full volumes

- **Reports PVC**: retention keeps `REPORTS_RETENTION_PER_TYPE` (20) per type and at most
  `REPORTS_RETENTION_MAX_TOTAL_BYTES` (2 GiB) overall; lower them, or delete reports in the UI
  (each deletion is logged as `report.deleted`).
- **Worker cache PVC** (`/cache`): grype DB ~3 GB, trivy client cache ~1.5 GB, scanner output
  scratch (`/cache/tmp`), local image cache (`/cache/images`, LRU by `IMAGE_CACHE_MAX_BYTES`). Lower
  `IMAGE_CACHE_MAX_BYTES` or grow the PVC; leftover `/cache/images/.copy-*` directories of crashed
  copies are removed after 6 h.
- **Postgres**: `image_scans` / `scan_snapshots` / compat reports beyond `HISTORY_RETAIN_SCANS` (30)
  are pruned after every scan, raw scanner JSON after 14 days. `VACUUM FULL image_scans` returns
  the space to the OS after lowering the retention (locks the table; run between scans).
  hostpath provisioners do not enforce PVC sizes: watch node disk too.

### Restore from backup

1. Scale the api, workers and report-worker to 0.
2. Restore the dump into an empty database:
   `pg_restore -h <host> -U <user> -d posture --clean --if-exists <dump>` (the chart's backup
   CronJob writes custom-format dumps).
3. Start the api once: its migration step brings the schema to head (`alembic upgrade head` under
   an advisory lock), then scale the workers back up.
4. Reports are files on the reports PVC: rows whose file is missing answer 410 on download;
   regenerate them. Scans in `running`/`queued` at backup time are failed or picked up by the
   restarted workers.
