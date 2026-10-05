# nebari-security-posture — API + worker

Python 3.12 package `posture` (`src/posture/`) with two entrypoints:

| process | command | image |
|---|---|---|
| API (FastAPI, `/api/v1`) | `uvicorn posture.main:app --host 0.0.0.0 --port 8000` | `Dockerfile.api` |
| migrations | `python -m posture.migrate` (alembic upgrade head, retries until the DB is up) | api image |
| worker (inventory + scans + scheduler) | `python -m posture.worker` (health on `:9000/healthz`) | `Dockerfile.worker` |
| scap-worker (DESIGN §14, OpenSCAP) | `python -m posture.worker --stages scap` (root in its container in the chart) | `Dockerfile.worker` |

The contract is `../docs/DESIGN.md` §4–§6, §11, §12 (`../docs/PROVENANCE.md`), §14 (SCAP) and `../docs/SCORING.md`; deviations are in
`../docs/DECISIONS.md`.

## Run locally (no compose)

```bash
# 1. Postgres
docker run -d --name posture-pg -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=posture -e POSTGRES_PASSWORD=posture -e POSTGRES_DB=posture postgres:16-alpine

# 2. venv (uv or plain pip)
uv sync --extra dev            # or: python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'
export DATABASE_URL=postgresql://posture:posture@127.0.0.1:55432/posture
export AUTH_MODE=disabled POSTURE_DEV=1   # dev only: every request is admin; refused without POSTURE_DEV=1

# 3. schema + API
.venv/bin/python -m posture.migrate
.venv/bin/uvicorn --app-dir src posture.main:app --port 8000
curl -s localhost:8000/api/v1/summary   # empty/zero shapes before any scan

# 4. worker (needs trivy/grype/clairctl/skopeo on PATH, or run the worker image)
export KUBECONFIG=~/.kube-grace/config TRIVY_SERVER_URL=http://localhost:4954 CLAIR_URL=http://localhost:6060
export CACHE_DIR=$PWD/.cache MIRROR_ENABLED=false
.venv/bin/python -m posture.worker
curl -s -XPOST localhost:8000/api/v1/scans -H 'content-type: application/json' -d '{"namespaces":["default"]}'
```

Scanner backends for local runs: `docker run -p 4954:4954 aquasec/trivy:0.75.0 server --listen 0.0.0.0:4954`
and Clair 4.9.0 in combo mode (`CLAIR_MODE=combo`, a Postgres and a config with `updaters.sets`).

Images (build context `api/`):

```bash
docker build -f Dockerfile.api    -t security-posture-api:dev .
docker build -f Dockerfile.worker -t security-posture-worker:dev .
# both run as uid 10001 with a read-only root fs:
docker run --read-only -u 10001 --tmpfs /tmp -e DATABASE_URL=... security-posture-api:dev
docker run --read-only -u 10001 --tmpfs /tmp -v cache:/cache -e DATABASE_URL=... security-posture-worker:dev
```

## Tests

```bash
.venv/bin/python -m pytest -q                       # unit tests
TEST_DATABASE_URL=postgresql://posture:posture@127.0.0.1:55432/posture_test \
  .venv/bin/python -m pytest -q                     # + end-to-end (DROPS that DB's public schema)
```

Scanner parser fixtures in `tests/fixtures/` are trimmed real outputs (see the README there).
`tests/scap/` uses a hand-written 3-rule SCAP 1.3 datastream (`tests/scap/fixtures/`); its OpenSCAP
end-to-end test is skipped without `oscap` and runs in the worker image (as root, so the privileged
rootfs test runs too):

```bash
docker run --rm -u 0 -v "$PWD":/src:ro -w /src --entrypoint sh security-posture-worker:dev -c \
  'pip install -q --target /tmp/pt pytest==9.1.1 pytest-asyncio==1.4.0 &&
   PYTHONPATH=src:/tmp/pt python -m pytest -q -p no:cacheprovider tests/scap'
```
`tests/provenance/` runs the supply-chain checks against an in-memory registry / cosign fake
(`tests/provenance/fakes.py`), so no network is needed; its Postgres module
(`test_integration_provenance.py`) is also gated on `TEST_DATABASE_URL`.

## Environment

| var | default | used by | meaning |
|---|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://posture:posture@localhost:5432/posture` | both | `postgresql://` is rewritten to `+asyncpg` |
| `AUTH_MODE` | `oidc` | api | `disabled` = no auth (dev only; the API refuses to start unless `POSTURE_DEV=1`) |
| `POSTURE_DEV` | unset | api | `1` permits `AUTH_MODE=disabled`; never set in a cluster |
| `OIDC_JWKS_URL` | in-cluster Keycloak `.../realms/nebari/protocol/openid-connect/certs` | api | JWKS (cached 10 min, refetched on unknown `kid`) |
| `OIDC_ISSUERS` | empty | api | **required** with `AUTH_MODE=oidc`: comma list of accepted `iss`; empty = the API refuses to start |
| `OIDC_CLIENT_IDS` | empty | api | comma list; the chart sets the operator-provisioned client id `<namespace>-<fullname>`. A token is accepted when its `aud` contains, or its `azp` equals, one of `OIDC_CLIENT_IDS` ∪ `OIDC_AUDIENCES` ∪ `OIDC_AUDIENCE` |
| `OIDC_AUDIENCES` | empty | api | extra accepted audiences / authorized parties (comma list). All three empty = aud/azp not checked (warning logged at startup) |
| `OIDC_AUDIENCE` | unset | api | legacy single value, merged into the list above |
| `ADMIN_GROUPS` | `admin` | api | comma list; leading `/` stripped on both sides |
| `TRIVY_SERVER_URL` / `CLAIR_URL` | `http://trivy:4954` / `http://clair:6060` | worker | scanner backends |
| `TRIVY_ENABLED` / `GRYPE_ENABLED` / `CLAIR_ENABLED` | `true` | both | initial scanner toggles (then `PUT /settings`) |
| `MIRROR_ENABLED` | `true` | worker | skopeo-copy into the mirror before scanning |
| `MIRROR_REGISTRY` | `registry.container-registry.svc.cluster.local:5000` | worker | mirror registry |
| `MIRROR_INSECURE` | `true` | worker | mirror (and rewrite targets) are plain http |
| `MIRROR_REWRITE` | empty | worker | `src=dst,...`, e.g. `localhost:32000=registry.container-registry.svc.cluster.local:5000` |
| `MIRROR_ALL_PLATFORMS` | `false` | worker | `skopeo copy --all` |
| `REGISTRY_AUTH_FILE` / `DOCKER_CONFIG` | unset | worker | private registry creds (skopeo `--src-authfile`; scanners use `DOCKER_CONFIG`) |
| `SCAN_PARALLELISM` | `3` | both | images scanned concurrently (default for settings) |
| `SCAN_TIMEOUT_SECONDS` | `600` | worker | per scanner per image |
| `SCAN_INTERVAL_HOURS` | `6` | both | scheduled scans (default for settings) |
| `RESCAN_AFTER_HOURS` | `24` | both | skip digests scanned more recently unless `force` |
| `EXCLUDED_NAMESPACES` | empty | both | never inventoried |
| `GRYPE_DB_UPDATE_HOURS` | `12` | worker | `grype db update` interval |
| `SCAN_ON_START` | `true` | worker | enqueue a scan at startup if none ever completed |
| `WORKER_HEALTH_PORT` | `9000` | worker | `/healthz` (`lastHeartbeatAgeSeconds`) |
| `CACHE_DIR` | `/cache` (worker) `/tmp` (api) | worker | grype DB, trivy client cache, clairctl config, skopeo policy |
| `CLUSTER_NAME` | `nebari` | both | default `systemName` |
| `REPORTS_DIR` | `/data/reports` | both | report files `<id>.<ext>` (chart: PVC `persistence.reports`, shared by api + worker) |
| `REPORTS_KEEP_PER_TYPE` | `50` | both | retention: newest N finished reports per type |
| `REPORTS_AUTO_GENERATE` | empty | both | default for settings `reports.autoGenerate` (comma list of report types) |
| `LOG_LEVEL` | `INFO` | both | logs are `key=value` lines on stdout; tokens are never logged |
| `PROVENANCE_ENABLED` | `true` | both | supply-chain stage (DESIGN §12, `../docs/PROVENANCE.md`); default for settings `provenance.enabled` |
| `PROVENANCE_VERIFY_SIGNATURES` / `PROVENANCE_CHECK_SBOM` / `PROVENANCE_CHECK_PROVENANCE` / `PROVENANCE_CHECK_UPDATES` | `true` | both | per-check defaults (settings `provenance.*`) |
| `PROVENANCE_COSIGN_PUBLIC_KEY` | empty | both | PEM text, file path or KMS/remote URI for `cosign verify --key`; empty = existence check only |
| `PROVENANCE_COSIGN_CERTIFICATE_IDENTITY_REGEXP` / `..._OIDC_ISSUER_REGEXP` | empty | both | keyless verification (both required) |
| `PROVENANCE_UPDATE_LEVEL` / `PROVENANCE_SKIP_PRERELEASE` | `patch` / `true` | both | update check (provenance-collector-pack semantics) |
| `PROVENANCE_MAX_MAJOR_JUMP` | `50` | worker | update candidates more than this many majors above the current tag are ignored; `0` = off (docs/PROVENANCE.md) |
| `PROVENANCE_HELM_ENABLED` | `true` | both | Helm release discovery from `sh.helm.release.v1.*` Secrets (needs secrets list RBAC; chart default off) |
| `PROVENANCE_HELM_INDEX_TTL_HOURS` | `12` | Hours a cached chart-repo index / OCI tag list is reused before conditional revalidation (ETag / If-Modified-Since). |
| `PROVENANCE_HELM_CHART_REPOS` | empty | worker | `https://…` index.yaml repos / `oci://host/path` prefixes for chart update checks |
| `PROVENANCE_RECHECK_HOURS` | `24` | both | reuse a digest's signature/SBOM/provenance results |
| `PROVENANCE_CONCURRENCY` / `PROVENANCE_REGISTRY_TIMEOUT` | `8` / `30` | worker | registry concurrency / per-request timeout (s) |
| `PROVENANCE_COMPAT_INTERNAL_PORT` | unset | api | second listener serving only `/api/reports*`, `/api/export`, `/healthz` (Grafana); its read endpoints need `Authorization: Bearer <token>` |
| `PROVENANCE_COMPAT_TOKEN_FILE` / `PROVENANCE_COMPAT_TOKEN` | unset | api | bearer token for the internal listener (file = mounted Secret, re-read on change). With the port set and no token the API refuses to start |
| `PROVENANCE_COMPAT_ALLOW_ANONYMOUS` | `false` | api | `true` serves the internal listener without a token (old behaviour; explicit opt-out) |
| `PROVENANCE_TRUST_SETTINGS_LOCKED` | `false` (chart: `true`) | api | cosign key / keyless identity + issuer come only from `PROVENANCE_COSIGN_*`; `PUT /settings` answers 403 when asked to change them |
| `PROVENANCE_REGISTRY_AUTH_REALMS` | empty | worker | extra token-realm hosts the registry client may call (default: the registry host, its parent domain, `auth.docker.io`) |
| `PROVENANCE_HELM_MAX_RELEASE_BYTES` | `16777216` | worker | decompressed Helm release payload cap (larger releases are reported as corrupt) |
| `KEYCLOAK_CLIENT_ID` / `KEYCLOAK_CLIENT_SECRET` (or `KEYCLOAK_CLIENT_SECRET_FILE`) | unset | worker | controls engine: dedicated view-only client (`client_credentials`); when set the Keycloak admin Secret is not read |
| `KEYCLOAK_ALLOW_MASTER_FALLBACK` | `false` | worker | controls engine: with no pinned admin realm, also try the admin login against `master` |
| `SCANNERS_SCAP_ENABLED` | `false` | both | default for settings `scanners.scap` (SCAP scanner, DESIGN §14) |
| `SCAP_EMBEDDED` | `false` | worker | run the scap stage inside the scan worker instead of queueing it for `--stages scap` (dev; non-root -> `rootfsFidelity: degraded`) |
| `SCAP_CONTENT_DIR` / `SCAP_WORK_DIR` | `CACHE_DIR/scap-content` / `CACHE_DIR/scap` | worker | datastreams (+ `index.json`, rule cache) / rootfs + oscap scratch |
| `SCAP_CONTENT_SOURCES` | pinned SSG 0.1.82 zip | both | JSON `[{name, kind: ssg\|disa\|custom, url, sha256, include[]}]`; default for settings `scap.sources` |
| `SCAP_DISA_URLS` | `[]` | both | JSON `[{url, sha256, name?, include?}]` (kind disa) appended to the sources |
| `SCAP_CONTENT_OFFLINE` / `SCAP_CONTENT_REFRESH_HOURS` | `false` / `24` | worker | air-gapped (index only) / refresh interval |
| `SCAP_PREFER_DISA` / `SCAP_TIMEOUT_SECONDS` | `true` / `900` | both | defaults for settings `scap.preferDisa` / `scap.timeoutSeconds` (per image) |
| `SCAP_MAX_ROOTFS_GB` | `10` | worker | uncompressed rootfs cap |
| `SCAP_FINALIZE_WAIT_SECONDS` | `0` | worker | privileged worker waits this long for a queued / running scap stage before the posture snapshot; `0` = finalize at once with `scapPending`, re-aggregate and run the deferred auto-reports / controls when the stage completes (`scap_completed`) |
| `SCAP_PARALLELISM` / `SCAP_MEMORY_PER_EVAL_MB` | `3` / `1152` | worker | images evaluated concurrently by the scap stage, capped by the cgroup memory limit at `(limit - 384 MiB) / SCAP_MEMORY_PER_EVAL_MB` |
| `SCAP_DEFERRED_MAX_HOURS` | `12` | worker | a scap-pending scan whose stage is still queued / running after this long runs its deferred stages anyway |
| `SCAP_SKIP_VALIDATION` | `false` | worker | `oscap --skip-valid` |
| `SCAP_BENCHMARKS_FILE` | empty | worker | extra os-release / product -> benchmark candidates (`scap/data/benchmarks.yaml` format) |
| `OSCAP_BIN` / `OSCAP_CHROOT_BIN` | `oscap` / `oscap-chroot` | worker | OpenSCAP binaries (worker image: openscap-scanner 1.3.7) |
| `COSIGN_BIN` | `cosign` | worker | cosign binary (pinned v3.1.3 in the worker image; TUF cache `TUF_ROOT=/cache/sigstore`) |

## Module map (`src/posture/`)

| module | role |
|---|---|
| `config.py` | pydantic-settings for the env vars above |
| `app_settings.py` | editable settings (single `settings` row) over env defaults: interval, rescan, exclusions, scanner toggles, parallelism, `systemName`, `organization`, `remediationSlaDays`, `reports.autoGenerate` |
| `main.py` | FastAPI app, `/api/v1` routers, admin-gated `/api/v1/openapi.json` + `/api/v1/docs`, access log; provenance-collector-pack aliases outside `/api/v1` and the optional compat listener |
| `auth.py` | Bearer / `NebariIdToken` / `IdToken*` cookie → JWKS-verified JWT → issuer check → groups → admin |
| `routers/` | `health`, `me`, `summary`, `images`, `vulnerabilities`, `workloads` (+`/namespaces`), `checks`, `scans`, `scanners`, `settings`, `export`, `compliance` (`/compliance/controls`), `reports` (`/reports*`, `/compliance/stig`), `supply_chain` (`/supply-chain`, `/helm-releases`), `provenance_compat` (`/api/reports*`, `/api/export`, `/api/me`, `/api/scan`, `/healthz`) |
| `report_jobs.py` | report rows, generation off the event loop (`asyncio.to_thread(registry.generate)`), files under `REPORTS_DIR`, retention; used by the API background task and the worker's `reports.autoGenerate` |
| `views.py` | shared queries and camelCase JSON shapes |
| `db/` | SQLAlchemy 2 async models + engine; `alembic/` migrations (`0001` initial, `0002_provenance`) |
| `migrate.py` | `python -m posture.migrate` |
| `inventory.py` / `inventory_model.py` | K8s API inventory: pods (containers/init/ephemeral), owner chain (RS→Deployment, Job→CronJob), NebariApp mapping, securityContext snapshot, NetworkPolicies |
| `images.py` | image ref parsing, `imageID` normalization (`docker-pullable://`, bare `sha256:`), unique image key, rewrite map, mirror target |
| `mirror.py` | skopeo copy (`--digestfile`) to `<mirror>/posture-mirror/<registry>/<repo>:sha256-<hex>`; scanners pull `…@<copied digest>`; a cached copy is reused only when its digest matches the source (`mirrorDigestVerified`); fallback to the original ref |
| `scanners/` | `trivy.py` (`trivy image --server`), `grype.py` (local DB on PVC), `clair.py` (`clairctl report --out json`, generated clairctl config) → `ScanResult`; `base.run_proc`: allowlisted env, stdin `/dev/null`, own process group (SIGTERM, SIGKILL after 10 s on timeout or cancel), JSON streamed to `CACHE_DIR/tmp` and parsed from the file |
| `correlate.py` / `analysis.py` | consensus per `(vulnId, package)`, agreement, max severity, per-image score |
| `scoring.py` | SCORING.md formulas (pure) |
| `posture_checks.py` | the 16 SCORING.md checks (pure), kube-system ×0.5 |
| `aggregate.py` | workload / namespace / cluster scores |
| `controls.py` + `reports/data/controls.yaml` | NIST 800-53 tagging |
| `reports/models.py`, `reports/snapshot.py` | `ReportSnapshot` + `build_snapshot(session, scan_id, scope)` for report generators |
| `provenance/` | DESIGN §12: `registry` (async OCI client), `checks` (cosign / referrers / BuildKit / legacy-tag signature, SBOM, SLSA), `updates` (Masterminds-compatible semver update check), `helm` (release Secrets, chart updates), `stage` (worker stage, cache, persistence), `report` (their report JSON / CSV / Markdown), `scoring` (supply-chain score, controls), `models` (`image_provenance`, `helm_releases`, `images.provenance`) |
| `scap/` | DESIGN §14: `rootfs` (OCI layers -> rootfs, whiteouts, confinement, fidelity), `detect` (os-release, products -> `data/benchmarks.yaml` candidates), `content` (sha256-pinned sources, datastream index, rule metadata), `oscap` (oscap-chroot adapter, ARF parser), `scoring` (STIG score, configuration score), `stage` (worker stage + persistence), `models` (`scap_content`, `scap_image_summary`, `scap_results`, `images.stig`) |
| `routers/stig.py` | `/images/{id}/stig`, `/stig/benchmarks`, `/stig/benchmarks/{id}/rules`, `/summary.stig`, the `product` section of `/compliance/stig`, the `scap` scanner entry |
| `worker.py` | Postgres queue (`FOR UPDATE SKIP LOCKED`), APScheduler jobs, scan pipeline (provenance stage concurrent with scanning), health server |

## Limitations (v0.1)

* `imagePullSecrets` are not discovered; private registries need `REGISTRY_AUTH_FILE` (also used by the provenance checks; anonymous Docker Hub access is rate limited - rate-limited images are reported as errors and scored as unknown).
* Images whose `imageID` is a bare config digest (locally loaded) are scanned by tag.
* `no-netpol` is skipped (not failed) when NetworkPolicies cannot be listed (RBAC).
* List endpoints filter/sort in memory (fine for hundreds of images; not for tens of thousands).
