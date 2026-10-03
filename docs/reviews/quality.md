# Test/quality review: `security-posture-merge` (provenance-collector-pack)

Reviewed at `e86c9af`. Every number below was measured on 2026-10-03. I ran everything in docker or on scratch copies, and the tracked tree is unchanged (`git status` is clean).

Environments: Go ran in `golang:1.26` with `-race -covermode=atomic`. Python ran in `python:3.12-slim` (the same version as CI) plus the weasyprint libs, against `postgres:16-alpine`, with `CONTROLS_ENGINE_ENABLED=false`. UI ran in `node:22-alpine` with vitest 4.1.11 and `@vitest/coverage-v8@4.1.11`, installed only in the scratch copy.

## Summary table

| | Go `collector/` | Python `api/` (no DB) | Python `api/` (`TEST_DATABASE_URL`) | UI `ui/` |
|---|---|---|---|---|
| Tests | 117 `Test*` funcs, 9 pkgs, all pass | 512 pass, 26 skipped | **538 pass** | 59 (6 files) |
| Coverage (lines/stmts) | **58.5 %** total (686/1177 stmts); `internal/*` 73.4 % | **73.6 %** (6622/8995) | **85.9 %** (7723/8995); **84 %** line+branch | **67.2 % lines / 65.6 % stmts / 56.7 % branches / 56.1 % funcs**; app code without mocks and the ui-kit: 66.0 % lines, 56.8 % branches |
| Gated in CI? | No (only uploads `coverage.out` as an artifact) | No | No | Coverage not even run |
| Race detector | Yes, in CI | n/a | n/a | n/a |
| Lint in CI | golangci-lint, vet, configspec drift | **None** (ruff finds 5 issues with its default rules) | | eslint + tsc |
| Determinism | `-count=3 -shuffle=on` passes **offline** (`--network none`) | 3 random-order runs pass | 2 in-order runs pass. Random order: **11 and 15 failures** (the scenario modules depend on test order) | 3/3 plain runs pass. **Under coverage: 3/3 runs fail** (5 s timeout) |
| Hits the network | `TestCosignVerifier_*` call `docker.io/library/nginx:latest` | No | No | No (MSW `onUnhandledRequest: 'error'`) |
| Wall time | ~25 s (race, cold cache) | 25 s (63 s with cov) | 42 s (79 s with cov) | 22 s (32 s with cov) |

### Recommended gates, starting at today's floor and then ratcheting

| | Gate now | Target in 1-2 releases |
|---|---|---|
| Go | total ≥ 58 %, `internal/...` ≥ 73 % | `internal/...` ≥ 80 %, `verify`/`registry`/`discovery` ≥ 75 % each |
| Python (with PG) | `--cov-fail-under=85` | 90 % line+branch; per-module floor ≥ 95 % for `scoring`, `correlate`, `severity`, `auth`, `posture_checks`, `scanners/*`; `inventory.py` ≥ 80 % |
| UI | lines 65 / branches 55 / funcs 55 | lines 75 / branches 65; `src/lib/**` ≥ 90 % |

---

## Findings

### Blocker

**B1. CI cannot block a merge.** The upstream `nebari-dev/provenance-collector-pack` `main` ruleset contains only `deletion` and `non_fast_forward` rules (`gh api repos/nebari-dev/provenance-collector-pack/rules/branches/main`), and no required status checks are visible. The fork's `main` is unprotected. A red `Test`, `Lint` or `Integration Test` run is therefore advisory only.
- **Fix:** add a ruleset with required checks `collector (go test)`, `api (pytest)`, `ui (vitest + build)`, `go-lint`, `chart`, `ui-lint`, `shell`, plus the new jobs proposed below. `Integration Test` is path-filtered, so either make it always report or use a `paths-filter` "gate" job that is the required check.

**B2. The Kubernetes → `ContainerRecord` adapter is untested: `inventory.py` has 16.5 % coverage (116 of 139 statements missed).** Every posture check, workload score and STIG/SAR row is computed from this adapter's output. The uncovered code includes `build_containers` (init/ephemeral container walk, `ephemeralContainerStatuses`), `resolve_owner` (Pod→ReplicaSet→Deployment, Job→CronJob), `map_pack`, `_security_snapshot`, `parse_nebariapps` and `collect_sync`.
- `test_posture_checks.py` only feeds hand-built `ContainerRecord`s.
- Odd pod specs never go through the real code path: missing `securityContext`, init-sidecar `restartPolicy: Always`, ephemeral debug containers, pods without owners, Windows pods.
- **Windows:** `_security_snapshot` drops `spec.os`. Windows pods therefore produce false *fails* for `run-as-root`, `seccomp-unconfined` and `writable-rootfs`. `windowsOptions.hostProcess: true`, the Windows equivalent of privileged, is never flagged.
- **Fix:** add a table-driven test that feeds raw pod/RS/Job dicts (the shapes `kubectl get -o json` returns) through `build_containers` + `evaluate_inventory`. Effort: S.

### Major

**M1. The "hard timeout" on scanner/collector subprocesses is not hard.** `scanners/base.py:run_proc` calls `proc.kill()` and then an **unbounded** `await proc.communicate()`. If any child process still holds stdout/stderr, the call blocks until that child exits.
- Measured: `test_scanner_error_and_timeout` uses `timeout=0.5` with a script running `sleep 5` and takes **5.01 s**. `test_run_collector_errors` (`timeout=0.2`) takes **5.02 s**.
- Both tests still pass because they never assert elapsed time, so they cannot catch this bug.
- **Fix:** use `start_new_session=True` + `os.killpg`, and wrap the post-kill `communicate()` in `wait_for(..., 5)`. Add `assert r.duration_ms < 2000` to both tests.

**M2. Alembic autogenerate would drop two production tables.** `alembic/env.py` imports `posture.db.models` and `posture.controls_engine.models`, but **not** `posture.provenance.models`.
- `alembic check` against a migrated DB reports `remove_table image_provenance` and `remove_table helm_releases`, plus their indexes.
- With the import added, the check reports "No new upgrade operations detected".
- The next `alembic revision --autogenerate` would emit `DROP TABLE` for both.
- Up/down/up (`head → base → head → -1 → head`) works on PG16.
- **Fix:** add the import, and add a CI test that runs `upgrade head` → `alembic check` → `downgrade base` → `upgrade head`. Effort: XS.

**M3. Integration tests are order-coupled scenarios.** `test_integration.py`, `test_reports_api.py`, `provenance/test_integration_provenance.py` and `controls_engine/test_api_integration.py` are numbered `test_01…test_07` and share DB state. Under `pytest-randomly` they fail: 11 failures with one seed, 15 with another. Unit tests are clean: 3 random seeds, 0 failures.
- This is acceptable as a design choice, but it is undocumented and fragile: running one test with `-k test_05` fails.
- **Fix:** either fold each module into a single scenario test with `step()` sub-asserts, or give each test its own fixture-built state. At minimum, document the constraint and add `-p no:randomly` to the pytest config.

**M4. The UI suite fails under coverage instrumentation.** `app.test.tsx › Images › lists images…` takes 4.0–4.1 s against vitest's 5 s default. With v8 coverage it takes 5.3 s and **fails on 3/3 runs**, at low load as well. Turning on a coverage gate will turn CI red on day one.
- **Fix:** set `test.testTimeout: 15000`, and replace `user.type(…, 'keycloak')` with `user.type` on a debounced input plus `{ delay: null }` or `fireEvent.change`.
- `findings-table.test.tsx` tests also take 1.5–2.7 s each.

**M5. The UI has no error boundary, and malformed API data blanks the whole app.** No route defines `errorElement`. I probed each of 16 routes with every GET returning `{}`, `[]`, `null` and `{items:null}`. **25 of 64 combinations** fell through to React Router's "Unexpected Application Error" screen, with errors such as `reading 'trivy'`, `'passed'`, `'length'`, `'filter'`, `'includes'` and `'toLocaleString'`.
- Affected routes: `/`, `/images`, `/images/:id`, `/vulnerabilities`, `/vulnerabilities/:id`, `/checks/:id`, `/supply-chain`, `/settings`, and `/scans/:id` on `null`.
- Contract-violating responses are not the normal case. They do happen in practice during rolling upgrades (new UI, old API), and in mock mode.
- **Fix:** add `errorElement` at `/` and per page, and zod/valibot parsing (or `?? []` defaults) in `api/queries.ts`. Add the probe as a permanent `describe.each(ROUTES)` smoke test (about 40 lines).

**M6. Ten pages have no tests.** UI coverage is 47 % for `src/pages`, and every page below ~10 % has no test touching its route:

| Page | Coverage |
|---|---|
| `checks.tsx` | 6 % |
| `check-detail.tsx` | 6 % |
| `namespaces.tsx` | 5 % |
| `scans.tsx` | 5 % |
| `scan-detail.tsx` | 0 % |
| `workloads.tsx` | 4 % |
| `vulnerabilities.tsx` | 11 % |
| `vulnerability-detail.tsx` | 0 % |
| `not-found.tsx` | 0 % |

Components:

| Component | Coverage |
|---|---|
| `scan-control.tsx` (the "Scan now" admin action) | 34 % |
| `tag-input.tsx` (settings) | 20 % |
| `ui/dialog.tsx` | 21 % |
| `ui/toast.tsx` | 24 % |
| `ui/field.tsx` | 0 % |
| `ui/textarea.tsx` | 0 % |

`settings.tsx` is at 48 %. `mocks/handlers.ts` is at 36 %, which means most of mock mode (`dev:mock`, used for screenshots) is never exercised.

**M7. API routers are the least-tested Python layer:** 60.6 % with DB, 42.9 % without. Per module (with DB): `supply_chain` 34 %, `summary` 40 %, `compliance` 42 %, `workloads` 45 %, `scans` 49 %, `images` 50 %, `controls` 51 %, `export` 57 %, `checks` 61 %. Filters, pagination, sorting, 404s and query-param validation are mostly unasserted.
- Auth is applied per router group (`dependencies=[Depends(require_admin)]`), which is the right pattern. I checked the OpenAPI route table: of 46 operations, all return 401 unauthenticated and 403 for non-admins, except the intended public ones: `/health`, `/ready`, `/healthz`, `/api/v1/me`, `/api/me`, and `/api/scan`, which is CSRF-gated.
- Nothing locks this in. Add that route-table test (about 25 lines) so a new router mounted on the wrong group fails CI.

**M8. JWT negative cases are handled correctly but mostly untested, and one path returns 500.** Tested today: forged key, expired, bad issuer, `alg=none`, missing token, non-admin 403, key rotation.
- I probed the rest, and all return 401 correctly: `aud` missing/wrong (with `OIDC_AUDIENCE` set), no `exp`, no `iss`, future `nbf`, HS256 alg-confusion signed with the RSA modulus, JWKS HTTP 500. None of these is in the suite.
- **Bug:** a JWKS endpoint that returns 200 with a non-JSON body (an HTML error page from a proxy or Keycloak) raises an unhandled `JSONDecodeError`, so the request gets a 500 instead of a 401. It still fails closed, but it is noisy. Catch `ValueError` in `JWKSCache._fetch`.
- Not covered: the refetch throttle (`REFETCH_MIN_INTERVAL`) against random-`kid` floods, and `groups` given as a string (it is accepted).

**M9. Collector ↔ API contract skew is untested.**
- `tests/fixtures/provenance-collector-report.json` is **hand-written**. It was not produced by the Go collector.
- The report has no schema version: only `collectorVersion`, which is informational.
- `test_run_collector_subprocess` mimics the Go CLI (`--once --output`) with a shell script, so a renamed Go flag or JSON field passes every unit test. It would only be caught by `test-integration.yaml`, which is path-filtered and slow.
- The Python provenance engine (`provenance/checks.py`) is a *port* of `collector/internal/verify`, and the two have no differential test.
- **Fix:** add a Go test that writes a golden `report.json` from `report.Generator` with fakes, check it in, and have pytest parse that exact file. A `go test ./... -run Golden -update` step keeps it honest. Add `metadata.schemaVersion` and have `stage.py` reject or warn on unknown majors.

**M10. Go: the security-relevant happy paths have no coverage.**

| Package | Coverage |
|---|---|
| `internal/registry` | 34 % |
| `internal/discovery` | 37 % |
| `internal/verify` | 74 % |
| `cmd/provenance-collector` | 23 % (`run`, the orchestration path, at 0 %) |

- Exported functions at 0 %: `registry.NewDigestResolver`/`Resolve`, `registry.(*RegistryUpdateChecker).Check`, `discovery.NewHelmDiscoverer`/`Discover` (plus `listReleasesInNamespace`, `resolveNamespaces`, and the `ToRESTConfig`/`ToDiscoveryClient`/`ToRESTMapper`/`ToRawKubeConfigLoader` getters), `configspec.Names`, `verify.checkExistence`, and all of `cmd/dashboard` (`buildScanRunner`, `parseManualJobTTL`, `parseDuration`, `parseBool`, `parseBytes`, `splitAndTrim`).
- **No test verifies a correctly signed image** (`Signed=true, Verified=true`). The cosign tests only exercise key-loading errors. Three of them call **`docker.io/library/nginx:latest`** over the real network, which takes 4.2 s offline vs 0.6 s online and can be rate-limited.
- `ggcr`'s `pkg/registry` already provides an in-memory registry (it is used elsewhere: 100 `httptest`/registry references). Sign a test image with an ephemeral key and verify it there.
- Ephemeral containers are ignored by `discovery/images.go`; it only walks init and regular statuses. Debug-container images are invisible to the collector, but the Python inventory sees them.

**M11. Report generators scale poorly, with no budget or timeout.** Runs on `python:3.12-slim`; timings under `tracemalloc` are inflated about 2–4× but are comparable to each other:

| Snapshot | Measurement |
|---|---|
| Empty | All 14 type×format combinations succeed (only STIG and OSCAL have empty-snapshot tests today) |
| 125 images / 700 findings, no tracemalloc | SAR PDF **32.5 s**, POA&M xlsx 2.1 s, SAR HTML 0.1 s |
| 2 500 images / 70 000 findings, with tracemalloc | SAR PDF **631 s, 715 MB peak**; POA&M xlsx 214 s, 540 MB; OSCAL-AR json **195 MB output, 1.26 GB peak**; vuln-export json 79 MB, 563 MB peak |

- Generation runs in `asyncio.to_thread` with no timeout or size cap, inside the API pod. One SAR PDF on a large cluster can pin a core for minutes and OOM a 1 GiB-limited pod.
- **Fix:** add a perf smoke test (e.g. 500 images / 5k findings, fail if SAR PDF > 30 s), paginate or truncate the SAR finding tables, stream xlsx (`write_only=True`), add a job timeout, and document size limits.

**M12. Integration CI does not test the shipping configuration.** `.github/argo-apps/provenance-collector.yaml` turns off auth (`mode: disabled`), Clair, the mirror, signature verification, update checks, the controls engine, NetworkPolicy and NebariApp.
- As a result, three-scanner consensus, OIDC, NetworkPolicy egress and the mirror path never run end to end.
- The test asserts only `status == done` and that the collector log line exists. It does not check findings > 0, score/grade presence, UI 200, report generation or a chart upgrade from the previous release.

**M13. No scan of the pack's own images.** This is a security-posture pack, yet `build-image.yaml` builds, SBOMs and signs its images but never scans them with trivy/grype, and never runs container-structure tests (uid 10001, read-only root, scanner binaries present at pinned versions). The build also has no `cache-from: type=gha`.

### Minor

- **m1. Python lint is absent from CI.** `ruff check` with the default rules finds 5 issues: unused imports in `controls_engine/engine.py:282` and `provenance/models.py:13`, `E741` in `provenance/checks.py:275`, and `F841` in `tests/provenance/test_stage.py:30` (`tags` assigned but never used, a dead fixture). `ASYNC230` flags a blocking `open()` in an async function at `provenance/collector.py:150`. No mypy/pyright.
- **m2. `actions/setup-python@v6` is not SHA-pinned** in `test.yaml`; every other action is. There is no pip cache, and only Python 3.12 is tested, while `requires-python >=3.12` (3.13 and 3.14 are untested).
- **m3. Dependabot gaps.**
  - `pip` on `/api` updates `pyproject.toml` pins, but `uv.lock` exists and is used by neither CI nor the Dockerfiles, so it drifts. Switch to `package-ecosystem: uv` or delete the lock.
  - There is no `docker` ecosystem, so `python:`, `golang:` and `nginx` base images and the `TRIVY_/GRYPE_/CLAIRCTL_/COSIGN_VERSION` ARGs are never bumped. The chart's `aquasec/trivy` and `clair` tags aren't bumped either.
  - CI does not install from a lock, so transitive dependencies float.
- **m4. Scanner fixtures match the pinned versions today** (trivy 0.75.0, grype 0.120.0, clairctl 4.9.0, alpine:3.17.0 only). Gaps:
  - Nothing ties them together. Add a test that parses `Dockerfile.worker`'s ARGs and asserts they equal the versions in `fixtures/README.md` / the fixtures' own `Trivy.Version` / `descriptor.version`, so a scanner bump forces a fixture refresh.
  - The fixtures cover a single OS family, with no language-ecosystem (pypi/npm/gomod) findings.
  - There are no "zero findings" or "unsupported OS" fixtures.
  - The Clair `enrichments` block is hand-edited.
- **m5. Consensus/scoring edge cases** (probed; behaviour mostly sensible but untested):
  - `GHSA-…` vs `CVE-…` aliases for the same issue are never merged: trivy reporting GHSA while grype reports CVE gives two findings at 0.5 agreement each. Upper-casing GHSA IDs also changes their canonical form.
  - `normalize_package("a_")` → `"a-"`, which is not equal to `"a"`.
  - A finding from a scanner *not* in `succeeded` still counts toward agreement (0.5).
  - `finding_penalty` silently treats non-normalized severities (`"CRITICAL"`) as `unknown` (0.05 instead of 10.0). The parsers normalize today, but there is no guard.
  - Debian `unimportant` maps to `unknown` rather than `negligible`.
  - 0 scanners → `score None`/`?` and 1 scanner → `confidence low` are correct and tested.
  - The UI's `lib/scoring.ts` duplicates `scoring.py`. Share golden vectors (one JSON file read by both pytest and vitest).
- **m6. Timing-sensitive tests:**
  - Go `TestUserInfo_Cached` asserts 3 calls happen within a 50 ms TTL, then sleeps 80 ms. That is flaky on a loaded `-race` runner.
  - `test_internal_listener_starts_only_when_configured` binds port 0, releases it and re-binds (TOCTOU).
  - `controls_engine/fakes.py` freezes `NOW = datetime.now(UTC)` at import time.
- **m7. The test data carries real lab identifiers:** `security.100-89-230-107.sslip.io` (a Tailscale CGNAT address), `192.168.42.150` and a personal name in `tests/reports/conftest.py`, `test_stig.py` and `test_images.py`. Use `example.org` / RFC 5737 addresses.
- **m8. The report test factory can hide model drift.** `make_snapshot()` silently falls back to a stub model if the real `ReportSnapshot` rejects the data. `test_contract.py` mitigates this; make the fallback raise instead.
- **m9. Two Go tests assert private fields** (`TestNewUpdateChecker_*` read `rc.updateLevel` / `rc.skipPrerelease`), which is implementation-coupled. Assert via `Check()` behaviour instead.
- **m10. Chart:** `helm lint` passes (31 objects at defaults). There is no `values.schema.json`, no `helm unittest` suite and no `templates/tests/` hook, and kubeconform runs with `-ignore-missing-schemas` (which skips NebariApp/SecurityPolicy CRDs). The values-compat step is good, but it is grep-based.

---

## Test-quality audit (samples)

| Test | Verdict |
|---|---|
| **Python** | |
| `test_scoring.py` worked examples | Behaviour; mirrors SCORING.md. Good. |
| `test_correlate.py` | Behaviour; misses alias, normalization-edge and foreign-scanner cases (m5). |
| `test_auth.py` | Behaviour over real HTTP with a mock JWKS transport. Good; gaps in M8. |
| `test_posture_checks.py` | Behaviour, but on synthetic records only (B2). |
| `controls_engine/test_assertions.py` | **Excellent:** mutation-style. Every assertion gets pass, then one targeted mutation → fail, then missing evidence → unknown. |
| `test_integration.py` | Realistic: real parsers + real fixtures + Postgres + migrations, with fake scanners, mirror and inventory. Order-coupled (M3). |
| `test_worker_readiness.py` | Partly implementation: monkeypatches `asyncio.sleep` and asserts log text. |
| `provenance/test_stage.py` | Behaviour against `FakeRegistry`/`FakeCosign`; asserts exact score arithmetic. Good. |
| `provenance/test_collector.py::test_run_collector_subprocess` | Contract mimicry via a shell script; cannot detect Go drift (M9). |
| `test_scanners.py::test_scanner_error_and_timeout` | Weak: passes despite the 10× timeout overrun (M1). |
| **Go** | |
| `TestImageDiscovery` | Behaviour against a fake clientset, including init containers. Good. |
| `TestPVCWriter_Retention` | Behaviour on a tmpdir with relative `time.Now()`. Fine. |
| `TestCosignVerifier_WithKey_ValidKeyLoading` | Hits Docker Hub. Can only fail if the error string starts with a key-loading prefix, so it is near-tautological for the verify path. |
| `TestNewUpdateChecker_DefaultLevel` | Implementation (private fields). |
| `TestUserInfo_Cached` | Behaviour but timing-sensitive (m6). |
| **UI** | |
| `lib/scoring.test.ts` | Behaviour; SCORING.md worked examples. |
| `family-rollup.test.tsx` | Accessible-role queries; includes a partial-API-row defensive case. Good. |
| `findings-table.test.tsx` | Behaviour (pagination, sort, filter); slow (1.5–2.7 s per test). |
| `app.test.tsx` Auth states | MSW 401/403 → correct screens. Good. |
| `app.test.tsx` Images | Behaviour; close to the timeout (M4). |

No assertion-free tests were found: I scanned all Go and Python tests for bodies without `t.Error`/`t.Fatal`/`assert`/`raises`. No test reads `~/.kube-grace`, `KUBECONFIG`, or contacts the cluster. The only real network calls are the three Go cosign tests. `sslip.io` appears only as string data.

---

## CI/workflow audit

| | Go | Python | UI | Chart | Images |
|---|---|---|---|---|---|
| Lint | golangci-lint v2.11.4 + vet + drift checks | **none** | eslint + tsc | helm lint ×4 + kubeconform | n/a |
| Unit | `go test -race` | pytest + PG service | vitest | n/a | n/a |
| Coverage | artifact upload only (PRs), no gate | **none** | **none** | n/a | n/a |
| Caching | setup-go | **none** (no pip cache) | npm | n/a | **no buildx cache** |
| Matrix | 1 Go | 1 Python (3.12) | Node 22 | n/a | 4 images, amd64 only |
| Security scan of own code/images | none (no govulncheck) | none (no pip-audit) | none (no npm audit) | n/a | **none** |
| E2E | `test-integration.yaml`: kind sandbox, reduced config (M12) | | none (no Playwright) | | |

### Snippets to add

**Go: coverage gate, govulncheck, golden contract.**
```yaml
      - name: Run tests
        run: go test -race -covermode=atomic -coverprofile=coverage.out ./...
      - name: Coverage gate
        run: |
          grep -v -E '/(hack|cmd/dashboard)/' coverage.out > cov.internal.out
          total=$(go tool cover -func=cov.internal.out | awk '/^total:/ {sub("%","",$3); print $3}')
          echo "coverage: ${total}%"; echo "### Go coverage: ${total}%" >> "$GITHUB_STEP_SUMMARY"
          awk -v t="$total" 'BEGIN { exit (t+0 < 70) }'   # ratchet: 70 -> 80
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

**Python: lint, coverage gate, migrations check, cache, matrix.**
```yaml
  api:
    strategy: { matrix: { python: ["3.12", "3.13"] } }
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-python@<sha> # v6
        with: { python-version: "${{ matrix.python }}", cache: pip, cache-dependency-path: api/pyproject.toml }
      - run: pip install -e '.[dev]' pytest-cov ruff pip-audit
      - run: ruff check src tests && ruff format --check src tests
      - run: pip-audit --skip-editable
      - name: Migrations round-trip + model drift
        env: { DATABASE_URL: "${{ env.TEST_DATABASE_URL }}" }
        run: |
          python -m alembic -c alembic.ini upgrade head
          python -m alembic -c alembic.ini check
          python -m alembic -c alembic.ini downgrade base
          python -m alembic -c alembic.ini upgrade head
      - name: Test
        run: pytest -q -p no:randomly --cov=posture --cov-branch --cov-report=xml --cov-report=term-missing:skip-covered --cov-fail-under=85
      - uses: codecov/codecov-action@<sha> # or actions/upload-artifact
        with: { files: api/coverage.xml, flags: api }
```

**UI: `vite.config.ts` thresholds and timeout.**
```ts
  test: {
    environment: 'jsdom', globals: true, setupFiles: ['./src/test/setup.ts'], css: false,
    testTimeout: 15000,
    coverage: {
      provider: 'v8', include: ['src/**'], exclude: ['src/mocks/**', 'src/test/**', 'src/main.tsx', 'src/**/*.test.*'],
      reporter: ['text-summary', 'lcov', 'json-summary'],
      thresholds: { lines: 65, statements: 64, branches: 55, functions: 55, 'src/lib/**': { lines: 90, branches: 80 } },
    },
  },
```
```yaml
      - run: npm i -D @vitest/coverage-v8@4.1.11   # commit to devDependencies
      - run: npx vitest run --coverage
```

**UI: Playwright e2e against mock mode** (the image `mcr.microsoft.com/playwright:v1.63.0-noble` is already local).
```yaml
  ui-e2e:
    runs-on: ubuntu-latest
    container: mcr.microsoft.com/playwright:v1.63.0-noble
    defaults: { run: { working-directory: ui } }
    steps:
      - uses: actions/checkout@<sha>
      - run: npm ci && npm run build:mock
      - run: npx vite preview --port 4173 & npx wait-on http://localhost:4173
      - run: npx playwright test   # one spec per route: loads, no console errors, axe-core a11y scan
      - uses: actions/upload-artifact@<sha>
        if: failure()
        with: { name: playwright-report, path: ui/playwright-report }
```

**Chart: helm-unittest + schema.**
```yaml
      - run: helm plugin install https://github.com/helm-unittest/helm-unittest --version v1.0.3
      - run: helm unittest chart/       # chart/tests/*_test.yaml: securityContext, netpol egress, auth env, compat aliases
      - run: |                          # CRD schemas instead of -ignore-missing-schemas
          kubeconform -strict -summary \
            -schema-location default \
            -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' /tmp/enabled.yaml
```
Also add `chart/values.schema.json`, so that `helm lint` rejects typos.

**Images: scan + structure tests + cache** (in `build-image.yaml`, after the build, on PRs too).
```yaml
      - uses: docker/build-push-action@<sha>
        with: { ..., load: ${{ env.PUSH != 'true' }}, cache-from: "type=gha,scope=${{ matrix.name }}", cache-to: "type=gha,mode=max,scope=${{ matrix.name }}" }
      - uses: aquasecurity/trivy-action@<sha>
        with:
          image-ref: ${{ steps.meta.outputs.tags }}   # first tag
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: "1"
          format: sarif
          output: trivy-${{ matrix.name }}.sarif
      - uses: github/codeql-action/upload-sarif@<sha>
        with: { sarif_file: trivy-${{ matrix.name }}.sarif, category: image-${{ matrix.name }} }
      - name: container-structure-test
        run: |
          curl -sLo cst https://github.com/GoogleContainerTools/container-structure-test/releases/download/v1.19.3/container-structure-test-linux-amd64 && chmod +x cst
          ./cst test --image "$IMG" --config .github/cst/${{ matrix.name }}.yaml   # user 10001, trivy/grype/clairctl --version match ARGs
```

**Integration: run the shipping config.** Add a second matrix leg with `auth.mode: oidc` (a Keycloak token from the NIC sandbox), `scanner.clair.enabled: true`, `networkPolicy.enabled: true` and `controlsEngine.enabled: true`. Assert:
- `jq '.findings | length > 0'` on `/images/{id}`
- `.score != null` on `/summary`
- `POST /reports {type: sar, format: html}` reaches `done`
- `curl -sf ui/` returns 200
- `helm upgrade` from the last released chart, followed by `/ready`

**Dependabot.**
```yaml
  - package-ecosystem: "uv"        # replaces "pip" (or delete uv.lock)
    directory: "/api"
  - package-ecosystem: "docker"
    directories: ["/api", "/ui", "/collector"]
  - package-ecosystem: "helm"
    directory: "/chart"
```
Scanner ARG versions need Renovate `customManagers` (regex on `ARG TRIVY_VERSION=`) or a scheduled workflow. Pair this with the fixture-version test from m4.

**Required checks:** see B1.

---

## Prioritized plan

| # | Item | Effort | Moves |
|---|---|---|---|
| 1 | Ruleset with required checks (B1) | XS | Makes everything else matter |
| 2 | `env.py` provenance-models import + alembic round-trip/check job (M2) | XS | Prevents a table-drop migration |
| 3 | `run_proc` process-group kill + bounded post-kill wait + elapsed-time asserts (M1) | S | Real timeouts |
| 4 | Gates at current floors: Go 70 internal, pytest 85, vitest 65/55 + `testTimeout` (M4) + ruff + pin setup-python (m1, m2) | S | Stops regressions |
| 5 | `inventory.build_containers` table tests with raw pod JSON, including init/sidecar/ephemeral/no-SC/ownerless/Windows; add `spec.os` + `hostProcess` handling (B2) | S–M | Python +1.3 pp; closes the biggest correctness hole |
| 6 | Route-table auth test + JWT negative tests + JWKS non-JSON fix (M7, M8) | S | Locks in authz |
| 7 | UI `errorElement` + response parsing defaults + route smoke `describe.each` (M5) | M | No blank-screen failures |
| 8 | Go: in-memory registry tests for signed/verified, `Resolve`, `Check`, Helm discovery; drop the Docker Hub calls (M10) | M | Go 58 → ~72 % |
| 9 | Go→Python golden report contract + `schemaVersion` (M9) | S–M | Version skew caught in unit CI |
| 10 | Router tests for filters/pagination/404 (M7) | M | Python 86 → ~90 % |
| 11 | UI page tests for the 9 untested pages + scan-control/tag-input + Playwright on mock mode (M6) | M–L | UI 67 → ~78 % lines |
| 12 | Trivy + structure tests + buildx cache on own images (M13) | S | Dogfooding |
| 13 | Report perf budget test, SAR pagination, write-only xlsx, job timeout (M11) | M | Bounded cost on big clusters |
| 14 | Integration leg with the shipping config + upgrade test (M12) | L | E2E realism |
| 15 | Fixture-version guard, alias merging, shared scoring vectors, de-flake timing tests, scrub lab IDs (m4–m8) | S each | Hygiene |

Effort key: XS < 1 h, S ≤ ½ day, M 1–2 days, L 3+ days.

Steps 1–6 take about 2–3 days. They give a CI that a maintainer can trust as a gate. Steps 7–11 take about one more week and bring the targets to Go ~75 %, Python ~90 % line+branch, and UI ~75 % lines.
