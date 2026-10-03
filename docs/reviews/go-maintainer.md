# PR #105 review: Go maintainer's seat (nebari-dev/provenance-collector-pack)

Reviewer role: senior Go engineer who would approve and then own this repo. Branch `security-posture-merge` @ local checkout, compared with `upstream/main`.
What I ran myself, in a `golang:1.25` container: `go mod tidy` (no diff), `go vet ./...` (clean), `go test -race -cover ./...` (all pass, **58.5% total**; `internal/discovery` 37.0%, `internal/registry` 34.3%, `cmd/provenance-collector` 23.3%), `golangci-lint run` (0 issues).

## Verdict

**Request changes. Recommend option (B) and do not merge (A).** The Go change is small, careful and green: about 300 lines for `--once/--output`, an atomic `FileWriter` and table tests. The rest of the PR is the problem. It turns a 3.5k-LoC Go repo into a ~15k-LoC Python service with ~16k LoC of TypeScript around it, and the Go binary becomes a subprocess. Python re-implements nearly everything that binary does: OCI registry client, referrers/cosign/SBOM/SLSA detection, semver update checks, Helm discovery, image-ref parsing, pod-owner resolution, and the Go report JSON format plus the `/api/reports*` server. In two places Python is already declared the better implementation: update checks (`stage.py:328-331` switches the collector's off) and attestation detection (`provenance/checks.py:1-16` calls itself "a superset of internal/verify").

The Python fallback also hides the collector's real gaps. 21 of 79 images fell back on grace. The Go side has no custom-CA/insecure-registry support, `PROVENANCE_REGISTRY_AUTH` is never used, and `referrers.go` calls `remote.Get` anonymously. So no pressure ever reaches the Go code to fix them. That is the textbook way a component rots: it stays in the repo, keeps passing CI, and stops being the source of truth.

The people who own this repo write Go. Under (A) they would inherit a FastAPI/SQLAlchemy/Alembic/WeasyPrint/OSCAL codebase, four images, a Postgres, Trivy and Clair. The PR also points CODEOWNERS at a single personal handle and carries home-lab deploy config.

Instead: land the Go improvements here, put the posture pack in nebari-dev as its own pack that consumes this collector's versioned report, and move the Python-only provenance detection into Go so that one engine exists. Revisit (C) only if the posture pack graduates and nebari-dev wants it in Go. Even then, port the backend incrementally behind the existing OpenAPI contract, not as a precondition.

---

## 1. Shape of the merge: A vs B vs C

| | (A) this PR | (B) separate posture pack consumes collector | (C) port backend to Go |
|---|---|---|---|
| Who maintains | Go maintainers inherit 27.7k Python + 16k TS + chart with 6+ workloads | Each team owns its own language | Go team, but a huge port (OSCAL, POA&M xlsx, SAR PDF, 35 assertions) |
| nebari-dev conventions | Breaks them: operator, NIC and this repo are Go | Keeps them | Keeps them |
| Review burden | +66.8k/-16.8k in one PR; realistically unreviewable | Collector PRs stay small; posture pack reviewed on its own | Months of work before any value lands |
| Release eng | 4 images + 4 binaries + chart from one tag (no tests gate release; see §5) | Collector: 1 image + binaries. Posture: 3 images | Fewer images, still large surface |
| Collector rot risk | High: Python fallback and Python update check already override Go (§2) | Low: the collector is the only provenance engine the posture pack has, so its gaps must be fixed in Go | None |
| Existing users | Breaking chart (CronJob → api/worker/ui/Postgres/Trivy/Clair; helm default flipped off; `registryCredentials` silently ignored) | Unchanged; opt in to the posture pack | Breaking |

**Recommendation: (B)**, plus these concrete moves:
1. Merge the `--once/--output` change and release binaries here (proposal 0001's own "PR 2", `docs/proposals/0001-*.md:57-60`).
2. Port the Python-only detection into Go: sigstore bundles, `.sbom` tags, decoded DSSE in `.att`, the candidate-tag update filter, registry auth, and custom CA / insecure registries. Then delete `api/src/posture/provenance/{checks,registry,updates,helm}.py` from the posture pack instead of keeping them as a "fallback".
3. Version the report schema (see §4) and publish it from this repo. The posture pack pins a collector version range.
4. The posture pack goes in nebari-dev as `nebari-security-posture-pack` with its own owners. The proposal already lists this as the alternative (`0001:76-79`). Its only argument against it is "overlapping discovery code", and (A) does not fix that either: Python `inventory.py` still re-discovers pods and owners, and the result has to be prefix-matched against the collector's ReplicaSet names (`collector.py:174-182`).

Why not (A) even with a follow-up to delete the Python port: the PR's own data argues against it. Update checks were moved *back* to Python after the Go ones misbehaved (`docs/DECISIONS.md:126-128`, `stage.py:328`). The fallback hides collector failures behind a log line (`stage.py:246-251`). The compat `/api/reports/latest` that Grafana reads is a Python reconstruction of the Go JSON from Postgres (`provenance/report.py:1-8`, "serialization follows Go's json.MarshalIndent"), stamped with the Python package version (`0.1.0+posture`, PR-DESCRIPTION "Known gaps"). After (A), the Go code is load-bearing for nothing that Python cannot already do.

## 2. Duplication audit (capability in BOTH Go and Python)

| Capability | Go | Python | Source of truth |
|---|---|---|---|
| Pod/image discovery + owner resolution | `collector/internal/discovery/images.go` | `api/src/posture/inventory.py`, matched back via `collector.py:185-231` | Go for provenance. Posture inventory should key off the report, or both should share one schema. Today two discoveries run per scan and race each other. |
| Image-ref parsing / normalisation | go-containerregistry `name` | `images.py:52` `parse_image_ref`, `updates.py:237` | Go (go-containerregistry is canonical) |
| OCI registry client (auth, token challenge, pagination) | go-containerregistry / crane | `provenance/registry.py` (279 LoC, httpx) | Go. But Go must actually wire auth (Major finding 5). |
| Digest resolution | `internal/registry/digest.go` | `registry.py` + `checks.py` | Go |
| Signature existence + cosign verification | `internal/verify/cosign.go` (cosign lib, key file only) | `checks.py:338-400` (`cosign` CLI, key/KMS/keyless) | Go. Add keyless + KMS to the Go verifier, then drop the cosign CLI from the worker. |
| SBOM detection | `internal/verify/sbom.go` | `checks.py:89-313` (adds `.sbom` tags, DSSE decode) | Go, after porting the extra detection |
| SLSA provenance / referrers / BuildKit attestations | `internal/verify/provenance.go`, `referrers.go` | `checks.py:52-81, 201-279` ("ported verbatim" + superset) | Go, after porting |
| Update checks (semver, level, prerelease) | `internal/registry/updates.go` (Masterminds/semver) | `provenance/updates.py` (312 LoC hand-rolled semver + candidate-tag filter) | Go. Port the candidate-tag filter there; the PR offers to (body Q3). |
| Helm release discovery | `internal/discovery/helm.go`, `helmrest.go` | `provenance/helm.py:59-161` (decode `sh.helm.release.v1` secrets) | Go |
| Helm chart update check | none (the Go report never fills `helmReleases[].update`) | `helm.py:168-230` | Port to Go, or document as posture-only |
| Report schema / types | `internal/report/types.go` | `provenance/report.py` (re-serialises Go JSON shape) + hand-written fixture `api/tests/fixtures/provenance-collector-report.json` | Go. Generate a JSON Schema from `types.go` and contract-test both sides against it. |
| Report HTTP API `/api/reports*`, `/api/export` CSV, `/api/me`, `/api/scan`, internal listener | `internal/dashboard/*` + `cmd/dashboard` (~2.5k LoC with tests, 89.7% covered) | `routers/provenance_compat.py` (236 LoC) | Go's is now dead code: kept, tested and shipped in the collector image, but not deployed by the chart (gendocs text, `collector/hack/gendocs/main.go`). Either delete it or keep it as the canonical server. Shipping both is the worst option. |
| Config/env spec | `internal/configspec` + `checkenvs`/`gendocs` | `CollectorConfig.environ` (`collector.py:70-112`) + chart `_compat.tpl` | Go `configspec`. Python should be generated from it or checked against it. |
| Namespace allowlist (`PROVENANCE_NAMESPACES`) | supported | forced to `""` (`collector.py:102`), and `config.namespaces` now fails the render (`_compat.tpl:32-34`) | Go. This is a capability regression introduced by the wrapper. |
| Supply-chain scoring | none | `provenance/scoring.py` | Python only (fine: a posture concern) |

Rough count: ~1.6k LoC of Python (`checks`, `registry`, `updates`, `helm`, `report`, compat router, plus image parsing) duplicate ~2k LoC of non-test Go, and ~2.5k LoC of Go dashboard is orphaned.

## 3. Quality of the Go changes

The Go code is good and nothing in it is blocking on its own. What I checked:
- `collector/cmd/provenance-collector/main.go`: `flag.NewFlagSet(..., ContinueOnError)`, rejects positional args, logs go to stderr when the report goes to stdout, and `selectWriter` is extracted and testable. Default behaviour is unchanged. Exit codes: 2 on bad flags, 0 on `-h`, 1 on run error.
- `collector/internal/report/writer.go:198-252` `FileWriter`: temp file in the same dir, then close, chmod 0644 and rename. Atomic, with cleanup on every error path.
- `go.mod`: `sigstore/sigstore` moved from indirect to direct. This is correct, since `internal/verify/cosign.go:12-13` imports it directly. `go mod tidy` gives no diff. Module path is unchanged (`github.com/nebari-dev/provenance-collector`). The module now lives in `collector/`, so `go install github.com/nebari-dev/provenance-collector/...@vX` breaks for anyone using it. Release tags would need a `collector/vX.Y.Z` prefix to be resolvable by the Go proxy. Not documented.
- `.golangci.yml`: moved unchanged. It is a minimal set (errcheck, govet, staticcheck, unused, ineffassign, misspell). This is fine for a binary, but given the new surface I would ask for `errorlint`, `bodyclose`, `contextcheck`, `gosec` and `revive`.

Things a Go reviewer would raise:
- **Minor: `--once` is a no-op.** The binary was always single-run (it ran as a CronJob). `--once` only defaults `--output` to `-` (`main.go:47-49`). Either drop `--once` and keep `--output`, or document it as an alias. A flag implying a daemon mode that never existed will confuse users.
- **Minor: `run()` still has no seam for an end-to-end `--once` test.** It builds real clients (`k8s.NewClient`, crane resolvers). `cmd/provenance-collector` coverage is 23%. Inject a `kubernetes.Interface` plus resolvers so a fake-clientset test can produce a real report. That same test can then emit the golden fixture the Python side consumes (§4).
- **Minor: test nits.** In `main_test.go:113` the `List` error is discarded (`cms, _ :=`) and then dereferenced. `var metav1ListAll` at the bottom of the file is odd. `TestLogWriterKeepsStdoutForTheReport` compares against global `os.Stderr`, which is fine but brittle.
- **Major (pre-existing, but this PR now depends on it): registry auth and TLS.** `config.RegistryAuth` is read (`internal/config/config.go:63`) and never used anywhere. `internal/verify/referrers.go:44,55,111,131` call `remote.Get/Index/Image` with only `WithContext`, i.e. anonymous. crane and cosign fall back to `authn.DefaultKeychain` only because the worker happens to export `DOCKER_CONFIG`. There is no custom CA or insecure-registry option. These are exactly the cases the Python fallback "covers". Fix them in Go and the fallback is unnecessary.
- **Major: helm discovery failure is invisible to the caller.** `main.go:147-151` logs and continues. The report cannot tell "0 releases" from "403 on secrets", so Python re-runs its own Helm discovery (`stage.py:263`), which is more duplication. Add a `warnings`/`errors` array to the report metadata.
- **Major: toolchain skew.** `go.mod` says `go 1.25.0`, CI `setup-go` uses go.mod (1.25), `collector/Dockerfile` uses `golang:1.25-alpine`, but `api/Dockerfile.worker:10` builds the shipped binary with `golang:1.26` (a floating tag, no digest). The binary users actually run is built by a toolchain CI never tests. Pin one version, by digest.
- **Minor: `collector/Dockerfile` hardcodes `GOARCH=amd64`.** Release binaries build arm64 and the images do not. The worker image also downloads amd64-only scanners (`Dockerfile.worker:46-54`).
- `hack/gendocs` now writes `../docs/...` relative to `collector/`. It works from CI's `working-directory: collector` but breaks if run from the repo root. Minor; resolve the path relative to the module root instead.

## 4. Subprocess integration (`api/src/posture/provenance/collector.py`, `stage.py`)

What is fine: `create_subprocess_exec` (no shell), a wall-clock timeout with kill and reap (`collector.py:140-145`), a non-zero exit becomes `CollectorError` with the log tail, a temp dir per run, and sink env vars are scrubbed so the report cannot leak elsewhere (`:110-111`). A fake-binary test covers success, exit 1, bad JSON and timeout (`api/tests/provenance/test_collector.py:138-163`).

Problems:
- **Blocker: cancellation orphans the process.** `run_collector` handles `TimeoutError` but not `asyncio.CancelledError`. On a scan cancel, the worker calls `prov_task.cancel()` (`worker.py:311,328`) and the Go process keeps running for up to `provenance_collector_timeout` = 1800s (`config.py:103`), still hitting registries. The repo's own `scanners/base.py:99-101` handles this correctly. Reuse `run_proc`, or add `except CancelledError: proc.terminate(); …; raise`. Prefer SIGTERM then SIGKILL: Go already handles SIGTERM via `signal.NotifyContext`.
- **Major: no schema version or contract.** `validate_report` only checks that `metadata` and `images` exist (`collector.py:158-161`). The Python test fixture is hand-written (commit 563fa79), not produced by the Go binary, so nothing in CI catches a Go-side rename. Add a `schemaVersion` to `ReportMetadata`, have a Go test emit a golden report from fakes, commit it, and make pytest consume that same file. Better still, generate a JSON Schema from `types.go` and validate on ingest. Python should refuse unknown major versions.
- **Major: partial output and silent degradation.** Per-image registry errors produce records with an empty `digest`, which Python routes to the fallback (`collector.py:253`, `stage.py:323-325`). A total collector failure falls back to Python for every image (`stage.py:246-251`). The integration test only asserts that "engine=collector" appears in the log and "engine=collector failed" does not (`test-integration.yaml`). It would pass with 0 images ingested by Go. Expose and alert on the collector/Python split; fail the integration test below a threshold.
- **Major: double discovery and a race.** The collector does its own cluster-wide pod listing, the worker does another (`inventory.py`), and the two are joined heuristically: digest+ns, then image+ns, then digest anywhere, with ReplicaSet-prefix workload matching (`collector.py:174-231`). Pods that roll between the two listings mis-attribute or fall to Python. With a library or input boundary, Python would pass the image list *in*, or consume the collector's discovery, and no join would be needed.
- **Major: registry load.** The collector re-checks every image every scan with no `recheckHours` cache, Python then re-checks the remainder plus all update tags, and the PR itself reports Docker Hub 429s (PR-DESCRIPTION "Known gaps", scan 7). Two engines also give different answers for the same image depending on reachability. The engine is recorded per row, but scores are not comparable across rows.
- **Major: RBAC parity regression.** Upstream gave the collector its own SA. Now api and worker share one SA (`chart/templates/rbac.yaml`; `api.yaml:30`, `worker.yaml:27`). With `provenance.helmReleases.enabled`, **the gateway-facing API pod gets cluster-wide `secrets get/list`** because the collector inside the worker needs it. Split the SAs: worker-only for secrets. Separately, the Helm default flipped from `helmEnabled: true` (upstream `values.yaml:30`) to `false`, so Helm data silently disappears from existing Grafana dashboards on upgrade. Document it as breaking or keep the default.
- **Major: `registryCredentials.existingSecret` (upstream `values.yaml:221-223`) is silently ignored** (`_compat.tpl:97`), even though `registryAuth.existingSecret` is its exact equivalent. Private-registry users lose auth on upgrade with no error. Alias it.
- **Minor:** the child inherits the full worker environment (`collector.py:87`), including DB credentials. Pass an allowlist. stdout and stderr are merged and fully buffered in memory, and only 5 lines are kept. `stdin` is not set to DEVNULL.

**Exec vs library/gRPC/HTTP.** For a Go binary consumed by Python, exec + JSON file is a reasonable boundary. It is simpler than gRPC and needs no long-running sidecar, so I would not ask for gRPC. If (A) were taken, the better boundary is an input-driven exec: `provenance-collector --once --images-from <file>` (image refs plus pull-secret refs in, report out). That removes the second discovery and the heuristic join, and makes the collector a pure function that is easy to golden-test. Under (B), the right boundary is the versioned report document itself: the posture pack reads it from the collector's existing HTTP or ConfigMap sink, or runs the released binary. If the posture backend were ever Go (C), `internal/report.Generator` is already a library with interfaces for every dependency (`report.NewGenerator(..., digestResolver, updateChecker, …)`) and should be imported directly. It would need to move out of `internal/` to `pkg/`.

## 5. CI / workflows

Gated today (none of it has run on GitHub yet, per the PR body):
- Go: vet, `go test -race -coverprofile`, golangci-lint v2.11.4, `checkenvs`, `gendocs --check` (`test.yaml`, `lint.yaml`)
- Python: pytest against Postgres 16
- UI: eslint, tsc, vitest, build
- Chart: lint, 6 kubeconform renders, a values-compat script
- Docs: build, link check, sync check
- shellcheck
- Images: built with SBOM and `provenance: mode=max`, keyless-signed by digest on non-PR pushes

Missing for a maintainer to trust a green build:
- **Blocker: release is not gated on tests.** `release.yaml` runs only `helm lint`, then publishes the chart, uploads binaries and stamps versions onto main. The images build in a separate `build-image.yaml` on the same `release` event, so a chart pointing at images that failed to build can still be published. Make the release `needs:` the test, lint and build jobs, or call them as a reusable workflow.
- **Major: unsigned, unattested release binaries.** `release.yaml` collector-binaries uploads tarballs plus `checksums.txt` only. For a *provenance* tool, add `actions/attest-build-provenance` and/or `cosign sign-blob` and an SBOM. Also add a `cosign verify` step after image signing in `build-image.yaml`.
- **Major: no coverage thresholds.** Go coverage is uploaded as an artifact but never enforced. `discovery` (37%) and `registry` (34%) are precisely the packages Python claims to do better. Python has no `pytest-cov` at all. Set floors and ratchet them.
- **Major: no Python static checks.** No ruff and no mypy in `pyproject.toml` or any workflow, for a 14.7k-LoC package (`find api/src -name '*.py' | xargs wc -l`). `actions/setup-python@v6` in `test.yaml` is the only action not SHA-pinned, which breaks the repo's own pinning convention.
- **Major: integration realism.** Upstream had a two-collection timeline test plus Playwright e2e of the dashboard (`upstream/main:.github/workflows/test-integration.yaml:154-320`). Both were dropped, and the new UI has no e2e at all. The new test runs one scan on kind against public images. It does not test private-registry auth, signature *verification*, the admin gate, Helm discovery, or how much ingest the collector actually achieved (see §4).
- **Minor: missing checks.** No `govulncheck`, no `go mod tidy`/`git diff --exit-code` check, no Trivy/Grype scan of the four images the pack ships (ironic for a vuln-scanning pack). `kubeconform -ignore-missing-schemas` skips NebariApp and SecurityPolicy validation; add CRD schemas.
- **Minor: home-lab config is wired into CI.** `deploy/grace/values.yaml` and `deploy/grace/*.sh` are in CI (`lint.yaml:62,99,150`), so a personal cluster config becomes a required check.
- **Minor: path filters.** `build-image.yaml` PR paths exclude `chart/**` and `.github/scripts/**`. If it becomes a required check, path-filtered required checks block merges.

## 6. Split into separate PRs (if any of this lands here)

1. **Proposal + ARCHITECTURE only** (the proposal's own step 1, `0001:53-56`). Decide A/B/C before any code.
2. **Go: `--output/--once` + `FileWriter` + tests + release binaries** (~400 LoC). Mergeable now after the nits.
3. **Go: report `schemaVersion`, `warnings[]`, a golden report fixture, and a JSON Schema generated from `types.go`.**
4. **Go: registry auth (`RegistryAuth` actually used, keychain on referrers), custom CA / insecure registries, keyless and KMS cosign verification.**
5. **Go: sigstore bundles, `.sbom` tags, decoded `.att` DSSE, and the candidate-tag update filter in `updates.go`**, each with tests ported from `api/tests/provenance/test_checks.py` and `test_updates.py`.
6. **Go: delete or deprecate `cmd/dashboard` + `internal/dashboard`** if the Go dashboard is retired, or keep it as the canonical `/api/reports*`.
7. **CI hardening:** release gating, binary attestation, coverage floors, govulncheck, tidy check.
8. *(Only if A is chosen)* `git mv` to `collector/` alone. Then the chart, as its own PR, with a compat matrix covering `registryCredentials`, the helm default, split SAs and namespace allowlist parity. Then api/worker, then ui, each with its own CI. Then a final PR deleting the Python provenance port. That deletion should be a merge criterion, not a follow-up.

---

## Prioritized findings

### Blocker
1. **Wrong shape for this repo (§1).** It merges a Python/TS product into a Go repo whose maintainers would own it, and duplicates most of the collector in Python (§2). Prefer (B).
2. **Collector orphaned on scan cancel.** `run_collector` does not handle `CancelledError` (`collector.py:137-145`; compare `scanners/base.py:99-101`).
3. **Release publishes without tests or a successful image build** (`release.yaml`). Binaries are unsigned and unattested.
4. **Ownership, licence and fork leftovers.**
   - `CODEOWNERS` is new and assigns the whole repo to `@geraci` (not the PR author's handle, not the nebari-dev maintainers). `pack-metadata.yaml` keeps `owner: viniciusdc`, who did not author any of this.
   - Licence conflict: `LICENSE` is Apache-2.0, but `README.md:25` and `api/pyproject.toml` (`license = BSD-3-Clause`) say BSD-3.
   - README badges link to `brandonrc/…` (`README.md:22-26`). Home-lab `deploy/grace/` (scripts, values, ~8 MB of tracked screenshots) and sslip URLs in the README, plus a dependency on "grace's operator mapper" (`README.md:128`).

### Major
5. The Python fallback masks Go gaps:
   - `PROVENANCE_REGISTRY_AUTH` is unused (`internal/config/config.go:63`).
   - Referrers lookups are anonymous (`internal/verify/referrers.go:44-131`).
   - There is no CA/insecure support.

   Fix in Go, then delete the fallback (§2, §4).
6. No report schema version or cross-language contract test; the Python fixture is hand-written (§4).
7. Shared SA gives the API pod cluster-wide Secrets read when Helm is enabled. The Helm default flipped true→false (§4).
8. `registryCredentials.existingSecret` is silently ignored on upgrade (`_compat.tpl:97`). The `config.namespaces` allowlist was removed even though Go supports it (`_compat.tpl:32`, `collector.py:102`).
9. Double discovery plus a heuristic join (`collector.py:185-231`), and doubled registry load / 429s (§4).
10. Toolchain skew: the shipped binary is built with `golang:1.26` (floating) while CI tests 1.25 (`api/Dockerfile.worker:10`).
11. Go dashboard (~2.5k LoC with tests) is dead but still built and shipped, duplicating `routers/provenance_compat.py`.
12. CI gaps:
    - no coverage floors
    - no Python lint/type-check
    - unpinned `setup-python`
    - e2e/timeline integration tests dropped
    - the integration test can pass with 0 collector-ingested images
13. Helm discovery errors are swallowed in Go (`main.go:147-151`), forcing Python to re-run Helm discovery.

### Minor
14. `--once` is a no-op flag (`main.go:47-49`).
15. `run()` has no injection seam; `cmd/` coverage is 23%.
16. Test nits in `main_test.go:113`.
17. Module moved to `collector/` without documenting `go install` / tag-prefix implications.
18. golangci config is minimal (add errorlint, bodyclose, gosec, contextcheck, revive).
19. amd64-only images vs multi-arch binaries.
20. `gendocs` path is relative to the CWD.
21. Child process inherits the full worker env, including DB creds. Merged unbounded log buffering; stdin not set to DEVNULL.
22. No govulncheck, tidy check or image vuln scan. `kubeconform -ignore-missing-schemas` hides CRD errors.
23. Personal cluster values (`deploy/grace`) are part of required CI.
