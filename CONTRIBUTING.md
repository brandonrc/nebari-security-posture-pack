# Contributing

## Branch protection and required checks

`master` is protected by the repository ruleset **"master: required checks"** (Settings → Rules →
Rulesets). The ruleset:

- blocks deletion of the branch and non-fast-forward (force) pushes;
- requires these status checks to pass before a change lands. They are job names, so do not rename them without updating the ruleset:

| Check | Workflow | What it runs |
|---|---|---|
| `lint` | `lint.yaml` | ruff (api), shellcheck (deploy + CI scripts), actionlint, eslint + `tsc` (ui) |
| `chart` | `lint.yaml` | `helm unittest`, then `.github/scripts/chart-matrix.sh`: helm lint (defaults + grace), 18 value sets through kubeconform `-strict` with the NebariApp / SecurityPolicy / Prometheus-operator CRD schemas, and 4 value sets that must refuse to render |
| `test` | `test.yaml` | gate over `api (py3.12)` and `api (py3.13)`: pytest against Postgres 16, `--cov-fail-under=85` (line+branch) and per-module floors (`.github/scripts/coverage_floors.py`) |
| `ui` | `test.yaml` | gate over `ui (vitest + coverage + build)` (thresholds in `ui/vitest.config.ts`) and `ui (playwright e2e)` (mock-mode bundle) |

**Bypass (temporary).** The repository admin role can bypass the ruleset while the project still
pushes straight to `master`. GitHub prints "Bypassed rule violations" on such pushes. When the
project moves to a pull-request flow:

1. Remove the bypass actor from the ruleset.
2. Add a `pull_request` rule (one approval, dismiss stale reviews).
3. Turn on "require branches to be up to date" (`strict_required_status_checks_policy`).

To inspect the ruleset:

```sh
gh api repos/brandonrc/nebari-security-posture-pack/rulesets --jq '.[] | {id, name, enforcement}'
gh api repos/brandonrc/nebari-security-posture-pack/rulesets/<id>
```

These workflows are informational and not required: `mypy (advisory)` (the error count is shown in the job summary),
`Image scan` (path-filtered, plus a weekly run), and `Build Docker Images` / `Release Chart`
(publishing, nebari-dev `main` only).

## Coverage gates

Gates start at today's floor and only move up. Raise a number in the same change that adds the
tests that justify it.

| | Gate | Where |
|---|---|---|
| Python, total | 85% line+branch | `--cov-fail-under` in `test.yaml` |
| Python, per module | ≥ 95%: `scoring`, `correlate`, `severity`, `auth`, `posture_checks`, `scanners/*`; ≥ 80%: `inventory` | `.github/scripts/coverage_floors.py` |
| UI | lines 65 / statements 65 / branches 55 / functions 55 | `ui/vitest.config.ts` |

Coverage reports are uploaded as workflow artifacts (`api-coverage-py3.12`, `ui-coverage`). They
also go to Codecov, but only when a `CODECOV_TOKEN` secret exists.

## Running the suites locally (Docker only, no host Python/Node)

Never run `docker network create` on the lab host: it restarts MicroK8s. Use `--network host`
and published ports instead.

```sh
# Python: Postgres on a free port, then the same command CI runs
docker run -d --name posture-test-pg -p 127.0.0.1:55432:5432 -e POSTGRES_USER=posture \
  -e POSTGRES_PASSWORD=posture -e POSTGRES_DB=posture_test postgres:16-alpine
cd api && uv sync --frozen --extra dev --extra lint      # or the venv recipe in api/README.md
TEST_DATABASE_URL=postgresql://posture:posture@127.0.0.1:55432/posture_test \
  .venv/bin/python -m pytest -q -p no:randomly --cov=posture --cov-branch --cov-report=json
python ../.github/scripts/coverage_floors.py coverage.json
.venv/bin/ruff check src tests && .venv/bin/mypy           # mypy is advisory

# UI (from ui/)
alias dnode='docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app -e HOME=/tmp node:22-alpine'
dnode npm ci && dnode npx vitest run --coverage && dnode npm run lint && dnode npm run typecheck
dnode npm run build:mock-preview                            # dist-mock/ for Playwright
docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -e PORT=4391 \
  -v "$PWD":/app -w /app mcr.microsoft.com/playwright:v1.63.0-noble npm run e2e

# Chart (from the repo root; helm + kubeconform + the helm-unittest plugin)
helm dependency build chart/ && helm unittest chart/ && .github/scripts/chart-matrix.sh
```

The Postgres-backed scenario modules (`test_integration.py`, `test_reports_api.py`,
`provenance/test_integration_provenance.py`, `controls_engine/test_api_integration.py`) are
numbered `test_01…` steps that share database state. Run them in file order (`-p no:randomly`),
and run each module whole, not a single step with `-k`.

## Writing tests

- Test behaviour through public interfaces. For the UI, query by role and label and use the MSW handlers in `ui/src/mocks`.
- For Python, drive raw input shapes through the real adapters. Examples: `kubectl get -o json` pods in `api/tests/fixtures/k8s/cluster.json`, and real scanner JSON in `api/tests/fixtures/`.
- Do not use fixed sleeps or tight timing windows. Poll for the condition, and give elapsed-time asserts generous bounds that still prove the point. CI runners are slow and run under coverage.
- In the UI, avoid per-keystroke `user.type` on large lists. Use `fireEvent.change` or `userEvent.setup({ delay: null })`.
- Do not use real identifiers in test data: use `example.org` hostnames, RFC 5737 addresses (`192.0.2.0/24`) and invented names.
- When you find a bug that someone else's change should fix, record the desired behaviour as `pytest.mark.xfail(strict=True, reason=...)`, as in `api/tests/test_q_scoring_edges.py`. When the fix lands, the XPASS fails CI and the marker gets removed.
- Every API route must be in the auth table (`api/tests/test_q_auth.py`). A new route that is not admin-only must be added to an explicit allowlist there.
- Every UI route must survive malformed API bodies (`ui/src/test/route-smoke.test.tsx`). Add new routes to its `ROUTES` list and to `ui/playwright/navigation.spec.ts`.

## Dependencies

Dependabot (`.github/dependabot.yml`) covers `uv` (`api/uv.lock`, which the images install from with
`uv sync --frozen`), `npm` (ui), `docker` base images, the `helm` chart dependencies and the SHA-pinned
GitHub Actions. Bump these together, by hand:

- **Scanner binaries.** The `*_VERSION` / `*_SHA256` ARGs in `api/Dockerfile.worker`, the parser fixtures (`api/tests/fixtures/README.md`) and `.github/cst/worker.yaml`.
- **Playwright.** `@playwright/test` and the `mcr.microsoft.com/playwright` image tag in `test.yaml`.

Install the git hooks with `pip install pre-commit && pre-commit install`. They run the same fast
checks as the `lint` job.

## Commits

Make small, focused commits. Rebase on `origin/master` before pushing (`git pull --rebase`), and
stage only the files that belong to the change.
