# Security Posture Scoring (v1): a hygiene index

All scores are 0–100 (higher is better). Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.

> **What the grade is and is not.** The score and the A–F grade are an internal **hygiene index**
> for trends and prioritization. They have no authoritative basis (no NIST, DISA or FedRAMP
> method defines them) and they are **not an assessment result**: reports call them "hygiene
> index", and control evidence is reported separately ([CONTROLS.md](CONTROLS.md)). Use the
> CISA KEV exposure, the SLA counts and the POA&M for risk decisions.

## Image vulnerability score

For each consensus finding (unique `(vulnId, package)` across scanners):

| consensus severity | base weight |
|---|---|
| critical | 10 |
| high | 4 |
| medium | 1 |
| low | 0.2 |
| negligible / unknown | 0.05 |

Multipliers:
- **Agreement**: 1 scanner = 0.6, 2 scanners = 0.85, 3 scanners = 1.0, counted over the
  scanners that completed **and are capable of detecting that package type**: OS distribution
  packages (deb, apk, rpm, ...) all three; language-ecosystem packages (Python, Go, Java, npm,
  ...) Trivy and Grype only, because Clair does not cover them. A Python finding reported by
  Trivy and Grype is therefore full agreement. If only one capable scanner succeeded, the
  multiplier is 1.0 and the image gets `confidence: low`.
- **CISA KEV**: a finding in the CISA Known Exploited Vulnerabilities catalog is never
  down-weighted (agreement multiplier 1.0), whatever the number of scanners.
- **Fixable** (a fixed version exists): × 1.25 (unpatched-but-patchable is worse).

`penalty = Σ base × agreement × fixable`
`imageVulnScore = 100 × exp(−penalty / 40)` rounded to 1 decimal.

Examples: 1 critical fixable, all three agree → penalty 12.5 → 73.2 (C). 5 highs agreed
→ 20 → 60.7 (D). 30 mediums → 30 → 47.2 (F). Clean → 100 (A).

If **no scanner succeeded** the image has `score: null`, `grade: "?"` and is excluded
from aggregates but counted in `images.failed`.

## Posture (configuration) checks

Each check has a severity weight: critical 10, high 4, medium 1, low 0.2. Evaluated per
container (or per pod where noted).

| id | sev | rule |
|---|---|---|
| privileged | critical | `securityContext.privileged == true` |
| host-namespaces | critical | pod `hostPID`/`hostIPC`/`hostNetwork` true |
| host-path | high | pod has `hostPath` volume |
| run-as-root | high | neither container nor pod sets `runAsNonRoot: true` and `runAsUser` is unset or 0 |
| privilege-escalation | high | `allowPrivilegeEscalation` not `false` |
| added-capabilities | high | `capabilities.add` non-empty (NET_ADMIN/SYS_ADMIN etc. → critical) |
| capabilities-not-dropped | medium | `capabilities.drop` lacks `ALL` |
| writable-rootfs | medium | `readOnlyRootFilesystem` not true |
| no-resource-limits | medium | cpu or memory limits unset |
| no-resource-requests | low | requests unset |
| mutable-tag | medium | image tag is `latest` or missing and no digest pinned in spec |
| no-liveness-probe | low | long-running container w/o livenessProbe |
| no-readiness-probe | low | w/o readinessProbe |
| automount-sa-token | low | `automountServiceAccountToken` not false and SA is `default` |
| seccomp-unconfined | medium | seccompProfile type `Unconfined` or unset at both levels |
| no-netpol | low | namespace has no NetworkPolicy selecting the pod (per pod) |

`workloadPostureScore = 100 × exp(−Σ failed weights / 20)`.
Checks for system-namespace pods are evaluated but weighted × 0.5 (system components are
expected to be privileged); they are flagged `systemNamespace: true`.

## Aggregation

- **Workload score** = 0.7 × mean(imageVulnScore of its containers' images, running only)
  + 0.3 × workloadPostureScore.
- **Namespace score** = container-weighted mean of workload scores (more replicas = more
  exposure).
- **Supply-chain score** per image (DESIGN §12): start 100; −40 unsigned (−20 signed but unverified),
  −20 no SBOM, −15 no provenance, −15 update available (−25 if a major version behind), −10 mutable tag
  without digest pin; floor 0. `supplyChainScore` = container-weighted mean over running containers.
- **Cluster score** = 0.6 × `vulnScore` + 0.25 × `postureScore` + 0.15 × `supplyChainScore`
  (before §12 ships: 0.7 / 0.3 with supply chain omitted), where
  `vulnScore` = container-weighted mean of imageVulnScore over all running containers with
  a scored image, and `postureScore` = container-weighted mean of workloadPostureScore.
- `grade` from the table above. Trend compares to previous completed scan.

## STIG score (OS / product STIGs inside images, DESIGN §14)

When the SCAP scanner is on (`scanner.scap.enabled`, settings `scanners.scap`), every image is
evaluated with OpenSCAP against the applicable DISA SCAP benchmark or ComplianceAsCode (SSG)
profile, offline against its flattened root filesystem.

`imageStigScore = 100 × (1 − Σ failed weight / Σ evaluated weight)`, rounded to 1 decimal, with

| DISA category (XCCDF severity) | weight |
|---|---|
| CAT I (high) | 10 |
| CAT II (medium) | 4 |
| CAT III (low, info, unknown) | 1 |

over the rules whose result is **pass** or **fail**. `notapplicable`, `notchecked` (rules that
need a running system: services, kernel parameters, audit daemon, mounts), `error`, `unknown`
and `informational` are excluded. With several benchmarks for one image (an OS benchmark plus a
product one) the weights are summed across them. The score is `null` when no benchmark applies
(Alpine, scratch, most distroless images without dpkg metadata), when the applicable benchmark
has no content on the volume, or when every rule came back notchecked (manual STIGs such as
PostgreSQL 9.x): such images are reported as `notApplicable` / `noContent` / evaluated-without-
score, not penalised.

Example: 1 CAT I fail, 1 CAT II pass, 1 CAT III pass, 1 CAT II notchecked → 100 × (1 − 10/15) = 33.3.

**Configuration dimension.** A workload's configuration (posture) score becomes the mean of its
`workloadPostureScore` and the STIG scores of its images that have one:
`postureScore = mean(workloadPostureScore, imageStigScore₁, …)`; with no STIG score anywhere it is
`workloadPostureScore` unchanged. Workload, namespace and cluster scores then use that value
(0.7 / 0.3, and 0.25 posture share at cluster level). The vulnerability score, KEV exposure and
consensus are untouched.

Timing: the privileged worker takes the STIG scores present when it writes the posture
snapshot. It waits up to `scanner.scap.finalizeWaitSeconds` (default 0: not at all) for the scan's
SCAP stage; when the stage is still queued / running, the scan finishes with `scapPending: true`
and the snapshot uses the STIG results stored so far. When the stage completes (`scap_completed`),
the privileged worker recomputes that scan's workload / namespace / cluster scores with the new
STIG scores, clears `scapPending` and then runs the auto-reports and the controls engine it had
deferred. With no live scap-worker nothing is deferred (the re-aggregation still happens when the
stage eventually completes).

A failed re-evaluation (registry rate limit, copy or oscap timeout) never replaces a genuine stored
result: the image keeps its previous STIG score, flagged `stale`, and is retried by the next scan.

`/summary.stig = {evaluated, pass, fail, cat1Open, cat2Open, cat3Open, coverage, notApplicable,
noContent, errors, pending, images, score}` over the latest scan's images; `coverage` is the
percentage of those images with an evaluated benchmark, `score` the mean image STIG score.

Like the rest of the index the STIG score is a hygiene measure, not an assessment result: the
checklists and the POA&M carry the rule results (REPORTS.md).

## Exposure (CISA KEV)

`GET /summary` carries `exposure: {kev, kevCves, kevOverdue, kevEarliestDue, kevCatalogVersion,
topKev}`: open findings on running images whose CVE is in the CISA KEV catalog, how many are past
the KEV due date, and the earliest due date. It is reported next to the grade, not folded into
it. The catalog is the vendored snapshot, refreshed daily from `KEV_URL` into `CACHE_DIR`
(see REPORTS.md, Remediation SLA policy).

## System namespaces

`kube-system`, `kube-public` and `kube-node-lease` (`posture.scoring.SYSTEM_NAMESPACES`, the single
definition used by scoring, posture checks and reports; the control evidence engine's default
`systemNamespaces` is the same set). Their posture checks are weighted × 0.5.

## Known limitations of the index

- Container-weighted means let many clean pods mask one exposed gateway or identity-provider
  image; look at the per-image grades and the KEV exposure, not only the cluster grade.
- Images no scanner could analyze are excluded from the means (listed as `images.failed`) rather
  than penalised, which flatters the score when coverage is poor.
- Consensus severity is the highest vendor severity, not NVD CVSS; the DoD CAT mapping in the
  POA&M is severity-based.

## Scanner freshness

Each scanner reports `dbUpdatedAt`. If any enabled scanner DB is older than 72h, the
summary carries `warnings: ["trivy database is 5 days old"]`; it does not change the
score.

## VEX (suppressed findings)

A consensus finding covered by an OpenVEX `not_affected` statement (posture.vex; REPORTS.md,
"VEX") is **suppressed**: it is stored and exported with its justification, but it adds no
penalty to the image vulnerability score and is not counted in `counts` / `fixable` (image,
workload, namespace, cluster), the SLA-overdue and KEV exposure counts, the CVE rollup
(`/vulnerabilities`) or control coverage. `/summary` reports the number on running images as
`vexSuppressed`. Statements with any other status (`under_investigation`, `affected`, `fixed`)
are recorded on the finding and change nothing in the score. The decision is made in Python at
correlation time, once per consensus finding, whatever the individual scanners did with
`--vex`.

