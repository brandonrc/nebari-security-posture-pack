# Compliance reports

Audience: Information System Security Officers (ISSOs), ISSMs and assessors who need to
move the Security Posture pack's scan results into an ATO / continuous-ATO (cATO) package.

Every completed scan can be turned into the artifacts listed below, without re-keying
anything. The reports are generated from one scan snapshot (cluster, namespace or single
workload scope) by `api/src/posture/reports/` and downloaded from the **Reports** page or
`POST /api/v1/reports` (see DESIGN.md §11).

> **Read this first.** These reports are machine-generated starting points. They come
> from automated scanners and configuration checks, which produce false positives and
> cannot see everything (see [Caveats](#caveats)). They do not replace a Security Control
> Assessor (SCA), and every row must be reviewed before it goes into an authorization
> package or an eMASS import.

## Where each report goes in the ATO process

| Report | Formats | RMF step / use | Destination |
|---|---|---|---|
| POA&M | xlsx, csv | Step 5 (Authorize) and Step 6 (Monitor): weaknesses with milestones and scheduled completion dates | eMASS **POA&M import** (paste into your system's template), or the FedRAMP-style POA&M |
| STIG checklist | ckl, cklb | Step 4 (Assess): STIG compliance evidence for the Kubernetes platform | **STIG Viewer** 2.x (.ckl) / 3.x (.cklb), **STIG Manager**, eMASS checklist import |
| Assessment summary (`sar`) | pdf, html | Step 4 (Assess): **input** to the SCA's Security Assessment Report (the SAR is the SCA's deliverable, SP 800-37 task A-4) | Given to the SCA; uploaded to eMASS as a supporting artifact |
| CRM (`crm`) | xlsx, csv | Steps 2-3: draft Customer Responsibility Matrix for programs on the platform | Programs' SSPs / eMASS inheritance planning |
| OSCAL AR | json | Steps 4 and 6, machine-readable | GRC / cATO tooling that ingests NIST OSCAL |
| Inventory | xlsx, csv | Steps 1-2: system component inventory (CM-8) | eMASS **Hardware/Software** list, asset spreadsheets |
| Vuln export | csv, json, cyclonedx-vex | Step 6 (Monitor): continuous vulnerability data | ACAS/Nessus-style trackers, Iron Bank VAT justification sheets, VEX-aware tooling |

For cATO, set `reports.autoGenerate` in **Settings** (for example `["poam", "oscal-ar"]`)
so that every completed scan produces fresh reports automatically.

## Generating reports

`POST /api/v1/reports` body:

```json
{"type": "poam", "format": "xlsx", "scope": {"kind": "namespace", "name": "dev"},
 "scanId": 42, "options": {"rollupByCve": true, "systemName": "Nebari DEV enclave"}}
```

| Option | Applies to | Default | Meaning |
|---|---|---|---|
| `systemName` | all | settings `systemName` | Name printed as the system / eMASS "System / Project Name" |
| `includeSystemNamespaces` | all | `true` | Include `kube-system`, `kube-public`, `kube-node-lease`. Set `false` to report on tenant workloads only |
| `poamGranularity` | poam | `repository` | `repository`: one item per image repository (the remediation unit), CVEs in Security Checks; `cve`: one item per CVE with Devices Affected; `finding`: one per image x CVE x package |
| `rollupByCve` | poam | `false` | Alias of `poamGranularity: cve` |
| `poamVariant` | poam csv | `emass` | Which column layout the CSV uses: `emass`, `generic`, `emass-legacy` (the xlsx contains all three) |
| `emassProfile` | poam | `generic` | eMASS template differences per component: `generic`, `navy` (CSSP Mitigations header), `army` (no Predisposing Conditions / Threat Description / Resulting Residual Risk), `marine-corps` (no Resulting Residual Risk) |
| `baseline` | poam, oscal-ssp, crm | settings `controlsEngine.baseline` | Control set: POA&M rows keep only controls in it |
| `kevDueDates` | poam, vuln-export | `true` | A CISA KEV due date earlier than the SLA date becomes the scheduled completion date |
| `requireOrganization` | poam | `false` | Refuse to generate without settings `organization` (eMASS Office/Org); otherwise a loud warning |
| `includeSrg` | stig-checklist | `false` | Add the complete Container Platform SRG checklist (all 188 rules; unevaluated ones Not_Reviewed) next to the Kubernetes STIG |

Scope: `cluster` (everything), `namespace` (`name` = namespace), or `workload`
(`name` = `<namespace>/<Kind>/<name>`, for example `dev/Deployment/hub`). Images,
findings and posture results are limited to that scope.

File names follow `<system>[-<scope>]-<report>-scan<id>-<yyyymmdd>.<ext>`.

## Remediation SLA policy

Scheduled completion dates come from the consensus severity and the date the finding
was **first seen** by this tool **on the image repository** (the clock keeps running across
rebuilt or retagged digests that still carry the vulnerability). The day counts are set in
**Settings** (`remediationSlaDays`). Provenance of the defaults: critical 15 / high 30 follow CISA
BOD 19-02 (internet-facing), medium 90 / low 180 follow FedRAMP continuous monitoring (Moderate /
Low). For DoD systems the binding dates come from **IAVM** (IAVA / IAVB compliance dates) and
TASKORDs; for federal civilian systems **CISA KEV due dates** (BOD 22-01) override the severity
SLA, which the POA&M applies by default (`kevDueDates`).

| Severity | Default SLA |
|---|---|
| Critical | 15 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |
| Negligible | 365 days |
| Unknown | 180 days |

`scheduled completion = min(firstSeenAt + SLA(severity), KEV due date)`. A finding is **overdue** when that
date is in the past at report time. Overdue POA&M rows are shaded red in the xlsx and
marked `OVERDUE.` in Comments. The SAR and `/summary` count them per severity.
Posture (configuration) failures use the same table, based on the check's severity and
the earliest first-seen date among the failing workloads.

## NIST SP 800-53 control tagging

Corrected per the compliance review (`docs/reviews/compliance-sme.md` M4):

| Source | Controls |
|---|---|
| Any vulnerability finding | SI-2 (SI-2 c when past its SLA). RA-5 is the scanning control: findings evidence that it works, they are not weaknesses against it |
| privileged, added-capabilities, capabilities-not-dropped | AC-6, CM-7, SC-39 |
| run-as-root, privilege-escalation | AC-6, CM-7, SC-39, AC-6(8) (in no 800-53B baseline: dropped from the POA&M) |
| host-namespaces, host-path | SC-39, AC-6, CM-7 |
| writable-rootfs | CM-6, CM-7, SI-7 |
| no-resource-limits, no-resource-requests | SC-5 |
| mutable-tag | CM-2, SI-7 |
| no-liveness-probe, no-readiness-probe | none: operational hygiene, no POA&M row |
| automount-sa-token | AC-6, CM-7 |
| seccomp-unconfined | CM-6, CM-7, SC-39 |
| no-netpol | AC-4, SC-7 |
| STIG-derived items | plus the rev5 controls of the rule's DISA CCIs (vendored DISA CCI list), e.g. CCI-001090 -> SC-4 |

The mapping is stored in `api/src/posture/reports/data/controls.yaml`, the single source for the
API, the UI and every report. The POA&M keeps only controls of the selected baseline (eMASS
imports items only against controls in the system's control set): the first in-baseline control
goes into **Controls / APs**, items without any are dropped and the Info sheet counts what was
dropped.

## POA&M (`poam`)

### Granularity

- **Vulnerabilities, default `repository`:** one item per image repository, the unit you rebuild.
  Security Checks lists its vulnerability IDs (KEV first, then by severity; capped, the full list
  is in `vuln-export`), Devices Affected lists every digest and the workloads using them, the
  scheduled date is the earliest due date of its findings. `cve` gives one item per vulnerability
  ID (closest to ACAS plugin-based POA&Ms); `finding` one per image x CVE x package.
- **Configuration:** one item per failing posture check with a control. Security Checks cites only
  the STIG / SRG rules the checklist marks **Open**, with their CCIs.
- **Control assertions:** one item per failing assertion of the same control evidence run as the
  SSP (`SP-CTL-<id>`).
- Only `open` findings are included. Items are sorted most severe first, then by due date.
- **External UID** (`SP-REPO-…`, `SP-CVE-…`, `SP-CFG-<check>`, `SP-CTL-<assertion>`) is stable
  across regenerations. Use it to match items on re-import (or as the eMASS REST API
  `externalUid`), so a new scan does not create duplicates.

### Workbook layout (xlsx)

| Sheet | Purpose |
|---|---|
| `eMASS` | Current eMASS POA&M import columns (32 columns; header per `emassProfile`), then the tool columns External UID, KEV, KEV Due Date, IAVM ID |
| `POA&M` | Widely published generic POA&M columns (FedRAMP-style, 27 columns) |
| `eMASS (legacy)` | Pre-5.x DoD POA&M template columns |
| `Info` | System, scan, scope, counts, SLA table, notes |

**eMASS import workflow.** eMASS validates imports against the template downloaded
from *your* system: it contains system-specific header rows and hidden metadata that no
external tool can reproduce. Follow these steps:

1. In eMASS, open the system, go to POA&M, then Import, and download the current
   template.
2. Paste the rows from the `eMASS` sheet (without the header row) under the template's
   header row, keeping the same column order.
3. Complete the risk-analysis columns (see below) and import.

`POA&M Item ID` is left blank so that eMASS assigns IDs. Our stable ID is in the trailing
**External UID** column (and in Comments): drop the tool columns when pasting into the template
and keep the workbook to match items on later imports, or use the eMASS REST API with
`externalUid` for create / update / close. Each row is also a single milestone. To add more milestones, add
rows with the item-level columns repeated, which is the same convention eMASS exports
use.

The column set was verified against an eMASS POA&M CSV export (32 columns, `POA&M Item ID`
through `Resulting Residual Risk after Proposed Mitigations`) and the published C-PAT
eMASS export mapping. Army templates omit *Predisposing Conditions*, *Threat
Description* and *Resulting Residual Risk*, and the Marine Corps template omits the last
column. Delete those columns before pasting if your template does not have them.

### `eMASS` sheet mapping

| Column | Value |
|---|---|
| POA&M Item ID | blank (eMASS assigns) |
| Control Vulnerability Description | Title, description, affected packages (`pkg installed (fixed in X)`), advisory URL. For configuration items: check title, failing workload count, details |
| Controls / APs | Primary in-baseline control: `SI-2` for vulnerabilities, the first in-baseline mapped control for configuration items (for example `AC-6`). Other controls are listed in Comments |
| Security Checks | Vulnerability IDs of the item (repository granularity: the list, KEV first), or the Open STIG rules with their CCIs (`V-233127 (CCI-001090); ...`) for configuration items |
| POA&M Status | `Ongoing` |
| POA&M Scheduled Completion Date | first seen + SLA (MM/DD/YYYY) |
| POA&M Requested Risk Accepted Expiration Date, POA&M Completion Date | blank |
| Milestone ID | `1` |
| Milestone Description | "Rebuild image(s) with fixed package, redeploy and confirm by rescan by <date>". Vulnerabilities with no fix get "Monitor vendor ... or request risk acceptance". Configuration items get "Remediate workload configuration ..." |
| Milestone Status | `Pending` |
| Milestone Status Comments | Overdue items: `OVERDUE: scheduled completion … has passed. ISSO action: record a milestone change …` (many eMASS instances reject a past date on a new item) |
| Milestone Scheduled Completion Date | same as the scheduled completion date |
| Identification Source | `Vulnerability scan - Nebari Security Posture Pack (Trivy x; Grype y; Clair z)`. Configuration items use the STIG/SRG title and release (`Container Platform Security Requirements Guide :: Version 2, Release: 4 ...`) |
| Identification Source Details | Scanner names and versions that reported the finding |
| Office/Org | Settings `organization`, POC name, POC email. Required by eMASS: an empty value is warned about in the Info sheet and the log (`requireOrganization` refuses) |
| Resources Required | `Default (confirm with the program): existing O&M staff; no additional funding identified.` / `... vendor fix required.` |
| Comments | Stable ID, scanner agreement (`3/3 scanners (trivy=high, grype=high, clair=medium)`), CVSS, single-scanner warning, SLA basis, `OVERDUE.`, additional controls |
| Raw Severity | critical: Very High, high: High, medium: Moderate, low: Low, negligible: Very Low (consensus severity, unassessed) |
| Severity | blank: the assessed severity after mitigations and threat relevance is the ISSO's |
| Devices Affected | Image `ref@digest` list plus `Used by:` workloads (configuration items list `ns/Kind/name [container]`) |
| Mitigations (`navy` profile: "Mitigations (in-house and in conjunction with the Navy CSSP)") | blank: compensating measures already in place, completed by the ISSO. The fix is **not** a mitigation |
| Impact Description | blank (no boilerplate) |
| Recommendations, Milestone Description | The fix / remediation plan with its target date |
| External UID, KEV, KEV Due Date, IAVM ID | Tool columns after the template: stable id, CISA KEV flag and due date, IAVM ID left blank (not available from the scanners) |
| Predisposing Conditions, Relevance of Threat, Threat Description, Likelihood, Impact, Residual Risk Level, Resulting Residual Risk after Proposed Mitigations | **blank: the ISSO must complete these.** The tool cannot judge threat or residual risk |

### `POA&M` (generic) sheet mapping

| Column | Value |
|---|---|
| POAM ID | `SP-<vulnId>-<hash>` (per image/package), `SP-<vulnId>` (rolled up), `SP-CFG-<check>` |
| Controls | All tagged controls, comma separated |
| Weakness Name | `CVE-x (packages)` / `Configuration: <check title>` |
| Weakness Description | as eMASS *Control Vulnerability Description* |
| Weakness Detector Source | Scanner names and versions that reported it, or `Nebari Security Posture Pack posture check <id>` |
| Weakness Source Identifier | as eMASS Security Checks |
| Asset Identifier | Image `ref@digest` list plus workloads |
| Point of Contact | POC name/email (falls back to the organization) |
| Resources Required | as above |
| Overall Remediation Plan | Upgrade path or vendor-dependency plan |
| Original Detection Date | first seen |
| Scheduled Completion Date | first seen + SLA |
| Planned Milestones | Single milestone with date |
| Milestone Changes | blank |
| Status Date | report generation date |
| Vendor Dependency | `Yes` when no fixed version exists |
| Last Vendor Check-in Date | Freshest vulnerability-DB update among the reporting scanners (vendor-dependent rows only) |
| Vendor Dependent Product Name | Affected package(s) (vendor-dependent rows only) |
| Original Risk Rating | critical/high: High, medium: Moderate, low/negligible/unknown: Low |
| Adjusted Risk Rating, Deviation Rationale | blank |
| Risk Adjustment, False Positive, Operational Requirement, Auto-Approve | `No` |
| Supporting Documents | `Nebari Security Posture Pack scan <id> / control evidence run <id> (assessment summary / vuln-export)` |
| Milestone Changes | Overdue items: the milestone-change flag |
| External UID, KEV, KEV Due Date, IAVM ID | as in the eMASS sheet |
| Comments | as eMASS Comments |

### `eMASS (legacy)` sheet

These are the older DoD template columns (`Control Vulnerability Description`,
`Security Control Number (NC/NA controls only)`, `Office/Org`, `Security Checks`,
`Resources Required`, `Scheduled Completion Date`, `Milestone with Completion Dates`,
`Milestone Changes`, `Source Identifying Vulnerability`, `Status`, `Comments`,
`Raw Severity`, `Devices Affected`, `Mitigations`, `Predisposing Conditions`,
`Severity`, `Relevance of Threat`, `Threat Description`, `Likelihood`, `Impact`,
`Impact Description`, `Residual Risk Level`, `Recommendations`,
`Resulting Residual Risk after Proposed Mitigations`). Values match the sheets above,
with two differences: **Raw Severity is a CAT level** (critical/high: `I`, medium: `II`,
low/negligible: `III`; Severity is left for the ISSO), and **Security Control Number** lists
every in-baseline control.

## STIG checklist (`stig-checklist`)

### Benchmarks

| Benchmark | Release | Rules in checklist | Source |
|---|---|---|---|
| Kubernetes STIG (`Kubernetes_STIG`) | **V2R6**, 01 Apr 2026 | all 92 | `U_Kubernetes_V2R6_STIG.zip` from DISA (dl.dod.cyber.mil) |
| Container Platform SRG (`Container_Platform_SRG`) | **V2R4**, 28 Oct 2025 | 13 that the tool can evidence | `U_Container_Platform_V2R4_SRG.zip` from DISA |

Rule text, severities, Rule IDs (`SV-...r..._rule`), Rule versions (`CNTR-K8-...`), CCIs
and discussion, check and fix text are copied verbatim from the official XCCDF into
`api/src/posture/reports/data/stig_mapping.yaml`. Every entry is `verified: true`.
V2R6 was the newest Kubernetes STIG on DISA's download site at the time of writing. V2R2
is no longer published there; if your system is still assessed against an older release,
use STIG Viewer's checklist upgrade/downgrade function after importing.

### How each rule's status is derived

Rules the tool cannot observe, such as control-plane flags, file permissions on nodes,
etcd and audit logging (86 of the 92 Kubernetes rules), are **`Not_Reviewed`**. Their
comments say "Control-plane / host-level requirement: not evaluated by this tool". This
keeps the checklist complete and importable, and your manual review fills them in. The
evaluated rules:

| Vuln ID | Benchmark | CAT | Rule version | Rule | Evidence | If evidence found | If clean |
|---|---|---|---|---|---|---|---|
| V-242383 | K8s STIG | I | CNTR-K8-000290 | User-managed resources must be created in dedicated namespaces. | workloads in default, kube-public, kube-node-lease | Open | NotAFinding |
| V-242414 | K8s STIG | II | CNTR-K8-000960 | The Kubernetes cluster must use non-privileged host ports for user pods. | host-namespaces check (hostNetwork pods listed) | Not_Reviewed | Not_Reviewed |
| V-242417 | K8s STIG | II | CNTR-K8-001360 | Kubernetes must separate user functionality. | workloads in kube-system, kube-public, kube-node-lease (listed for review) | Not_Reviewed | NotAFinding |
| V-242437 | K8s STIG | I | CNTR-K8-002010 | Kubernetes must have a pod security policy set. | privileged, run-as-root, privilege-escalation | Open | Not_Reviewed |
| V-242443 | K8s STIG | II | CNTR-K8-002720 | Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs. | fixable critical/high image CVEs (supporting evidence) | Not_Reviewed | Not_Reviewed |
| V-254800 | K8s STIG | I | CNTR-K8-002011 | Kubernetes must have a Pod Security Admission control file configured. | privileged, host-namespaces, host-path, run-as-root, privilege-escalation, added-capabilities, seccomp-unconfined | Open | Not_Reviewed |
| V-233029 | CP SRG | II | SRG-APP-000038-CTR-000105 | ...enforce approved authorizations for controlling the flow of information within the container platform... | no-netpol | Open | Not_Reviewed |
| V-233030 | CP SRG | II | SRG-APP-000039-CTR-000110 | ...flow of information between interconnected systems... | no-netpol | Open | Not_Reviewed |
| V-233065 | CP SRG | II | SRG-APP-000131-CTR-000285 | The container platform must verify container images. | mutable-tag | Open | Not_Reviewed |
| V-233074 | CP SRG | II | SRG-APP-000142-CTR-000330 | The container platform runtime must enforce the use of ports that are non-privileged... | host-namespaces (listed for review) | Not_Reviewed | Not_Reviewed |
| V-233127 | CP SRG | II | SRG-APP-000243-CTR-000595 | The container platform must prohibit containers from accessing privileged resources. | privileged, host-namespaces, host-path, added-capabilities | Open | NotAFinding |
| V-233163 | CP SRG | II | SRG-APP-000342-CTR-000775 | Container images instantiated by the container platform must execute using least privileges. | run-as-root, privilege-escalation, capabilities-not-dropped, seccomp-unconfined, automount-sa-token | Open | NotAFinding |
| V-233222 | CP SRG | II | SRG-APP-000435-CTR-001070 | ...protect against or limit the effects of all types of denial-of-service (DoS) attacks... | no-resource-limits | Open | Not_Reviewed |
| V-233233 | CP SRG | II | SRG-APP-000456-CTR-001125 | The container platform registry must contain the latest images with most recent security-relevant updates... | any fixable vulnerability | Open | NotAFinding |
| V-233234 | CP SRG | II | SRG-APP-000456-CTR-001130 | ...runtime must have security-relevant software updates installed within 30 days... | fixable vulnerability first seen > 30 days ago | Open | NotAFinding |
| V-233273 | CP SRG | II | SRG-APP-000516-CTR-001325 | Container platform components must be configured in accordance with the security configuration settings... | any of the 16 posture checks (catch-all) | Open | Not_Reviewed |
| V-233275 | CP SRG | II | SRG-APP-000516-CTR-001335 | The container platform must continuously scan components, containers, and images for vulnerabilities. | scan finished within 7 days with at least one healthy scanner | Open | NotAFinding |
| V-270875 | CP SRG | II | SRG-APP-000247-CTR-000330 | The container must have resource request limits set. | no-resource-limits, no-resource-requests | Open | NotAFinding |
| V-270876 | CP SRG | II | SRG-APP-000380-CTR-000340 | The container root filesystem must be mounted as read-only. | writable-rootfs | Open | NotAFinding |

"If clean" is `Not_Reviewed` wherever a passing result does not prove compliance.
V-242437 and V-254800 are examples: the actual check reads the API server's admission
configuration, which the tool never sees. A **running** privileged pod is still
conclusive evidence that the control is not enforced, so the failing case is `Open`.

The `FINDING_DETAILS` / `finding_details` field lists the offending
`namespace/Kind/name [container]: check (detail)` entries. Findings from system
namespaces are tagged `[system namespace]`. `COMMENTS` records the scan ID and time and
the evaluation caveat. Asset fields: host name = the pack's hostname (or the cluster
name), IP = settings value, role `None`, type `Computing`, marking = settings
`marking` (default `CUI`).

### Formats and import

- **`.ckl`** is STIG Viewer 2.x XML (`CHECKLIST/ASSET/STIGS/iSTIG/STIG_INFO/VULN`). Its
  `STIG_DATA` attribute order, status vocabulary (`NotAFinding`, `Open`, `Not_Reviewed`,
  `Not_Applicable`) and `TargetKey` follow files exported by STIG Viewer 2.17. To use
  it in STIG Viewer 2.x, choose *Checklist*, *Open Checklist from File*.
- **`.cklb`** is STIG Viewer 3.x JSON (`title`, `id`, `target_data`, `stigs[].rules[]`,
  `cklb_version: "1.0"`). Statuses are `not_a_finding`, `open`, `not_reviewed` and
  `not_applicable`. The fields follow `.cklb` files produced by DISA SCC 5.14 and STIG
  Viewer 3. To use it in STIG Viewer 3, choose *Open Checklist*.
- Both files are parsed without errors by STIG Manager's parsers
  (`@nuwcdivnpt/stig-manager-client-modules` `reviewsFromCkl` / `reviewsFromCklb`), which
  recognize the benchmarks as `Kubernetes_STIG V2R6` and `Container_Platform_SRG V2R4`.
  This makes STIG Manager a convenient way to roll checklists into eMASS.
- The SRG checklist contains only the 13 evidenced SRG rules. Use `includeSrg: false` if
  your process expects only complete benchmarks.

UUIDs are deterministic (UUIDv5 of system, scope, scan and benchmark), so regenerating a
report for the same scan produces an identical file.

## Security Assessment Report (`sar`)

This is a printable narrative (US Letter, page numbers, classification banner from
settings `classification`, Nebari branding) with these sections:

1. Executive summary: grade and score (vulnerability and posture components), open,
   critical/high and past-SLA counts, data-quality warnings (scanner DBs older than
   72 h, unhealthy scanners, unscannable images), score trend over the last 30 scans.
2. System and assessment scope.
3. Methodology: inventory, mirror-then-scan, three-scanner consensus, posture checks,
   scoring formula, SLA.
4. Vulnerability results: severity table (open, fixable, past SLA, SLA days), scanner
   agreement distribution, critical/high vulnerabilities with fix and due date, riskiest
   images.
5. Configuration (posture) results: every check with severity, controls, STIG/SRG IDs,
   pass/fail, plus failing workloads and remediation.
6. Control and STIG coverage: NIST controls with open items, and STIG status by CAT with
   the Open rules.
7. Scanner versions and database freshness.
8. Limitations.
- Appendix A: inventory of namespaces and images with digests.
- Appendix B: all open findings. This is capped at 2,000 rows; use `vuln-export` for
  the full list.

`html` is self-contained (inline CSS and SVG). `pdf` is rendered with WeasyPrint, which
requires `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 fonts-dejavu-core` in the API
image. If those libraries are missing, PDF generation fails with a clear error
(`ReportDependencyMissing`) and HTML still works.

Upload the PDF to eMASS as an artifact (type *Security Assessment Report* or
*Continuous Monitoring*). An SCA should treat it as tool output that feeds their own SAR.

## OSCAL Assessment Results (`oscal-ar`)

This is NIST OSCAL **1.1.2** `assessment-results` JSON. It is validated in the tests
against the official `oscal_assessment-results_schema.json` from the usnistgov/OSCAL
v1.1.2 release (`api/tests/reports/fixtures/`).

| OSCAL element | Content |
|---|---|
| `metadata` | Title, version = scan ID, parties (organization, POC), props `system-name`, `scope`, `generator` |
| `import-ap` | `#<uuid>` of a back-matter resource that describes the implicit continuous-monitoring assessment plan. No separate AP document exists; replace this with your AP's href if you have one |
| `results[0]` | One result per scan: `start`/`end` = scan times, props `scan-id`, `score`, `grade` |
| `results[0].local-definitions` | `components`: the pack plus each scanner (with version and DB date). `inventory-items`: each image (ref, digest, base OS) and each workload |
| `reviewed-controls` | Every control touched (`ra-5`, `si-2`, `si-2.2`, `ac-6`, `cm-7`, ...) |
| `observations` | One per open (image, vuln, package) finding and one per failing posture check. Methods `TEST`, type `finding`, origin actors = the scanners (tool), subjects = inventory items. Props carry severity, per-scanner severity, agreement, CVSS, fixable |
| `risks` | One per CVE and one per failing check. Status `open`, `deadline` = SLA due date, planned `remediations` when a fix exists |
| `findings` | One per control, target `<control>_smt` with state `not-satisfied` when open risks map to it, otherwise `satisfied` |

Custom props use the namespace `https://nebari.dev/ns/oscal`. UUIDs are deterministic
(v5), so regenerating the same scan yields an identical document.

## Hardware/Software inventory (`inventory`)

Sheet `Images` (also the CSV) has one row per unique image digest:

| Column | Value |
|---|---|
| Asset Type | `Software (container image)` |
| Image Reference | Reference as deployed |
| Registry, Repository, Tag / Version, Digest | Parsed from the reference and the resolved digest |
| Base OS | From scanner metadata |
| Namespaces, Workloads, Pack / NebariApp | Where the image is used |
| Containers, Running Containers, Running | Usage counts |
| Score, Grade, severity counts, fixable critical/high | Vulnerability posture |
| Trivy, Grype, Clair, Scanner Coverage | Per-scanner status (`ok`, `error`, `timeout`, `unsupported`) and `n/3` |
| Agreement Index, Last Scanned (UTC), Mirrored, Warnings | Scan metadata |

The xlsx adds `Workloads`, `Namespaces` and `Info` sheets. The software list maps onto
the eMASS Hardware/Software module (Software: vendor/product = repository,
version = tag + digest).

## Vulnerability export (`vuln-export`)

- **csv / json** have one row per (image, vulnerability, package) with the consensus
  severity and **each scanner's severity**, plus scanners, agreement, CVSS, fixed
  version, controls, first seen, SLA due, overdue and status. The CSV is
  UTF-8 with BOM so that it opens cleanly in Excel. Use it for ACAS/Nessus-style
  trackers or to pre-fill Iron Bank VAT justifications.
- **cyclonedx-vex** is a CycloneDX 1.6 JSON BOM. Its components are the images
  (`pkg:oci` purls), and its vulnerabilities are one per CVE with `affects` = images,
  ratings from the consensus and each scanner, and `analysis.state: in_triage`. Update
  the analysis (`not_affected`, `exploitable`, ...) after triage. This format is not yet
  validated against the CycloneDX schema.

## Caveats

- **Machine-generated, not an assessment.** Scanners report package metadata. They miss
  statically linked or vendored code, and they flag CVEs that the distribution has
  back-ported fixes for or that are unreachable. Agreement across Trivy, Grype and Clair
  raises confidence. Single-scanner findings are marked in POA&M comments and should be
  validated first.
- **Scope is container images and pod specs.** Nodes, the OS, the control plane, etcd,
  RBAC, Secrets, admission configuration, audit logging and the network are not
  assessed. That is why most Kubernetes STIG rules are `Not_Reviewed`.
- **First seen is not the disclosure date.** SLA clocks start when this tool first
  detected the finding. If your policy measures from CVE publication or IAVM release,
  adjust the dates.
- **Risk analysis is yours.** Relevance of threat, likelihood, impact and residual risk
  are left blank on purpose.
- **eMASS templates vary** by component (Army, Navy, Marine Corps) and by eMASS release.
  Always paste into the template downloaded from your system, and check the column order
  before importing.
- **System namespaces** (`kube-system`, `kube-public`, `kube-node-lease`) are included by
  default and flagged. Platform components often need privileges; document those as
  operational requirements or risk acceptances rather than "fixing" them.
- **Images the scanners could not reach** (private registries without credentials, or
  scan errors) have no findings. The SAR lists them as a data-quality warning, and the
  inventory shows their scanner status.

## Maintenance

- **New STIG / SRG release:** download the DISA zip files and run
  `python api/tests/reports/build_stig_mapping.py <k8s-xccdf.xml> <cp-srg-xccdf.xml>
  api/src/posture/reports/data/stig_mapping.yaml`. The script holds the hand-maintained
  `EVAL` table; review it for renumbered or withdrawn rules. Then run
  `pytest api/tests/reports`.
- **OSCAL upgrade:** replace the schema in `api/tests/reports/fixtures/`, bump
  `OSCAL_VERSION` in `oscal.py`, and run the tests.
- **Input contract** for the generators: `api/src/posture/reports/models_contract.md`.
