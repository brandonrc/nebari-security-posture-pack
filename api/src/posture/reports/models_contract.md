# ReportSnapshot input contract (report generators)

The generators in `posture/reports/{poam,stig,sar,oscal,inventory,vuln_export}.py` are
pure functions of a `ReportSnapshot` (pydantic model in `posture/reports/models.py`,
built from the DB by `posture/reports/snapshot.py`). They are **duck-typed**: they only
read the attributes listed here, via `getattr(obj, name, default)`, so any object (the
pydantic model, a dataclass, a `SimpleNamespace`) that exposes these names works.

Attribute names are the **Python (snake_case) attribute names**. If the pydantic model
uses `alias_generator=to_camel` for the API, that is fine: attributes stay snake_case.
Plain `dict`s are also accepted at every level (`_common.get()` falls back to `obj[name]`).

Every field except `scan.id`, `images[].id`/`ref`, `findings[].image_id`/`vuln_id`/
`severity`/`package` and `posture_results[].check_id`/`status` is optional; generators
fall back to the documented default.

Reference implementation used by the tests: `api/tests/reports/_snapshot_stub.py`.

## ReportSnapshot

| attribute | type | default / notes |
|---|---|---|
| `generated_at` | `datetime` (tz-aware) | now (UTC) |
| `system` | `SystemInfo` | see below |
| `scan` | `ScanInfo` | required |
| `scope` | `Scope` | `{kind: "cluster"}` |
| `sla_days` | `dict[str, int]` severity → days | `{critical:15, high:30, medium:90, low:180, negligible:365, unknown:180}` |
| `scanners` | `list[ScannerStatus]` | `[]` |
| `images` | `list[ImageRecord]` | `[]` |
| `findings` | `list[FindingRecord]` | `[]` — one per (image, vulnId, package) consensus finding |
| `workloads` | `list[WorkloadRecord]` | `[]` |
| `namespaces` | `list[NamespaceRecord]` | `[]` (derived from workloads when empty) |
| `checks` | `list[CheckDefinition]` | `[]` — posture check catalogue (SCORING.md table) |
| `posture_results` | `list[PostureResult]` | `[]` — one per (check, workload, container) evaluation |
| `trend` | `list[TrendPoint]` | `[]` — oldest → newest, last 30 scans |
| `summary` | `Summary \| None` | derived from findings when absent |

### SystemInfo
`name` (str, default `"Nebari cluster"`), `organization` (str, `""`), `cluster_name`
(str, `None`), `description` (str), `hostname` (str — FQDN, CKL HOST_FQDN), `host_name` (str — CKL HOST_NAME),
`ip_address` (str), `mac_address` (str), `poc_name`, `poc_email`, `poc_phone` (str),
`classification` (str, `"UNCLASSIFIED"`), `marking` (str, `"CUI"` — CKL `MARKING`),
`emass_system_id` (str, optional).

### ScanInfo
`id` (int|str, **required**), `status` (str), `trigger` (str), `started_at`,
`finished_at` (datetime), `requested_by` (str), `score` (float|None), `grade` (str),
`vuln_score` (float|None), `posture_score` (float|None).

### Scope
`kind` (`cluster` | `namespace` | `workload`), `name` (str|None). For `workload`, `name`
is `"<namespace>/<kind>/<name>"`. Generators re-apply the scope filter (idempotent), so
`snapshot.py` may pass either a filtered or an unfiltered snapshot.

### ScannerStatus
`name` (`trivy`|`grype`|`clair`), `enabled` (bool, True), `version` (str),
`db_updated_at` (datetime|None), `healthy` (bool), `last_error` (str|None),
`last_run_at` (datetime|None).

### ImageRecord
`id` (int|str, **required**), `ref` (str, **required**, as displayed, e.g.
`docker.io/library/nginx:1.27`), `registry`, `repository`, `tag`, `digest`
(`sha256:…`), `score` (float|None), `grade` (str), `counts` (`dict[severity,int]`),
`fixable` (`dict[severity,int]`), `namespaces` (list[str]), `workloads` (list[str]
`"<ns>/<kind>/<name>"`), `packs` (list[str] NebariApp/pack names), `containers` (int —
total container count using the image), `running_containers` (int), `running` (bool),
`os` (str — base OS from scanner metadata, e.g. `"debian 12.7"`), `scanner_status`
(`dict[scanner, "ok"|"error"|"timeout"|"unsupported"|"skipped"]`),
`scanner_versions` (`dict[scanner, str]`, optional), `agreement_index` (float 0–1),
`last_scanned_at` (datetime), `mirrored` (bool), `warnings` (list[str]),
`system_namespace` (bool — every namespace using it is a system namespace).

### FindingRecord (consensus finding)
`image_id` (**required**, matches `ImageRecord.id`), `vuln_id` (**required**),
`severity` (**required**, critical|high|medium|low|negligible|unknown), `package`
(**required**), `installed_version`, `fixed_version` (str|None), `pkg_type`,
`scanners` (list[str]), `agreement` (float 0–1), `per_scanner` (`dict[scanner,
severity]`), `cvss` (float|None), `title`, `description`, `url` (str), `fixable`
(bool, default `bool(fixed_version)`), `first_seen_at` (datetime; default
`scan.started_at`), `controls` (list[str]; default `RA-5, SI-2` + `SI-2(2)` when fixable),
`status` (`open` (default) | `fixed` | `accepted` | `false-positive` | `not_affected` (a VEX
statement suppresses it: excluded from `open_findings`, so from POA&M, SAR and OSCAL)),
`vex_status` / `vex_justification` / `vex_source` / `vex_detail` (str|None; the applied OpenVEX
statement, any status).

### WorkloadRecord
`namespace`, `kind`, `name` (str), `pack` (str|None), `score` (float|None), `grade`,
`image_ids` (list), `containers` (int), `running` (bool), `system_namespace` (bool),
`posture` (`{passed:int, failed:int}`), `counts` (dict).

### NamespaceRecord
`name`, `pack`, `managed` (bool), `score`, `grade`, `workloads` (int), `images` (int),
`system_namespace` (bool).

### CheckDefinition
`id` (SCORING.md id, e.g. `privileged`), `title`, `severity`, `category`,
`description`, `remediation`, `controls` (list[str]; default from §11 table),
`passed`, `failed` (int).

### PostureResult
`check_id` (**required**), `status` (**required**, `pass` | `fail` | `skip`),
`namespace`, `kind`, `name`, `container` (str|None), `detail` (str), `severity` (str;
default the check's), `system_namespace` (bool), `first_seen_at` (datetime|None).

### TrendPoint
`scan_id`, `finished_at` (datetime), `score` (float), `grade` (str), `critical`, `high` (int).

### Summary (optional)
`counts`, `fixable` (dict[severity,int]), `sla_overdue` (dict[severity,int]),
`images_total`, `images_scanned`, `images_failed`, `workloads`, `namespaces` (int).

## Options (`generate(..., options)`)
`dict` (camelCase keys, as POSTed): `rollupByCve` (bool, POA&M), `systemName` (str,
overrides `system.name`), `includeSystemNamespaces` (bool, default `True`),
`poamVariant` (`emass` | `generic` | `emass-legacy`, CSV only, default `emass`),
`includeSrg` (bool, STIG, default `False`: the SRG is emitted in full only on request), `now` (datetime, test hook for SLA overdue).

Accepted aliases / extras: `ImageRecord.base_os` is used when `os` is empty;
`system_namespace` flags are OR-ed with the namespace name check (a `False` default from
the model never hides `kube-system`). `FindingRecord.sla_due_at` is ignored: generators
recompute `first_seen_at + sla_days[severity]` (same formula as `views.sla_due`).

## Integration API (what the routers call)

```python
from posture.reports.registry import (REPORT_TYPES, generate, GeneratedReport,
                                      UnsupportedReport, ReportDependencyMissing)
rep = generate(report_type, fmt, snapshot, options)   # -> GeneratedReport(content, filename, content_type)
```

* `REPORT_TYPES` is the `GET /reports/types` payload: `[{type, title, formats, scopes, options, description}]`.
* `UnsupportedReport` (a `ValueError`): unknown type, format or `poamVariant`. Map it to HTTP 400/422.
* `ReportDependencyMissing` (a `RuntimeError`): WeasyPrint system libraries are missing (PDF
  only). Map it to HTTP 503 or a failed report row with that message.
* `posture.reports.stig.stig_rollup(snapshot, options)` returns
  `[{vulnId, ruleId, ruleVersion, benchmark, title, cat, severity, status, offenders, checks, method}]`
  for `GET /compliance/stig`.
* `posture.reports.stig.rules_for_check(check_id)` returns the DISA rules mapped to a
  posture check (for the check detail's "STIG rule id").
* Generators are synchronous and CPU-bound (under 1 s for typical clusters; the PDF takes a
  few seconds). Run them in a threadpool (`run_in_threadpool`) from the background task.
* Shared helpers live in `posture/reports/_common.py` (owned by the report generators).
