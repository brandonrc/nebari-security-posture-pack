"""Product / OS STIG results from the SCAP scanner (DESIGN §14).

GET /images/{id}/stig, GET /stig/benchmarks, GET /stig/benchmarks/{id}/rules, plus the helpers
behind `/summary.stig`, the `product` section of `/compliance/stig` and the `scap` entry of
`/scanners`. Benchmark ids are the catalogue keys of scap/data/benchmarks.yaml (`ssg-rhel9`,
`disa-rhel9`, ...); `xccdfId` carries the XCCDF benchmark id.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Image
from ..db.session import get_session
from ..scap.models import ScapContent, ScapImageSummary, ScapResultRow
from ..views import current_image_ids, iso, page_params, stig_brief

router = APIRouter(tags=["stig"])

RESULTS = ("pass", "fail", "notapplicable", "notchecked", "error", "unknown", "informational")
CATS = ("cat1", "cat2", "cat3")
SEV_ALIASES = {"i": "cat1", "ii": "cat2", "iii": "cat3", "high": "cat1", "medium": "cat2", "low": "cat3"}
_CAT_RANK = case({"cat1": 3, "cat2": 2, "cat3": 1}, value=ScapResultRow.severity, else_=0)
_RESULT_RANK = case({"fail": 7, "error": 6, "unknown": 5, "notchecked": 4, "informational": 3, "pass": 2,
                     "notapplicable": 1}, value=ScapResultRow.result, else_=0)


def summary_dict(s: ScapImageSummary) -> dict[str, Any]:
    c = s.counts or {}
    return {**{r: int(c.get(r, 0) or 0) for r in RESULTS}, "cat1Open": s.cat1_open, "cat2Open": s.cat2_open,
            "cat3Open": s.cat3_open, "score": s.score, "status": s.status, "evaluatedAt": iso(s.evaluated_at),
            "rootfsFidelity": s.rootfs_fidelity, "durationMs": s.duration_ms, "error": s.error,
            "oscapVersion": s.oscap_version, "scanId": s.scan_id}


def rule_dict(r: ScapResultRow) -> dict[str, Any]:
    return {"ruleId": r.rule_id, "stigId": r.stig_id, "vulnId": r.vuln_id, "svId": r.sv_id,
            "ruleVersion": r.rule_version, "cci": list(r.cci or []), "nist": list(r.nist or []),
            "severity": r.severity, "result": r.result, "title": r.title, "fixText": r.fix_text,
            "groupTitle": r.group_title, "checkedAt": iso(r.checked_at), "firstFailedAt": iso(r.first_failed_at)}


def _filters(result: str | None, severity: str | None, q: str | None) -> list[Any]:
    conds: list[Any] = []
    if result:
        conds.append(ScapResultRow.result.in_([x.strip().lower() for x in result.split(",") if x.strip()] or ["-"]))
    if severity:
        sevs = [SEV_ALIASES.get(x.strip().lower(), x.strip().lower()) for x in severity.split(",") if x.strip()]
        conds.append(ScapResultRow.severity.in_(sevs or ["-"]))
    if q:
        needle = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conds.append(or_(*(func.lower(func.coalesce(col, "")).like(needle, escape="\\") for col in (
            ScapResultRow.rule_id, ScapResultRow.title, ScapResultRow.stig_id, ScapResultRow.rule_version))))
    return conds


@router.get("/images/{image_id}/stig")
async def image_stig(
    image_id: int,
    page: int = Query(1, ge=1),
    pageSize: int = Query(100, alias="pageSize"),  # noqa: N803
    result: str | None = None,
    severity: str | None = None,
    q: str | None = Query(None, max_length=200),
    benchmark: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Per-benchmark summary and the (filtered, paged; fail first, then CAT) rules of one image.
    Paging applies per benchmark. `status` is the image-level outcome: evaluated | notApplicable |
    noContent | error | timeout | notEvaluated."""
    img = await session.get(Image, image_id)
    if img is None:
        raise HTTPException(404, detail="image not found")
    page, page_size = page_params(page, pageSize)
    summaries = (await session.execute(select(ScapImageSummary).where(ScapImageSummary.image_id == image_id)
                                       .order_by(ScapImageSummary.benchmark_key))).scalars().all()
    image_level = next((s for s in summaries if s.benchmark_key == ""), None)
    benches = []
    conds = _filters(result, severity, q)
    for s in summaries:
        if s.benchmark_key == "" or (benchmark and s.benchmark_key != benchmark):
            continue
        base = [ScapResultRow.summary_id == s.id, *conds]
        total = await session.scalar(select(func.count()).select_from(ScapResultRow).where(*base)) or 0
        rows = (await session.execute(select(ScapResultRow).where(*base).order_by(
            _RESULT_RANK.desc(), _CAT_RANK.desc(), ScapResultRow.rule_id).offset((page - 1) * page_size)
            .limit(page_size))).scalars().all()
        benches.append({"benchmarkId": s.benchmark_key, "xccdfId": s.benchmark_id, "title": s.title,
                        "version": s.version, "source": s.source, "profileId": s.profile_id,
                        "profileTitle": s.profile_title, "summary": summary_dict(s), "rules": [rule_dict(r) for r in rows],
                        "rulesTotal": int(total), "page": page, "pageSize": page_size})
    stig = stig_brief(getattr(img, "stig", None))
    status = (stig or {}).get("status") or (image_level.status if image_level else "notEvaluated")
    any_row = image_level or (summaries[0] if summaries else None)
    return {"imageId": img.id, "ref": img.ref, "digest": img.digest, "status": status, "stig": stig,
            "reason": image_level.error if image_level else None,
            "detected": (any_row.detected if any_row else None) or None,
            "rootfs": (any_row.rootfs if any_row else None) or None,
            "benchmarks": benches}


async def _current_summaries(session: AsyncSession) -> tuple[list[ScapImageSummary], set[int] | None]:
    cur = await current_image_ids(session)
    stmt = select(ScapImageSummary)
    if cur is not None:
        stmt = stmt.where(ScapImageSummary.image_id.in_(cur or {-1}))
    return list((await session.execute(stmt)).scalars().all()), cur


async def benchmark_rollup(session: AsyncSession) -> list[dict[str, Any]]:
    """Per benchmark over the current inventory: images evaluated, rule result totals, open CATs."""
    summaries, _ = await _current_summaries(session)
    by: dict[str, dict[str, Any]] = {}
    for s in summaries:
        if s.benchmark_key == "":
            continue
        b = by.setdefault(s.benchmark_key, {
            "id": s.benchmark_key, "benchmarkId": s.benchmark_key, "xccdfId": s.benchmark_id, "title": s.title,
            "version": s.version, "source": s.source, "profileId": s.profile_id, "profileTitle": s.profile_title,
            "imagesEvaluated": 0, "imagesFailing": 0, **{r: 0 for r in RESULTS}, "cat1Open": 0, "cat2Open": 0,
            "cat3Open": 0, "imagesWithCat1": 0, "meanScore": None, "_scores": [], "lastEvaluatedAt": None})
        b["imagesEvaluated"] += 1
        c = s.counts or {}
        for r in RESULTS:
            b[r] += int(c.get(r, 0) or 0)
        b["cat1Open"] += s.cat1_open
        b["cat2Open"] += s.cat2_open
        b["cat3Open"] += s.cat3_open
        b["imagesWithCat1"] += 1 if s.cat1_open else 0
        b["imagesFailing"] += 1 if int(c.get("fail", 0) or 0) else 0
        if s.score is not None:
            b["_scores"].append(s.score)
        ts = iso(s.evaluated_at)
        if ts and (b["lastEvaluatedAt"] is None or ts > b["lastEvaluatedAt"]):
            b["lastEvaluatedAt"] = ts
    out = []
    for b in sorted(by.values(), key=lambda x: (-x["cat1Open"], x["id"])):
        scores = b.pop("_scores")
        b["meanScore"] = round(sum(scores) / len(scores), 1) if scores else None
        out.append(b)
    return out


@router.get("/stig/benchmarks")
async def list_benchmarks(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """Benchmarks evaluated on the current inventory (plus content-only catalogue entries with
    imagesEvaluated 0, `id` null: available but not applicable to any image)."""
    out = await benchmark_rollup(session)
    used = {b["xccdfId"] for b in out}
    for c in (await session.execute(select(ScapContent).order_by(ScapContent.file))).scalars():
        if c.benchmark_id in used:
            continue
        out.append({"id": None, "benchmarkId": None, "xccdfId": c.benchmark_id, "title": c.title,
                    "version": c.version, "source": c.source, "profileId": None, "profileTitle": None,
                    "imagesEvaluated": 0, "imagesFailing": 0, **{r: 0 for r in RESULTS}, "cat1Open": 0,
                    "cat2Open": 0, "cat3Open": 0, "imagesWithCat1": 0, "meanScore": None, "lastEvaluatedAt": None,
                    "file": c.file})
    return out


@router.get("/stig/benchmarks/{benchmark_id}/rules")
async def benchmark_rules(
    benchmark_id: str,
    page: int = Query(1, ge=1),
    pageSize: int = Query(100, alias="pageSize"),  # noqa: N803
    severity: str | None = None,
    q: str | None = Query(None, max_length=200),
    failing: bool | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Rule rollup across the current inventory's images: failing / passing / other image counts
    per rule (fail first, then CAT, then the number of failing images)."""
    page, page_size = page_params(page, pageSize)
    cur = await current_image_ids(session)
    r = ScapResultRow
    conds = [r.benchmark_key == benchmark_id, *_filters(None, severity, q)]
    if cur is not None:
        conds.append(r.image_id.in_(cur or {-1}))
    exists = await session.scalar(select(func.count()).select_from(ScapImageSummary)
                                  .where(ScapImageSummary.benchmark_key == benchmark_id))
    if not exists:
        raise HTTPException(404, detail="benchmark not evaluated on any image")
    failing_n = func.count().filter(r.result == "fail")
    passing_n = func.count().filter(r.result == "pass")
    stmt = (select(r.rule_id, func.max(r.stig_id), func.max(r.vuln_id), func.max(r.rule_version), func.max(r.title),
                   func.max(r.severity), failing_n, passing_n, func.count(), func.max(r.sv_id))
            .where(*conds).group_by(r.rule_id))
    if failing is not None:
        stmt = stmt.having(failing_n > 0) if failing else stmt.having(failing_n == 0)
    rank = case({"cat1": 3, "cat2": 2, "cat3": 1}, value=func.max(r.severity), else_=0)
    rows = (await session.execute(stmt.order_by((failing_n > 0).desc(), rank.desc(), failing_n.desc(), r.rule_id))).all()
    total = len(rows)
    rows = rows[(page - 1) * page_size: page * page_size]
    fail_imgs: dict[str, list[int]] = {}
    if rows:
        for rule_id, image_id in (await session.execute(select(r.rule_id, r.image_id).where(
                *conds, r.result == "fail", r.rule_id.in_([x[0] for x in rows])))).all():
            fail_imgs.setdefault(rule_id, []).append(image_id)
    refs = {}
    ids = {i for v in fail_imgs.values() for i in v}
    if ids:
        refs = {i: ref for i, ref in (await session.execute(select(Image.id, Image.ref).where(Image.id.in_(ids)))).all()}
    items = [{"ruleId": x[0], "stigId": x[1], "vulnId": x[2], "ruleVersion": x[3], "title": x[4], "cat": x[5],
              "severity": x[5], "failingImages": int(x[6]), "passingImages": int(x[7]),
              "otherImages": int(x[8]) - int(x[6]) - int(x[7]), "svId": x[9],
              "failing": [{"imageId": i, "ref": refs.get(i)} for i in sorted(fail_imgs.get(x[0], []))[:50]]}
             for x in rows]
    summ = next((b for b in await benchmark_rollup(session) if b["id"] == benchmark_id), None)
    return {"benchmark": summ, "items": items, "total": total, "page": page, "pageSize": page_size}


async def stig_summary(session: AsyncSession, cur: set[int] | None) -> dict[str, Any]:
    """`/summary.stig`: over the latest done scan's images. coverage = evaluated / inventoried
    images in percent; pending = images not evaluated yet; stale = kept results whose last
    re-evaluation failed transiently (retried next scan)."""
    stmt = select(Image.id, Image.stig)
    if cur is not None:
        stmt = stmt.where(Image.id.in_(cur or {-1}))
    rows = (await session.execute(stmt)).all()
    out = {"evaluated": 0, "pass": 0, "fail": 0, "cat1Open": 0, "cat2Open": 0, "cat3Open": 0, "coverage": None,
           "notApplicable": 0, "noContent": 0, "errors": 0, "pending": 0, "stale": 0, "images": len(rows),
           "score": None}
    scores = []
    for _id, stig in rows:
        st = (stig or {}).get("status")
        if (stig or {}).get("stale"):
            out["stale"] += 1  # counted under its kept status too
        if st == "evaluated":
            out["evaluated"] += 1
            for k in ("pass", "fail", "cat1Open", "cat2Open", "cat3Open"):
                out[k] += int(stig.get(k) or 0)
            if stig.get("score") is not None:
                scores.append(float(stig["score"]))
        elif st == "notApplicable":
            out["notApplicable"] += 1
        elif st == "noContent":
            out["noContent"] += 1
        elif st in ("error", "timeout"):
            out["errors"] += 1
        else:
            out["pending"] += 1
    if rows:
        out["coverage"] = round(100.0 * out["evaluated"] / len(rows), 1)
    if scores:
        out["score"] = round(sum(scores) / len(scores), 1)
    return out


async def scap_scanner_entry(session: AsyncSession, row: Any, enabled: bool) -> dict[str, Any]:
    from ..views import scanner_dict

    d = scanner_dict("scap", row, enabled)
    d["content"] = [{"file": c.file, "benchmarkId": c.benchmark_id, "title": c.title, "version": c.version,
                     "source": c.source, "sourceName": c.source_name, "fetchedAt": iso(c.fetched_at),
                     "sha256": c.sha256, "profiles": len(c.profiles or []), "rules": c.rules}
                    for c in (await session.execute(select(ScapContent).order_by(ScapContent.file))).scalars()]
    return d
