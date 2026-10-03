"""provenance-collector-pack report document, built from our DB (DESIGN §12).

`build_report_document` is pure (tests assert the exact key set); `load_report`
pulls one completed scan's containers / images / provenance / helm rows.
Field names, order and `omitempty` behaviour follow their
`internal/report/types.go`; serialization follows Go's `json.MarshalIndent(v, "", "  ")`
(HTML-escaped `<>&`, RFC 3339 nano timestamps).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import __version__
from ..db.models import ContainerRow, Image, Scan
from .models import HelmReleaseRow, ImageProvenance
from .updates import parse_image_ref as split_tag

COLLECTOR_SUFFIX = "+posture"
REPORT_PREFIX = "provenance-"
LATEST_FILENAME = "provenance-latest.json"
_FILENAME_RE = re.compile(r"^provenance-(\d{8})-(\d{6})\.json$")


def collector_version() -> str:
    return f"{__version__}{COLLECTOR_SUFFIX}"


def go_time(dt: datetime) -> str:
    """Go `time.Time` JSON (RFC3339Nano, UTC `Z`, trailing fractional zeros trimmed)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        base += "." + f"{dt.microsecond:06d}".rstrip("0")
    return base + "Z"


def report_filename(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return f"{REPORT_PREFIX}{dt.astimezone(UTC).strftime('%Y%m%d-%H%M%S')}.json"


def filename_time(name: str) -> datetime | None:
    m = _FILENAME_RE.match(name)
    if not m:
        return None
    return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def go_json(obj: Any, indent: bool = True) -> bytes:
    """Byte-compatible with Go encoding/json: MarshalIndent("", "  ") or Encoder (+newline)."""
    if indent:
        text = json.dumps(obj, indent=2, ensure_ascii=False)
    else:
        text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n"
    text = (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    return text.encode("utf-8")


# ---------------------------------------------------------------- pure document builder
@dataclass
class ImageEntry:
    """One of their ImageRecords: unique (namespace, workload kind/name, spec image)."""

    image: str
    namespace: str
    workload_kind: str
    workload_name: str
    digest: str = ""
    signature: dict[str, Any] | None = None
    sbom: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    update: dict[str, Any] | None = None


@dataclass
class ReportInput:
    generated_at: datetime
    cluster_name: str
    images: list[ImageEntry] = field(default_factory=list)
    helm_releases: list[dict[str, Any]] = field(default_factory=list)  # HelmRecord JSON
    namespaces_scanned: list[str] | None = None


def image_record(e: ImageEntry) -> dict[str, Any]:
    rec: dict[str, Any] = {"image": e.image}
    if e.digest:
        rec["digest"] = e.digest
    rec["namespace"] = e.namespace
    rec["workload"] = {"kind": e.workload_kind, "name": e.workload_name}
    if e.signature is not None:
        rec["signature"] = e.signature
    if e.sbom is not None and e.sbom.get("hasSBOM"):
        rec["sbom"] = e.sbom
    if e.provenance is not None and e.provenance.get("hasProvenance"):
        rec["provenance"] = e.provenance
    if e.update is not None and e.update.get("updateAvailable"):
        rec["update"] = e.update
    return rec


def compute_summary(images: list[dict[str, Any]], helm: list[dict[str, Any]]) -> dict[str, int]:
    """Their Generator.computeSummary."""
    s = {"totalImages": len(images), "uniqueImages": len({i["image"] for i in images}), "signedImages": 0,
         "verifiedImages": 0, "imagesWithSBOM": 0, "imagesWithProvenance": 0, "imagesWithUpdates": 0,
         "totalHelmReleases": len(helm), "helmReleasesWithUpdates": 0}
    for img in images:
        sig = img.get("signature")
        if sig and sig.get("signed"):
            s["signedImages"] += 1
            if sig.get("verified"):
                s["verifiedImages"] += 1
        if (img.get("sbom") or {}).get("hasSBOM"):
            s["imagesWithSBOM"] += 1
        if (img.get("provenance") or {}).get("hasProvenance"):
            s["imagesWithProvenance"] += 1
        if (img.get("update") or {}).get("updateAvailable"):
            s["imagesWithUpdates"] += 1
    s["helmReleasesWithUpdates"] = sum(1 for h in helm if (h.get("update") or {}).get("updateAvailable"))
    return s


def build_report_document(inp: ReportInput) -> dict[str, Any]:
    meta: dict[str, Any] = {"generatedAt": go_time(inp.generated_at), "collectorVersion": collector_version()}
    if inp.cluster_name:
        meta["clusterName"] = inp.cluster_name
    meta["namespacesScanned"] = inp.namespaces_scanned if inp.namespaces_scanned else None
    images = [image_record(e) for e in inp.images]
    doc: dict[str, Any] = {"metadata": meta, "images": images}
    if inp.helm_releases:
        doc["helmReleases"] = inp.helm_releases
    doc["summary"] = compute_summary(images, inp.helm_releases)
    return doc


def image_entries(containers: Iterable[Any], images: dict[int, Any], prov: dict[int, Any]) -> list[ImageEntry]:
    """Their discovery dedup: one record per (namespace, owner kind, owner name, spec image)
    over containers + init containers (ephemeral containers excluded). `containers` are
    ContainerRow-like objects; `images` Image-like by id; `prov` ImageProvenance-like by image id."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[ImageEntry] = []
    for c in containers:
        if c.container_type == "ephemeral":
            continue
        key = (c.namespace, c.workload_kind, c.workload_name, c.image)
        if key in seen:
            continue
        seen.add(key)
        img = images.get(c.image_fk) if c.image_fk is not None else None
        p = prov.get(c.image_fk) if c.image_fk is not None else None
        e = ImageEntry(image=c.image, namespace=c.namespace, workload_kind=c.workload_kind,
                       workload_name=c.workload_name, digest=(img.digest or "") if img is not None else "")
        if p is not None:
            e.signature = p.signature
            e.sbom = p.sbom
            e.provenance = p.provenance
            _, tag = split_tag(c.image)
            e.update = (p.updates or {}).get(tag)
        out.append(e)
    return out


# ---------------------------------------------------------------- DB access
async def report_scans(session: AsyncSession, limit: int = 50) -> list[Scan]:
    """Completed scans that have provenance results (newest first)."""
    ids = select(ImageProvenance.scan_id).distinct()
    return list((await session.execute(
        select(Scan).where(Scan.status == "done", Scan.inventory_complete.is_(True), Scan.id.in_(ids))
        .order_by(Scan.id.desc()).limit(limit)
    )).scalars())


def scan_time(scan: Scan) -> datetime:
    return scan.finished_at or scan.started_at or scan.created_at


async def find_scan(session: AsyncSession, filename: str) -> Scan | None:
    scans = await report_scans(session, limit=500)
    if filename in ("latest", LATEST_FILENAME):
        return scans[0] if scans else None
    for s in scans:
        if report_filename(scan_time(s)) == filename:
            return s
    return None


async def load_report(session: AsyncSession, scan: Scan, cluster_name: str) -> dict[str, Any]:
    containers = list((await session.execute(
        select(ContainerRow).where(ContainerRow.scan_id == scan.id).order_by(ContainerRow.namespace, ContainerRow.id)
    )).scalars())
    image_ids = {c.image_fk for c in containers if c.image_fk is not None}
    images = {i.id: i for i in (await session.execute(select(Image).where(Image.id.in_(image_ids or {0})))).scalars()}
    prov = {p.image_id: p for p in (await session.execute(
        select(ImageProvenance).where(ImageProvenance.scan_id == scan.id))).scalars()}
    helm = list((await session.execute(
        select(HelmReleaseRow).where(HelmReleaseRow.scan_id == scan.id)
        .order_by(HelmReleaseRow.namespace, HelmReleaseRow.release_name))).scalars())
    entries = image_entries(containers, images, prov)
    helm_json = []
    for h in helm:
        rec: dict[str, Any] = {"releaseName": h.release_name, "namespace": h.namespace, "chart": h.chart,
                               "version": h.version, "appVersion": h.app_version, "status": h.status}
        if h.update:
            rec["update"] = h.update
        helm_json.append(rec)
    nss = sorted({e.namespace for e in entries})
    return build_report_document(ReportInput(generated_at=scan_time(scan), cluster_name=cluster_name,
                                             images=entries, helm_releases=helm_json, namespaces_scanned=nss))


# ---------------------------------------------------------------- exports (their export.go)
def _b(v: Any) -> str:
    return "true" if v else "false"


def csv_escape(s: str) -> str:
    if any(ch in s for ch in ',"\n'):
        return '"' + s.replace('"', '""') + '"'
    return s


CSV_HEADER = ("Image,Namespace,Workload Kind,Workload Name,Digest,Signed,Verified,SLSA Provenance,SBOM,"
              "SBOM Format,Update Available,Current Tag,Latest In Major\n")


def export_csv(doc: dict[str, Any]) -> str:
    out = [CSV_HEADER]
    for img in doc.get("images") or []:
        sig, prov, sbom, upd = img.get("signature"), img.get("provenance"), img.get("sbom"), img.get("update")
        wl = img.get("workload") or {}
        out.append(",".join([
            csv_escape(img.get("image", "")), csv_escape(img.get("namespace", "")), csv_escape(wl.get("kind", "")),
            csv_escape(wl.get("name", "")), csv_escape(img.get("digest", "")),
            _b(sig and sig.get("signed")), _b(sig and sig.get("verified")),
            _b(prov and prov.get("hasProvenance")), _b(sbom and sbom.get("hasSBOM")),
            csv_escape((sbom or {}).get("format", "")), _b(upd and upd.get("updateAvailable")),
            csv_escape((upd or {}).get("currentTag", "")), csv_escape((upd or {}).get("latestInMajor", "")),
        ]) + "\n")
    return "".join(out)


def _md_time(s: str) -> str:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return s
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def export_markdown(doc: dict[str, Any]) -> str:
    meta, s = doc.get("metadata") or {}, doc.get("summary") or {}
    b = ["# Provenance Report\n\n", f"**Generated:** {_md_time(meta.get('generatedAt', ''))}\n\n"]
    if meta.get("clusterName"):
        b.append(f"**Cluster:** {meta['clusterName']}\n\n")
    b.append(f"**Namespaces:** {', '.join(meta.get('namespacesScanned') or [])}\n\n")
    b.append("## Summary\n\n| Metric | Count |\n|---|---|\n")
    for label, key in (("Unique Images", "uniqueImages"), ("Signed", "signedImages"), ("Verified", "verifiedImages"),
                       ("SLSA Provenance", "imagesWithProvenance"), ("With SBOM", "imagesWithSBOM"),
                       ("Updates Available", "imagesWithUpdates"), ("Helm Releases", "totalHelmReleases")):
        b.append(f"| {label} | {s.get(key, 0)} |\n")
    b.append("\n## Container Images\n\n| Image | Namespace | Workload | Signed | SLSA | SBOM | Update |\n"
             "|---|---|---|---|---|---|---|\n")
    for img in doc.get("images") or []:
        sig, prov, sbom, upd = img.get("signature"), img.get("provenance"), img.get("sbom"), img.get("update")
        signed = "-" if sig is None else ("Verified" if sig.get("verified") else "Signed" if sig.get("signed") else "No")
        slsa = "-" if prov is None else ("Yes" if prov.get("hasProvenance") else "No")
        sb = "-" if sbom is None else ((sbom.get("format") or "").upper() if sbom.get("hasSBOM") else "No")
        if upd is None:
            update = "-"
        elif upd.get("updateAvailable"):
            update = upd.get("latestInMajor") or upd.get("newestAvailable") or ""
        else:
            update = "Current"
        wl = img.get("workload") or {}
        b.append(f"| `{img.get('image', '')}` | {img.get('namespace', '')} | {wl.get('kind', '')}/{wl.get('name', '')} "
                 f"| {signed} | {slsa} | {sb} | {update} |\n")
    helm = doc.get("helmReleases") or []
    if helm:
        b.append("\n## Helm Releases\n\n| Release | Namespace | Chart | Version | App Version | Status |\n"
                 "|---|---|---|---|---|---|\n")
        for h in helm:
            b.append(f"| {h.get('releaseName', '')} | {h.get('namespace', '')} | {h.get('chart', '')} "
                     f"| {h.get('version', '')} | {h.get('appVersion', '')} | {h.get('status', '')} |\n")
    return "".join(b)
