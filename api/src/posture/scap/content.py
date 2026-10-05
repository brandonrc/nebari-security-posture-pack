"""SCAP content catalogue under SCAP_CONTENT_DIR (DESIGN §14).

Sources (settings `scap.sources`, chart `scanner.scap.content.sources[]` / `disa.urls[]`):

    {"name": "ssg", "kind": "ssg", "url": "https://github.com/ComplianceAsCode/content/releases/download/
      v0.1.82/scap-security-guide-0.1.82.zip", "sha256": "765e…", "include": ["ssg-debian12-ds.xml", …]}

Each source is downloaded once (sha256 verified before anything is unpacked; a source without a
sha256 is refused), and only the members matching `include` (file-name globs; default every
`*-ds.xml` / `*Benchmark*.xml`) are written, flat, to `<dir>/sources/<name>/`. `.xml.bz2`,
`.xml.gz`, `.xml.xz`, `.zip` and `.tar.*` archives are understood. A `.source.json` marker
records url / sha256 / files, so an unchanged source is never fetched again.

Air-gapped installs set SCAP_CONTENT_OFFLINE=true (or configure no sources) and mount the
datastreams anywhere under the directory (e.g. `<dir>/local/`): nothing is fetched, every
`*.xml` is indexed.

The index (`<dir>/index.json`) lists every datastream / XCCDF file with its benchmarks and
profiles, parsed from the XML (streaming; files are 5-30 MB). Rule metadata (title, severity,
V-/SV- ids, CCIs, NIST references, fix text) is parsed on first use and cached per file sha256
in `<dir>/rules/`.
"""

from __future__ import annotations

import bz2
import fnmatch
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from ..logs import get_logger

log = get_logger(__name__)

DEFAULT_INCLUDE = ["*-ds.xml", "*Benchmark*.xml", "*-xccdf.xml"]
MAX_DOWNLOAD_BYTES = 1024**3  # a source archive larger than 1 GiB is refused
MAX_MEMBER_BYTES = 512 * 1024**2
INDEX_VERSION = 2
SKIP_DIRS = {"rules", ".tmp"}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._+-]{1,200}$")
_SV = re.compile(r"SV-\d+r\d+_rule(?![A-Za-z0-9])")
_V = re.compile(r"^V-\d+$")
_CCI = re.compile(r"^CCI-\d{6}$")
_SRG = re.compile(r"^SRG-[A-Z]+-\d{6}")
_NIST = re.compile(r"^([A-Z]{2})-(\d+)(\((\d+)\))?")


class ContentError(RuntimeError):
    pass


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def ns_of(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- sources
@dataclass
class Source:
    name: str
    url: str
    sha256: str
    kind: str = "ssg"  # ssg | disa | custom
    include: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, d: dict[str, Any], default_kind: str = "ssg") -> Source:
        url = str(d.get("url") or "").strip()
        name = str(d.get("name") or "").strip() or re.sub(r"[^A-Za-z0-9._-]+", "-", url.rsplit("/", 1)[-1])[:80]
        name = name.lstrip(".") or "source"
        if not _SAFE_NAME.match(name):
            raise ContentError(f"invalid source name {name!r}")
        kind = str(d.get("kind") or default_kind).lower()
        if kind not in ("ssg", "disa", "custom"):
            raise ContentError(f"source {name}: kind must be ssg, disa or custom")
        sha = str(d.get("sha256") or "").lower().removeprefix("sha256:").strip()
        return cls(name=name, url=url, sha256=sha, kind=kind, include=[str(x) for x in d.get("include") or []])


def parse_sources(sources: Iterable[dict[str, Any]], disa_urls: Iterable[dict[str, Any] | str] = ()) -> list[Source]:
    out: list[Source] = []
    for d in sources or []:
        out.append(Source.parse(d))
    for d in disa_urls or []:
        out.append(Source.parse({"url": d} if isinstance(d, str) else d, default_kind="disa"))
    names = [s.name for s in out]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise ContentError(f"duplicate source name(s): {', '.join(sorted(dup))}")
    return out


def _download(url: str, dest: Path, timeout: float) -> str:
    """Stream `url` to `dest`; returns the sha256 hex. https only (http allowed for localhost
    mirrors in tests via file://)."""
    if url.startswith("file://"):
        src = Path(url[len("file://"):])
        shutil.copyfile(src, dest)
        return sha256_file(dest)
    if not url.startswith("https://") and not url.startswith("http://"):
        raise ContentError(f"unsupported URL scheme: {url[:40]}")
    import httpx

    h = hashlib.sha256()
    size = 0
    with httpx.stream("GET", url, follow_redirects=True, timeout=timeout,
                      headers={"User-Agent": "nebari-security-posture-pack (SCAP content)"}) as r:
        if r.status_code != 200:
            raise ContentError(f"HTTP {r.status_code} from {url}")
        with open(dest, "wb") as fh:
            for chunk in r.iter_bytes(1 << 20):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ContentError(f"{url} is larger than {MAX_DOWNLOAD_BYTES // 1024**2} MiB")
                h.update(chunk)
                fh.write(chunk)
    return h.hexdigest()


def _copy_capped(src: Any, dest: Path) -> None:
    n = 0
    with open(dest, "wb") as out:
        while chunk := src.read(1 << 20):
            n += len(chunk)
            if n > MAX_MEMBER_BYTES:
                raise ContentError(f"{dest.name} is larger than {MAX_MEMBER_BYTES // 1024**2} MiB")
            out.write(chunk)


def unpack(archive: Path, filename: str, out_dir: Path, include: list[str]) -> list[str]:
    """Write the archive members matching `include` (by base name) flat into out_dir."""
    pats = include or DEFAULT_INCLUDE
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    def want(base: str) -> bool:
        return bool(_SAFE_NAME.match(base)) and any(fnmatch.fnmatch(base, p) for p in pats)

    def emit(base: str, fh: Any) -> None:
        target_name = base
        for suf, opener in ((".bz2", bz2.open), (".gz", gzip.open), (".xz", lzma.open)):
            if base.lower().endswith(suf):
                target_name = base[: -len(suf)]
                fh = opener(fh, "rb")
                break
        if not want(target_name):
            return
        _copy_capped(fh, out_dir / target_name)
        written.append(target_name)

    lower = filename.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                base = zi.filename.rsplit("/", 1)[-1]
                stem = re.sub(r"\.(bz2|gz|xz)$", "", base, flags=re.I)
                if not want(stem):
                    continue
                if base.lower().endswith(".zip"):  # DISA bundles nest the SCAP zip
                    with zf.open(zi) as inner_fh, tempfile.TemporaryDirectory(dir=out_dir.parent) as td:
                        p = Path(td) / "inner.zip"
                        _copy_capped(inner_fh, p)
                        written += unpack(p, base, out_dir, include)
                    continue
                with zf.open(zi) as fh:
                    emit(base, fh)
            # nested DISA zips that the include patterns did not name explicitly
            if not written:
                for zi in zf.infolist():
                    if zi.filename.lower().endswith(".zip"):
                        with zf.open(zi) as inner_fh, tempfile.TemporaryDirectory(dir=out_dir.parent) as td:
                            p = Path(td) / "inner.zip"
                            _copy_capped(inner_fh, p)
                            written += unpack(p, zi.filename.rsplit("/", 1)[-1], out_dir, include)
    elif re.search(r"\.(tar(\.(gz|bz2|xz))?|tgz|tbz2)$", lower):
        with tarfile.open(archive, "r:*") as tf:
            for ti in tf:
                if not ti.isfile():
                    continue
                base = ti.name.rsplit("/", 1)[-1]
                stem = re.sub(r"\.(bz2|gz|xz)$", "", base, flags=re.I)
                if not want(stem):
                    continue
                fh = tf.extractfile(ti)
                if fh is not None:
                    emit(base, fh)
    else:
        base = filename.rsplit("/", 1)[-1]
        with open(archive, "rb") as fh:
            emit(base, fh)
    return sorted(set(written))


def fetch_source(src: Source, content_dir: Path, timeout: float = 600, force: bool = False) -> dict[str, Any]:
    """Fetch + unpack one source (no-op when its marker matches). Returns the marker dict."""
    if not src.sha256 or not re.fullmatch(r"[0-9a-f]{64}", src.sha256):
        raise ContentError(f"source {src.name}: a sha256 is required (got {src.sha256 or 'none'})")
    out_dir = content_dir / "sources" / src.name
    marker_path = out_dir / ".source.json"
    try:
        marker = json.loads(marker_path.read_text())
    except (OSError, ValueError):
        marker = {}
    if (not force and marker.get("sha256") == src.sha256 and marker.get("url") == src.url
            and marker.get("include") == src.include and all((out_dir / f).exists() for f in marker.get("files") or [])):
        return marker
    tmp_root = content_dir / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_root) as td:
        filename = src.url.split("?", 1)[0].rsplit("/", 1)[-1] or "content"
        dl = Path(td) / "download"
        started = time.monotonic()
        got = _download(src.url, dl, timeout)
        if got != src.sha256:
            raise ContentError(f"source {src.name}: sha256 mismatch (expected {src.sha256}, got {got}); not unpacked")
        stage = Path(td) / "out"
        files = unpack(dl, filename, stage, src.include)
        if not files:
            raise ContentError(f"source {src.name}: no member matched {src.include or DEFAULT_INCLUDE}")
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stage), str(out_dir))
        marker = {"name": src.name, "kind": src.kind, "url": src.url, "sha256": src.sha256, "include": src.include,
                  "files": files, "fetchedAt": datetime.now(UTC).isoformat(),
                  "downloadSeconds": round(time.monotonic() - started, 1)}
        marker_path.write_text(json.dumps(marker, indent=1))
    log.info("scap.content.fetched", source=src.name, files=len(files))
    return marker


# --------------------------------------------------------------------------- index
def _benchmark_source(bid: str, publisher: str, default: str) -> str:
    if bid.startswith("xccdf_mil.disa.stig") or "disa" in publisher.lower():
        return "disa"
    if bid.startswith("xccdf_org.ssgproject"):
        return "ssg"
    return default


def scan_xml(path: Path) -> dict[str, Any]:
    """Benchmarks / profiles of a datastream or XCCDF file (streaming parse; a profile's own
    <title>/<version> are attributed to the profile, not the benchmark)."""
    benchmarks: list[dict[str, Any]] = []
    datastreams: list[str] = []
    cur: dict[str, Any] | None = None
    in_profile = 0
    in_rule_or_group = 0
    for event, el in ET.iterparse(path, events=("start", "end")):
        name = local(el.tag)
        if event == "start":
            if name == "data-stream":
                datastreams.append(el.get("id", ""))
            elif name == "Benchmark":
                cur = {"id": el.get("id", ""), "title": "", "version": "", "status": "", "publisher": "",
                       "releaseInfo": "", "profiles": [], "rules": 0, "platforms": []}
            elif cur is not None and name == "Profile":
                in_profile += 1
                cur["profiles"].append({"id": el.get("id", ""), "title": "", "version": ""})
            elif cur is not None and name in ("Rule", "Group", "Value"):
                in_rule_or_group += 1
            continue
        if cur is None:
            if name not in ("data-stream", "data-stream-collection"):
                el.clear()
            continue
        if name in ("Rule", "Group", "Value"):
            in_rule_or_group -= 1
            if name == "Rule":
                cur["rules"] += 1
            el.clear()
            continue
        if in_rule_or_group:
            continue
        text = (el.text or "").strip()
        if name == "Profile":
            in_profile -= 1
            el.clear()
        elif in_profile:
            prof = cur["profiles"][-1]
            if name == "title" and not prof["title"]:
                prof["title"] = text
            elif name == "version" and not prof["version"]:
                prof["version"] = text
        elif name == "title" and not cur["title"]:
            cur["title"] = text
        elif name == "version" and not cur["version"]:
            cur["version"] = text
        elif name == "status" and not cur["status"]:
            cur["status"] = text
            cur["statusDate"] = el.get("date") or ""
        elif name == "publisher" and not cur["publisher"]:
            cur["publisher"] = text
        elif name == "plain-text" and el.get("id") == "release-info":
            cur["releaseInfo"] = text
        elif name == "platform" and el.get("idref") and len(cur["platforms"]) < 20:
            cur["platforms"].append(el.get("idref"))
        elif name == "Benchmark":
            benchmarks.append(cur)
            cur = None
            el.clear()
    return {"datastreams": datastreams, "benchmarks": benchmarks}


def _source_of(rel: str, markers: dict[str, dict[str, Any]]) -> tuple[str, str | None, dict[str, Any] | None]:
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == "sources":
        m = markers.get(parts[1])
        return (m or {}).get("kind", "custom"), parts[1], m
    return "custom", None, None


def build_index(content_dir: Path) -> dict[str, Any]:
    """(Re)index every XML file under content_dir; unchanged files reuse their entry."""
    content_dir = Path(content_dir)
    idx_path = content_dir / "index.json"
    try:
        old = json.loads(idx_path.read_text())
        if old.get("version") != INDEX_VERSION:
            old = {}
    except (OSError, ValueError):
        old = {}
    old_files = old.get("files") or {}
    markers: dict[str, dict[str, Any]] = {}
    for m in (content_dir / "sources").glob("*/.source.json") if (content_dir / "sources").exists() else []:
        try:
            markers[m.parent.name] = json.loads(m.read_text())
        except (OSError, ValueError):
            pass
    files: dict[str, Any] = {}
    for root, dirs, names in os.walk(content_dir):
        rel_root = os.path.relpath(root, content_dir)
        dirs[:] = [d for d in dirs if not (rel_root == "." and d in SKIP_DIRS) and not d.startswith(".")]
        for n in sorted(names):
            if not n.lower().endswith(".xml") or n.startswith("."):
                continue
            p = Path(root) / n
            rel = os.path.relpath(p, content_dir)
            st = p.stat()
            prev = old_files.get(rel)
            if prev and prev.get("size") == st.st_size and prev.get("mtime") == int(st.st_mtime):
                files[rel] = prev
                continue
            kind, sname, marker = _source_of(rel, markers)
            entry: dict[str, Any] = {"size": st.st_size, "mtime": int(st.st_mtime), "source": kind,
                                     "sourceName": sname, "url": (marker or {}).get("url"),
                                     "fetchedAt": (marker or {}).get("fetchedAt")
                                     or datetime.fromtimestamp(st.st_mtime, UTC).isoformat()}
            try:
                entry["sha256"] = sha256_file(p)
                info = scan_xml(p)
                entry["datastreams"] = info["datastreams"]
                bms = info["benchmarks"]
                for b in bms:
                    b["source"] = _benchmark_source(b["id"], b.get("publisher", ""), kind)
                entry["benchmarks"] = bms
                if not bms:
                    entry["error"] = "no XCCDF benchmark in file"
            except (ET.ParseError, OSError) as e:
                entry["error"] = f"unparseable: {e}"[:300]
                entry["benchmarks"] = []
            files[rel] = entry
    idx = {"version": INDEX_VERSION, "indexedAt": datetime.now(UTC).isoformat(), "files": files}
    tmp = idx_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=1))
    os.replace(tmp, idx_path)
    return idx


def load_index(content_dir: Path) -> dict[str, Any]:
    try:
        return json.loads((Path(content_dir) / "index.json").read_text())
    except (OSError, ValueError):
        return {"files": {}}


def catalogue(idx: dict[str, Any]) -> list[dict[str, Any]]:
    """Flat list of benchmarks [{path, sha256, benchmarkId, title, version, source, profiles, rules, ...}]."""
    out = []
    for rel, f in sorted((idx.get("files") or {}).items()):
        for b in f.get("benchmarks") or []:
            out.append({"path": rel, "file": rel.rsplit("/", 1)[-1], "sha256": f.get("sha256"),
                        "sizeBytes": f.get("size"), "fetchedAt": f.get("fetchedAt"), "url": f.get("url"),
                        "sourceName": f.get("sourceName"), "datastreamId": (f.get("datastreams") or [None])[0],
                        "benchmarkId": b["id"], "title": b.get("title", ""), "version": b.get("version", ""),
                        "releaseInfo": b.get("releaseInfo", ""), "status": b.get("status", ""),
                        "statusDate": b.get("statusDate", ""), "source": b.get("source", f.get("source")),
                        "profiles": b.get("profiles", []), "rules": b.get("rules", 0)})
    return out


def find_content(cat: list[dict[str, Any]], datastream_globs: list[str], profiles: list[str]) -> tuple[dict[str, Any], str] | None:
    """First catalogue entry whose file matches a glob (in glob order) and that offers one of the
    profiles (first wins; else the benchmark's first profile). -> (entry, profile id)."""
    for pat in datastream_globs:
        for e in cat:
            if not fnmatch.fnmatch(e["file"], pat):
                continue
            ids = [p["id"] for p in e["profiles"]]
            for want in profiles:
                if want in ids:
                    return e, want
            if ids:
                return e, ids[0]
    return None


# --------------------------------------------------------------------------- rule metadata
def _norm_nist(text: str) -> str | None:
    m = _NIST.match(text.strip())
    if not m:
        return None
    return f"{m.group(1)}-{int(m.group(2))}" + (f"({int(m.group(4))})" if m.group(4) else "")


def parse_rules(path: Path, benchmark_id: str | None = None) -> dict[str, dict[str, Any]]:
    """ruleId -> {title, severity, version, vulnId, svId, stigId, cci[], nist[], srg[], fixText, groupTitle}."""
    rules: dict[str, dict[str, Any]] = {}
    in_bench = benchmark_id is None
    groups: list[dict[str, str]] = []
    cur: dict[str, Any] | None = None
    for event, el in ET.iterparse(path, events=("start", "end")):
        name = local(el.tag)
        if event == "start":
            if name == "Benchmark":
                in_bench = benchmark_id is None or el.get("id") == benchmark_id
            elif in_bench and name == "Group":
                groups.append({"id": el.get("id", ""), "title": ""})
            elif in_bench and name == "Rule":
                rid = el.get("id", "")
                cur = {"title": "", "severity": el.get("severity") or "unknown", "version": "", "vulnId": None,
                       "svId": None, "stigId": None, "cci": [], "nist": [], "srg": [], "fixText": None,
                       "groupId": groups[-1]["id"] if groups else "", "groupTitle": groups[-1]["title"] if groups else ""}
                rules[rid] = cur
                m = _SV.search(rid)
                if m:
                    cur["svId"] = m.group(0)
            continue
        if not in_bench:
            el.clear()
            continue
        text = (el.text or "").strip()
        if name == "Group":
            if groups:
                groups.pop()
            el.clear()
        elif cur is None:
            if name == "title" and groups and not groups[-1]["title"]:
                groups[-1]["title"] = text
        elif name == "Rule":
            gid = cur["groupId"]
            gm = re.search(r"(V-\d+)$", gid)
            if gm and not cur["vulnId"]:
                cur["vulnId"] = gm.group(1)
            if groups and not cur["groupTitle"]:
                cur["groupTitle"] = groups[-1]["title"]
            cur = None
            el.clear()
        elif name == "title" and not cur["title"]:
            cur["title"] = text
        elif name == "version" and not cur["version"]:
            cur["version"] = text
        elif name == "fixtext" and cur["fixText"] is None:
            cur["fixText"] = "".join(el.itertext()).strip()[:4000] or None
        elif name in ("ident", "reference"):
            val = "".join(el.itertext()).strip()
            href = (el.get("href") or el.get("system") or "").lower()
            if _CCI.match(val):
                cur["cci"].append(val)
            elif _V.match(val):
                cur["vulnId"] = cur["vulnId"] or val
            elif _SV.fullmatch(val):
                cur["svId"] = cur["svId"] or val
            elif _SRG.match(val):
                if val not in cur["srg"]:
                    cur["srg"].append(val)
            elif "800-53" in href:
                n = _norm_nist(val)
                if n and n not in cur["nist"]:
                    cur["nist"].append(n)
            elif ("cyber.mil" in href or "iase.disa.mil" in href) and re.match(r"^[A-Z0-9]+(-[A-Z0-9]+)+-\d{5,6}$", val):
                cur["stigId"] = cur["stigId"] or val
    for r in rules.values():
        if r["groupTitle"] and _SRG.match(r["groupTitle"]) and r["groupTitle"] not in r["srg"]:
            r["srg"].append(r["groupTitle"])
        if not r["stigId"] and r["version"] and re.match(r"^[A-Z0-9]+(-[A-Z0-9]+)+-\d{5,6}$", r["version"]):
            r["stigId"] = r["version"]
        r["cci"] = sorted(set(r["cci"]))
    return rules


def rule_metadata(content_dir: Path, path: Path, sha256: str, benchmark_id: str) -> dict[str, dict[str, Any]]:
    cache = Path(content_dir) / "rules" / f"{sha256}-{hashlib.sha1(benchmark_id.encode()).hexdigest()[:10]}.json"
    try:
        return json.loads(cache.read_text())
    except (OSError, ValueError):
        pass
    rules = parse_rules(path, benchmark_id)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".tmp")
        tmp.write_text(json.dumps(rules))
        os.replace(tmp, cache)
    except OSError:
        pass
    return rules


# --------------------------------------------------------------------------- refresh
@dataclass
class RefreshResult:
    fetched: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    index: dict[str, Any] = field(default_factory=dict)


def refresh(content_dir: Path, sources: list[Source], offline: bool = False, timeout: float = 600) -> RefreshResult:
    content_dir = Path(content_dir)
    content_dir.mkdir(parents=True, exist_ok=True)
    res = RefreshResult()
    if not offline:
        for src in sources:
            marker_before = None
            try:
                marker_before = json.loads((content_dir / "sources" / src.name / ".source.json").read_text())
            except (OSError, ValueError):
                pass
            try:
                m = fetch_source(src, content_dir, timeout)
                (res.unchanged if marker_before and marker_before.get("sha256") == m.get("sha256") else res.fetched).append(src.name)
            except Exception as e:  # noqa: BLE001  (one bad source never blocks the others)
                res.errors[src.name] = str(e)[:300]
                log.warning("scap.content.fetch_failed", source=src.name, error=str(e)[:300])
    shutil.rmtree(content_dir / ".tmp", ignore_errors=True)
    res.index = build_index(content_dir)
    return res
