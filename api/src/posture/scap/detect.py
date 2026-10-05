"""What a rootfs contains (os-release + product probes) -> candidate benchmarks (DESIGN §14).

Nothing in the image is executed: product versions come from package databases, well-known
files and printable strings inside binaries (`postgres (PostgreSQL) 16.4`, `nginx/1.27.1`).
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .rootfs import read_file, secure_join

BENCHMARKS_PATH = Path(__file__).parent / "data" / "benchmarks.yaml"
BINARY_SCAN_LIMIT = 96 * 1024 * 1024  # bytes of a binary searched for a version string


@dataclass
class Detection:
    os: dict[str, Any] = field(default_factory=dict)  # id, versionId, idLike[], prettyName, name
    products: list[dict[str, str]] = field(default_factory=list)  # [{name, version, path}]
    distroless: bool = False  # no os-release and no shell / package manager

    def as_dict(self) -> dict[str, Any]:
        return {"os": dict(self.os), "products": [dict(p) for p in self.products], "distroless": self.distroless}


def parse_os_release(text: str) -> dict[str, Any]:
    vals: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        vals[k.strip()] = v
    out: dict[str, Any] = {}
    if vals.get("ID"):
        out["id"] = vals["ID"].lower()
    if vals.get("VERSION_ID"):
        out["versionId"] = vals["VERSION_ID"]
    if vals.get("ID_LIKE"):
        out["idLike"] = vals["ID_LIKE"].lower().split()
    for k, key in (("PRETTY_NAME", "prettyName"), ("NAME", "name"), ("VERSION_CODENAME", "codename")):
        if vals.get(k):
            out[key] = vals[k]
    return out


def _debian_version(root: Path) -> str | None:
    raw = read_file(root, "etc/debian_version", 256)
    return raw.decode("utf-8", "replace").strip() if raw else None


def detect_os(root: Path) -> dict[str, Any]:
    for name in ("etc/os-release", "usr/lib/os-release"):
        raw = read_file(root, name, 64 * 1024)
        if raw:
            osr = parse_os_release(raw.decode("utf-8", "replace"))
            if osr.get("id") == "debian" and not osr.get("versionId"):  # testing / sid
                dv = _debian_version(root)
                if dv and dv[:2].isdigit():
                    osr["versionId"] = dv.split(".")[0]
            if osr:
                return osr
    raw = read_file(root, "etc/redhat-release", 1024)
    if raw:
        m = re.search(r"release (\d+(?:\.\d+)?)", raw.decode("utf-8", "replace"))
        return {"id": "rhel", "versionId": m.group(1) if m else "", "prettyName": raw.decode().strip()}
    raw = read_file(root, "etc/alpine-release", 256)
    if raw:
        return {"id": "alpine", "versionId": raw.decode().strip()}
    return {}


# --------------------------------------------------------------------------- products
_VERSION_RES = {
    "postgresql": re.compile(rb"postgres \(PostgreSQL\) (\d+(?:\.\d+)?)"),
    "nginx": re.compile(rb"nginx/(\d+\.\d+\.\d+)"),
    "httpd": re.compile(rb"Apache/(\d+\.\d+\.\d+)"),
}

# product -> glob patterns (relative to the rootfs). Symlinks are followed inside the rootfs.
PRODUCT_PATHS: dict[str, list[str]] = {
    "postgresql": ["usr/lib/postgresql/*/bin/postgres", "usr/pgsql-*/bin/postgres", "usr/local/pgsql/bin/postgres",
                   "usr/local/bin/postgres", "usr/bin/postgres", "opt/bitnami/postgresql/bin/postgres"],
    "nginx": ["usr/sbin/nginx", "usr/local/nginx/sbin/nginx", "opt/bitnami/nginx/sbin/nginx"],
    "httpd": ["usr/sbin/httpd", "usr/sbin/apache2", "usr/local/apache2/bin/httpd"],
    "java": ["usr/lib/jvm/*/release", "opt/java/openjdk/release", "usr/local/openjdk-*/release"],
    "tomcat": ["usr/local/tomcat/RELEASE-NOTES", "opt/tomcat/RELEASE-NOTES", "usr/share/tomcat*/RELEASE-NOTES"],
    "docker": ["usr/bin/dockerd", "usr/local/bin/dockerd"],
    "kubernetes": ["usr/local/bin/kubelet", "usr/bin/kubelet", "usr/local/bin/kube-apiserver", "kube-apiserver"],
}


def _glob(root: Path, pattern: str) -> list[Path]:
    """Glob inside the rootfs. Only the matched path's *leaf* may be a symlink (resolved with
    secure_join); patterns never traverse a symlinked directory out of the rootfs."""
    base = str(root)
    hits = sorted(glob.glob(os.path.join(glob.escape(base), pattern)))
    out = []
    for h in hits:
        rel = os.path.relpath(h, base)
        if rel.startswith(".."):
            continue
        try:
            out.append(secure_join(root, rel, follow_final=True))
        except Exception:  # noqa: BLE001
            continue
    return out


def _scan_binary(path: Path, rx: re.Pattern[bytes]) -> str | None:
    try:
        with open(path, "rb") as fh:
            tail = b""
            read = 0
            while read < BINARY_SCAN_LIMIT:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                read += len(chunk)
                m = rx.search(tail + chunk)
                if m:
                    return m.group(1).decode()
                tail = chunk[-128:]
    except OSError:
        return None
    return None


def _product_version(name: str, path: Path, root: Path) -> str:
    rel = os.path.relpath(path, root)
    if name == "postgresql":
        m = re.search(r"(?:postgresql/|pgsql-)(\d+(?:\.\d+)?)", rel)
        if m:
            return m.group(1)
    if name in _VERSION_RES:
        return _scan_binary(path, _VERSION_RES[name]) or ""
    if name == "java":
        raw = read_file(root, rel, 16 * 1024) or b""
        m = re.search(rb'JAVA_VERSION="([^"]+)"', raw)
        return m.group(1).decode() if m else ""
    if name == "tomcat":
        raw = read_file(root, rel, 16 * 1024) or b""
        m = re.search(rb"Apache Tomcat Version (\d+\.\d+\.\d+)", raw)
        return m.group(1).decode() if m else ""
    return ""


def detect_products(root: Path) -> list[dict[str, str]]:
    out = []
    for name, patterns in PRODUCT_PATHS.items():
        for pat in patterns:
            hits = [p for p in _glob(root, pat) if p.is_file()]
            if hits:
                path = hits[-1]  # highest version directory sorts last
                out.append({"name": name, "version": _product_version(name, path, root),
                            "path": "/" + os.path.relpath(path, root)})
                break
    return out


def _lexists(root: Path, rel: str) -> bool:
    try:
        p = secure_join(root, rel)
    except Exception:  # noqa: BLE001
        return False
    return p.exists() or p.is_symlink()


def detect(root: Path) -> Detection:
    root = Path(root)
    osr = detect_os(root)
    products = detect_products(root)
    shell = any(_lexists(root, p) for p in ("bin/sh", "usr/bin/sh", "bin/busybox"))
    pkgdb = any(_lexists(root, p) for p in ("var/lib/dpkg/status", "var/lib/rpm", "usr/lib/sysimage/rpm",
                                            "lib/apk/db/installed"))
    distroless = not shell and not pkgdb
    if distroless and _lexists(root, "var/lib/dpkg/status.d"):
        osr.setdefault("variant", "distroless")
    return Detection(os=osr, products=products, distroless=distroless)


# --------------------------------------------------------------------------- candidates
@lru_cache(maxsize=8)
def load_candidates(path: str | None = None, extra: str | None = None) -> tuple[dict[str, Any], ...]:
    """Built-in candidates (or `path`), then those of `extra` (SCAP_BENCHMARKS_FILE: operator-
    defined benchmarks, e.g. a custom or tailored datastream; same format)."""
    items: list[dict[str, Any]] = []
    for f in [path or str(BENCHMARKS_PATH), *([extra] if extra else [])]:
        with open(f, encoding="utf-8") as fh:
            items += (yaml.safe_load(fh) or {}).get("candidates") or []
    out = []
    for c in items:
        for k in ("key", "family", "source", "match", "datastreams", "profiles"):
            if k not in c:
                raise ValueError(f"benchmarks.yaml: candidate {c.get('key')!r} lacks {k!r}")
        out.append(c)
    return tuple(out)


def _matches(match: dict[str, str], det: Detection, product: dict[str, str] | None) -> bool:
    for key, pattern in match.items():
        rx = re.compile(pattern, re.IGNORECASE)
        if key == "os.id":
            ok = bool(rx.search(det.os.get("id", "")))
        elif key == "os.versionId":
            ok = bool(rx.search(det.os.get("versionId", "")))
        elif key == "os.idLike":
            ok = any(rx.search(x) for x in det.os.get("idLike", []))
        elif key == "product":
            ok = product is not None and bool(rx.search(product["name"]))
        elif key == "productVersion":
            ok = product is not None and bool(rx.search(product.get("version", "")))
        else:
            raise ValueError(f"benchmarks.yaml: unknown match key {key!r}")
        if not ok:
            return False
    return True


def candidates_for(det: Detection, prefer_disa: bool = True, path: str | None = None,
                   extra: str | None = None) -> list[dict[str, Any]]:
    """Matching candidates, at most one source per family is *preferred* (ordered first); the
    caller evaluates the first candidate per family that has content."""
    hits = []
    for c in load_candidates(path, extra or None):
        needs_product = any(k.startswith("product") for k in c["match"])
        if needs_product:
            for p in det.products:
                if _matches(c["match"], det, p):
                    hits.append({**c, "product": p})
                    break
        elif _matches(c["match"], det, None):
            hits.append(dict(c))
    order = {"disa": 0, "ssg": 1} if prefer_disa else {"ssg": 0, "disa": 1}
    hits.sort(key=lambda c: order.get(c["source"], 2))
    return hits


def match_file(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)
