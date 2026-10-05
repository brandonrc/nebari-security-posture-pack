"""Flatten an OCI image layout (posture.image_cache) into a root filesystem directory (DESIGN §14).

`flatten(layout, dest, max_bytes)` applies the manifest's layers in order:

* OCI whiteouts: `.wh.<name>` deletes `<name>` from the lower layers, `.wh..wh..opq` empties
  the directory of everything the lower layers put there. Whiteouts of a layer are applied
  before its other entries are written, so they never remove the layer's own files.
* Every path is resolved inside `dest` (`secure_join`: `..`, absolute paths and symlinks are
  confined to the rootfs; a layer can never write outside it). Hard links must point inside
  the rootfs too.
* Ownership, mode (incl. setuid/setgid/sticky), mtime and `SCHILY.xattr.*` extended attributes
  are kept when the process can: root in its container with CAP_CHOWN / CAP_FOWNER /
  CAP_DAC_OVERRIDE / CAP_FSETID (+ CAP_SETFCAP for `security.capability`). Many STIG rules
  check owners and modes, so a non-root extraction is recorded as `fidelity: degraded` (files
  owned by the worker uid, setuid bits / xattrs dropped) and the stage says so next to every
  result. Device nodes are never created (no CAP_MKNOD); they are counted.
* `max_bytes` caps the uncompressed size written (SCAP_MAX_ROOTFS_GB); exceeding it aborts with
  `RootfsTooLarge` and the partial tree is removed.

Layers are read as streams (gzip / zstd via the `zstd` binary / plain tar); nothing in the image
is ever executed.
"""

from __future__ import annotations

import errno
import gzip
import json
import os
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

WHITEOUT_PREFIX = ".wh."
OPAQUE = ".wh..wh..opq"
MAX_SYMLINK_HOPS = 40
LAYER_MEDIA_TAR = ("tar", "tar+gzip", "tar+zstd")


class RootfsError(RuntimeError):
    """Image layout or layer that cannot be flattened (short reason in the message)."""


class RootfsTooLarge(RootfsError):
    pass


@dataclass
class RootfsResult:
    path: Path
    fidelity: str  # full | degraded
    layers: int = 0
    bytes_written: int = 0
    files: int = 0
    skipped_devices: int = 0
    dropped_xattrs: int = 0
    unsafe_entries: int = 0  # paths escaping the rootfs, refused
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"fidelity": self.fidelity, "layers": self.layers, "bytesWritten": self.bytes_written,
                "files": self.files, "skippedDevices": self.skipped_devices, "droppedXattrs": self.dropped_xattrs,
                "unsafeEntries": self.unsafe_entries, "notes": list(self.notes)}


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --------------------------------------------------------------------------- path confinement
def _clean_parts(name: str) -> list[str]:
    """Tar member name -> path components (no '', '.', leading '/'); '..' kept for secure_join."""
    return [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]


def secure_join(root: Path, name: str, follow_final: bool = False) -> Path:
    """`root/name` with every intermediate symlink resolved *inside* root (absolute link targets
    are relative to root, `..` never climbs above it). The final component is followed only
    with `follow_final`. Raises RootfsError on symlink loops."""
    root = Path(root)
    parts = _clean_parts(name)
    resolved: list[str] = []
    hops = 0
    i = 0
    while i < len(parts):
        part = parts[i]
        i += 1
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        last = i == len(parts)
        if (not last or follow_final) and candidate.is_symlink():
            hops += 1
            if hops > MAX_SYMLINK_HOPS:
                raise RootfsError(f"too many symlink levels resolving {name!r}")
            target = os.readlink(candidate)
            tparts = _clean_parts(target)
            if target.startswith("/"):
                resolved = []
            parts = tparts + parts[i:]
            i = 0
            continue
        resolved.append(part)
    return root.joinpath(*resolved)


def read_file(root: Path, name: str, limit: int = 1 << 20) -> bytes | None:
    """Read a file of the rootfs (symlinks followed inside it). None when absent / not a file."""
    try:
        p = secure_join(root, name, follow_final=True)
    except RootfsError:
        return None
    try:
        if not p.is_file():
            return None
        with open(p, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


# --------------------------------------------------------------------------- layout
def _blob(layout: Path, digest: str) -> Path:
    algo, _, hexd = str(digest).partition(":")
    if algo != "sha256" or len(hexd) != 64 or not all(c in "0123456789abcdef" for c in hexd):
        raise RootfsError(f"unsupported digest {digest!r}")
    return layout / "blobs" / "sha256" / hexd


def layout_layers(layout: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(layer descriptors in order, image config) of the single-manifest OCI layout."""
    try:
        index = json.loads((layout / "index.json").read_text())
        manifests = index.get("manifests") or []
        if len(manifests) != 1:
            raise RootfsError(f"layout has {len(manifests)} manifests (expected 1)")
        manifest = json.loads(_blob(layout, manifests[0]["digest"]).read_text())
    except (OSError, ValueError, KeyError) as e:
        raise RootfsError(f"unreadable OCI layout: {e}") from e
    if manifest.get("manifests"):
        raise RootfsError("layout holds an image index, not an image manifest")
    config: dict[str, Any] = {}
    cfg = manifest.get("config") or {}
    if cfg.get("digest"):
        try:
            config = json.loads(_blob(layout, cfg["digest"]).read_text())
        except (OSError, ValueError):
            config = {}
    return list(manifest.get("layers") or []), config


def _open_layer(path: Path, media_type: str) -> tuple[IO[bytes], subprocess.Popen | None]:
    mt = (media_type or "").lower()
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if mt.endswith("zstd") or magic == b"\x28\xb5\x2f\xfd":
        try:
            proc = subprocess.Popen(["zstd", "-dc", "--", str(path)], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except FileNotFoundError as e:
            raise RootfsError("zstd layer but no `zstd` binary") from e
        assert proc.stdout is not None
        return proc.stdout, proc
    if magic[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb"), None  # type: ignore[return-value]
    return open(path, "rb"), None  # noqa: SIM115


# --------------------------------------------------------------------------- extraction
class _Extractor:
    def __init__(self, dest: Path, max_bytes: int, privileged: bool):
        self.dest = dest
        self.max_bytes = max_bytes
        self.privileged = privileged
        self.res = RootfsResult(dest, "full" if privileged else "degraded")
        self.dir_meta: dict[str, tarfile.TarInfo] = {}
        self._fcap = privileged

    # ---- helpers
    def _remove(self, p: Path) -> None:
        try:
            if p.is_dir() and not p.is_symlink():
                self._make_writable_tree(p)
                shutil.rmtree(p)
            elif p.exists() or p.is_symlink():
                p.unlink()
        except FileNotFoundError:
            pass

    def _make_writable_tree(self, p: Path) -> None:
        if self.privileged:
            return
        for root, dirs, _ in os.walk(p):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o700)
                except OSError:
                    pass

    def _ensure_parent(self, p: Path) -> None:
        parent = p.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        elif not parent.is_dir():
            raise RootfsError(f"parent of {p} is not a directory")
        if not self.privileged:
            try:
                os.chmod(parent, stat.S_IMODE(parent.stat().st_mode) | 0o700)
            except OSError:
                pass

    def _apply_meta(self, p: Path, ti: tarfile.TarInfo, is_link: bool = False) -> None:
        if self.privileged:
            try:
                os.chown(p, ti.uid, ti.gid, follow_symlinks=False)
            except OSError:
                self.res.fidelity = "degraded"
        if is_link:
            try:
                os.utime(p, (ti.mtime, ti.mtime), follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
            return
        mode = ti.mode & 0o7777
        if not self.privileged:
            mode &= ~(stat.S_ISUID | stat.S_ISGID)
            if ti.isdir():
                mode |= 0o700
            else:
                mode |= 0o600
        try:
            os.chmod(p, mode)
        except OSError:
            self.res.fidelity = "degraded"
        self._xattrs(p, ti)
        try:
            os.utime(p, (ti.mtime, ti.mtime))
        except OSError:
            pass

    def _xattrs(self, p: Path, ti: tarfile.TarInfo) -> None:
        for k, v in (ti.pax_headers or {}).items():
            if not k.startswith("SCHILY.xattr."):
                continue
            name = k[len("SCHILY.xattr."):]
            raw = v.encode("utf-8", "surrogateescape") if isinstance(v, str) else v
            if not self.privileged and not name.startswith("user."):
                self.res.dropped_xattrs += 1
                continue
            try:
                os.setxattr(p, name, raw, follow_symlinks=False)
            except OSError:
                self.res.dropped_xattrs += 1

    # ---- whiteouts (pass 1)
    def whiteouts(self, members: list[tuple[str, str]]) -> None:
        for kind, name in members:
            try:
                if kind == "opaque":
                    d = secure_join(self.dest, name)
                    if d.is_dir() and not d.is_symlink():
                        for child in list(d.iterdir()):
                            self._remove(child)
                else:
                    self._remove(secure_join(self.dest, name))
            except RootfsError:
                self.res.unsafe_entries += 1

    # ---- entries (pass 2)
    def entry(self, tf: tarfile.TarFile, ti: tarfile.TarInfo) -> None:
        parts = _clean_parts(ti.name)
        if not parts:
            return
        if ".." in parts:
            self.res.unsafe_entries += 1
            return
        base = parts[-1]
        if base.startswith(WHITEOUT_PREFIX):
            return  # handled in pass 1
        try:
            parent = secure_join(self.dest, "/".join(parts[:-1]), follow_final=True)
        except RootfsError:
            self.res.unsafe_entries += 1
            return
        target = parent / base
        if not _inside(self.dest, target):
            self.res.unsafe_entries += 1
            return
        self._ensure_parent(target)
        if ti.isdir():
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                self._remove(target)
            target.mkdir(exist_ok=True)
            if not self.privileged:
                os.chmod(target, 0o700 | (ti.mode & 0o777))
            self.dir_meta[str(target)] = ti
            return
        if target.exists() or target.is_symlink():
            self._remove(target)
        if ti.isreg():
            self._budget(ti.size)
            src = tf.extractfile(ti)
            with open(target, "wb") as out:
                if src is not None:
                    shutil.copyfileobj(src, out, 1 << 20)
            self.res.files += 1
            self._apply_meta(target, ti)
        elif ti.issym():
            os.symlink(ti.linkname, target)
            self._apply_meta(target, ti, is_link=True)
        elif ti.islnk():
            try:
                src_path = secure_join(self.dest, ti.linkname)
            except RootfsError:
                self.res.unsafe_entries += 1
                return
            if not _inside(self.dest, src_path) or not (src_path.exists() or src_path.is_symlink()):
                self.res.unsafe_entries += 1
                return
            try:
                os.link(src_path, target, follow_symlinks=False)
            except OSError:
                shutil.copy2(src_path, target, follow_symlinks=False)
            self.res.files += 1
        elif ti.isfifo():
            os.mkfifo(target)
            self._apply_meta(target, ti)
        elif ti.ischr() or ti.isblk():
            self.res.skipped_devices += 1

    def _budget(self, n: int) -> None:
        self.res.bytes_written += max(0, int(n))
        if self.max_bytes and self.res.bytes_written > self.max_bytes:
            raise RootfsTooLarge(f"rootfs exceeds {self.max_bytes / 1024**3:.1f} GB (SCAP_MAX_ROOTFS_GB)")

    def finish_dirs(self) -> None:
        # deepest first, so a read-only parent is set after its children
        for path in sorted(self.dir_meta, key=lambda s: s.count("/"), reverse=True):
            p = Path(path)
            if p.is_dir() and not p.is_symlink():
                self._apply_meta(p, self.dir_meta[path])


def _inside(root: Path, p: Path) -> bool:
    try:
        Path(os.path.normpath(p)).relative_to(os.path.normpath(root))
        return True
    except ValueError:
        return False


def _scan_whiteouts(path: Path, media_type: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    fh, proc = _open_layer(path, media_type)
    try:
        with tarfile.open(fileobj=fh, mode="r|") as tf:
            for ti in tf:
                parts = _clean_parts(ti.name)
                if not parts:
                    continue
                base = parts[-1]
                if base == OPAQUE:
                    out.append(("opaque", "/".join(parts[:-1])))
                elif base.startswith(WHITEOUT_PREFIX):
                    out.append(("whiteout", "/".join(parts[:-1] + [base[len(WHITEOUT_PREFIX):]])))
    except (tarfile.TarError, OSError, EOFError) as e:
        raise RootfsError(f"corrupt layer {path.name[:12]}: {e}") from e
    finally:
        fh.close()
        if proc is not None:
            proc.wait()
    return out


def flatten(layout: Path, dest: Path, max_bytes: int = 10 * 1024**3, privileged: bool | None = None) -> RootfsResult:
    """Extract the layout's layers into `dest` (created; must not exist or be empty). On any
    error the partial tree is removed and the exception re-raised."""
    layout, dest = Path(layout), Path(dest)
    privileged = is_root() if privileged is None else privileged
    layers, _config = layout_layers(layout)
    if dest.exists() and any(dest.iterdir()):
        raise RootfsError(f"{dest} is not empty")
    dest.mkdir(parents=True, exist_ok=True)
    ex = _Extractor(dest, max_bytes, privileged)
    try:
        for desc in layers:
            mt = str(desc.get("mediaType") or "")
            if mt and not any(mt.endswith(s) for s in LAYER_MEDIA_TAR) and "tar" not in mt:
                ex.res.notes.append(f"skipped non-tar layer {mt}")
                continue
            path = _blob(layout, desc["digest"])
            if not path.exists():
                raise RootfsError(f"layer blob {desc['digest'][:19]} missing from the layout")
            ex.whiteouts(_scan_whiteouts(path, mt))
            fh, proc = _open_layer(path, mt)
            try:
                with tarfile.open(fileobj=fh, mode="r|") as tf:
                    for ti in tf:
                        ex.entry(tf, ti)
            except (tarfile.TarError, EOFError) as e:
                raise RootfsError(f"corrupt layer {desc['digest'][:19]}: {e}") from e
            finally:
                fh.close()
                if proc is not None:
                    proc.wait()
            ex.res.layers += 1
        ex.finish_dirs()
    except BaseException:
        remove_tree(dest)
        raise
    if not privileged:
        ex.res.notes.append("extracted without root: owners, setuid/setgid bits and most xattrs are not preserved")
    if ex.res.skipped_devices:
        ex.res.notes.append(f"{ex.res.skipped_devices} device node(s) not created")
    if ex.res.unsafe_entries:
        ex.res.notes.append(f"{ex.res.unsafe_entries} layer entr(y/ies) escaping the rootfs refused")
    if ex.res.dropped_xattrs and privileged:
        ex.res.fidelity = "degraded"
        ex.res.notes.append(f"{ex.res.dropped_xattrs} extended attribute(s) could not be set")
    return ex.res


def prepare_for_oscap(root: Path) -> list[str]:
    """Scratch-rootfs fixes so OpenSCAP's package probes see the image's packages (DESIGN §14):
    * distroless images keep dpkg metadata in var/lib/dpkg/status.d/<pkg> (no status file): the
      files are concatenated into var/lib/dpkg/status (the image's own records, unchanged);
    * libapt-pkg writes its cache under RootDir/var/cache/apt: created when missing, and named in
      an apt.conf.d drop-in (the image's docker-clean config empties it); its directories and
      dpkg's cputable / tupletable (absent in distroless) are supplied when missing.
    Returns notes for the summary."""
    notes: list[str] = []
    try:
        dpkg = secure_join(root, "var/lib/dpkg")
        status, status_d = dpkg / "status", dpkg / "status.d"
        if status_d.is_dir() and not status_d.is_symlink() and not (status.exists() or status.is_symlink()):
            parts = []
            for f in sorted(status_d.iterdir()):
                if f.is_file() and not f.is_symlink() and not f.name.endswith(".md5sums"):
                    parts.append(f.read_bytes().strip(b"\n"))
            status.write_bytes(b"\n\n".join(parts) + b"\n")
            notes.append(f"dpkg status synthesised from {len(parts)} status.d record(s) (distroless)")
        if dpkg.is_dir():
            secure_join(root, "var/cache/apt").mkdir(parents=True, exist_ok=True)
            # libapt-pkg (dpkginfo probe, RootDir=<rootfs>) reads the image's apt.conf.d: Debian
            # container images set Dir::Cache::pkgcache "" (docker-clean), which RootDir turns into
            # "<rootfs>/" and apt init fails, so every package rule would read "not installed"
            for d in ("etc/apt/apt.conf.d", "var/lib/apt/lists/partial", "var/cache/apt/archives/partial"):
                secure_join(root, d).mkdir(parents=True, exist_ok=True)  # distroless: no apt at all
            # libapt-pkg also needs dpkg's architecture tables, which distroless images lack
            for name in ("cputable", "tupletable", "ostable"):
                dst = secure_join(root, f"usr/share/dpkg/{name}")
                host = Path("/usr/share/dpkg") / name
                if not (dst.exists() or dst.is_symlink()) and host.is_file():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(host, dst)
                    notes.append(f"dpkg {name} supplied from the worker image")
            conf = secure_join(root, "etc/apt/apt.conf.d")
            if conf.is_dir() and not conf.is_symlink():
                (conf / "zzzz-posture-oscap").write_text(
                    'Dir::Cache::pkgcache "pkgcache.bin";\nDir::Cache::srcpkgcache "srcpkgcache.bin";\n')
    except (OSError, RootfsError) as e:
        notes.append(f"rootfs preparation skipped: {e}")
    return notes


def remove_tree(path: Path) -> None:
    """rm -rf that also works on trees whose directories were made read-only by the image."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return

    def onerror(func, p, exc):  # noqa: ANN001
        e = exc if isinstance(exc, BaseException) else exc[1]
        if isinstance(e, OSError) and e.errno in (errno.EACCES, errno.EPERM):
            try:
                os.chmod(os.path.dirname(p), 0o700)
                os.chmod(p, 0o700)
            except OSError:
                pass
            try:
                func(p)
            except OSError:
                pass

    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(path, onexc=onerror)
