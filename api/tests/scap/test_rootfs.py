"""posture.scap.rootfs: OCI layer flattening, whiteouts, confinement, fidelity, size cap."""

from __future__ import annotations

import os
import stat

import pytest

from posture.scap.rootfs import RootfsError, RootfsTooLarge, flatten, read_file, remove_tree, secure_join

from .helpers import make_layout

ROOT = os.geteuid() == 0


def test_layers_apply_in_order_with_whiteouts_and_opaque_dirs(tmp_path):
    layout = make_layout(tmp_path / "img", [
        [("dir", "etc"), ("file", "etc/keep", b"1"), ("file", "etc/gone", b"x"), ("dir", "opt/app"),
         ("file", "opt/app/old", b"old"), ("file", "etc/over", b"v1")],
        [("whiteout", "etc/gone"), ("opaque", "opt/app"), ("file", "opt/app/new", b"new"),
         ("file", "etc/over", b"v2")],
    ])
    res = flatten(layout, tmp_path / "rootfs", privileged=False)
    r = tmp_path / "rootfs"
    assert (r / "etc/keep").read_bytes() == b"1"
    assert not (r / "etc/gone").exists() and not (r / "etc/.wh.gone").exists()
    assert sorted(os.listdir(r / "opt/app")) == ["new"]  # opaque: lower layer's content gone, own kept
    assert (r / "etc/over").read_bytes() == b"v2"
    assert res.layers == 2 and res.fidelity == "degraded"


def test_opaque_marker_after_entries_of_same_layer_keeps_them(tmp_path):
    layout = make_layout(tmp_path / "img", [
        [("dir", "d"), ("file", "d/lower", b"l")],
        [("file", "d/upper", b"u"), ("opaque", "d")],  # marker after the layer's own file
    ])
    flatten(layout, tmp_path / "r", privileged=False)
    assert sorted(os.listdir(tmp_path / "r/d")) == ["upper"]


def test_entries_cannot_escape_the_rootfs(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    layout = make_layout(tmp_path / "img", [
        [("symlink", "evil", "/"), ("symlink", "up", "../../../.."), ("file", "../escape1", b"x"),
         ("dir", "etc")],
        [("file", "evil/etc/passwd", b"pwn"), ("file", "up/escape2", b"x"),
         ("hardlink", "etc/shadow-link", "../../outside/secret"), ("symlink", "etc/abs", str(outside))],
        [("file", "etc/abs/escape3", b"x")],
    ])
    (outside / "secret").write_text("s")
    res = flatten(layout, tmp_path / "r", privileged=False)
    r = tmp_path / "r"
    # symlinked parents are resolved inside the rootfs: "/" -> rootfs, "../../.." clamps at rootfs
    assert (r / "etc/passwd").read_bytes() == b"pwn"
    assert (r / "escape2").exists()
    assert (r / str(outside).lstrip("/") / "escape3").exists()  # absolute link target re-rooted
    assert not list(outside.glob("escape*")) and not (tmp_path / "escape1").exists()
    assert not (r / "etc/shadow-link").exists()
    assert res.unsafe_entries >= 2  # ../escape1 and the hard link


def test_secure_join_and_read_file(tmp_path):
    r = tmp_path / "r"
    (r / "usr/lib").mkdir(parents=True)
    (r / "usr/lib/os-release").write_text("ID=x\n")
    (r / "etc").mkdir()
    os.symlink("../usr/lib/os-release", r / "etc/os-release")
    os.symlink("/etc/os-release", r / "abs")
    os.symlink("loop2", r / "loop1")
    os.symlink("loop1", r / "loop2")
    assert read_file(r, "etc/os-release") == b"ID=x\n"
    assert read_file(r, "/abs") == b"ID=x\n"  # absolute target inside the rootfs
    assert read_file(r, "../../../../etc/hostname") is None
    assert secure_join(r, "a/../../b") == r / "b"
    with pytest.raises(RootfsError):
        secure_join(r, "loop1/x")


def test_hardlinks_symlinks_fifos_and_devices(tmp_path):
    layout = make_layout(tmp_path / "img", [[
        ("dir", "bin"), ("file", "bin/busybox", b"BB", 0o755), ("hardlink", "bin/sh", "bin/busybox"),
        ("symlink", "bin/ls", "busybox"), ("fifo", "run.fifo"), ("chr", "dev-null")]])
    res = flatten(layout, tmp_path / "r", privileged=False)
    r = tmp_path / "r"
    assert (r / "bin/sh").read_bytes() == b"BB" and os.readlink(r / "bin/ls") == "busybox"
    assert stat.S_ISFIFO(os.lstat(r / "run.fifo").st_mode)
    assert not (r / "dev-null").exists() and res.skipped_devices == 1


def test_degraded_mode_drops_setuid_and_keeps_tree_removable(tmp_path):
    layout = make_layout(tmp_path / "img", [[
        ("dir", "ro", 0o500), ("file", "ro/f", b"x", 0o400), ("file", "su", b"x", 0o4755, 0, 0)]])
    res = flatten(layout, tmp_path / "r", privileged=False)
    mode = os.stat(tmp_path / "r/su").st_mode
    assert not mode & stat.S_ISUID and res.fidelity == "degraded"
    assert any("without root" in n for n in res.notes)
    remove_tree(tmp_path / "r")
    assert not (tmp_path / "r").exists()


@pytest.mark.skipif(not ROOT, reason="needs root (CAP_CHOWN / CAP_FSETID): the scap-worker case")
def test_privileged_mode_preserves_owner_mode_and_xattrs(tmp_path):
    layout = make_layout(tmp_path / "img", [[
        ("file", "su", b"x", 0o4755, 0, 0), ("file", "owned", b"x", 0o640, 1234, 5678, {"user.test": "v"})]])
    res = flatten(layout, tmp_path / "r", privileged=True)
    st = os.stat(tmp_path / "r/owned")
    assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (1234, 5678, 0o640)
    assert os.stat(tmp_path / "r/su").st_mode & stat.S_ISUID
    assert os.getxattr(tmp_path / "r/owned", "user.test") == b"v"
    assert res.fidelity == "full"


def test_size_cap_aborts_and_cleans_up(tmp_path):
    layout = make_layout(tmp_path / "img", [[("file", "big", b"x" * 4096)]])
    with pytest.raises(RootfsTooLarge):
        flatten(layout, tmp_path / "r", max_bytes=1024, privileged=False)
    assert not (tmp_path / "r").exists()


def test_uncompressed_layers_and_bad_layouts(tmp_path):
    layout = make_layout(tmp_path / "img", [[("file", "a", b"1")]], compress=False)
    flatten(layout, tmp_path / "r", privileged=False)
    assert (tmp_path / "r/a").read_bytes() == b"1"
    (tmp_path / "bad").mkdir()
    with pytest.raises(RootfsError):
        flatten(tmp_path / "bad", tmp_path / "r2", privileged=False)
    with pytest.raises(RootfsError):  # non-empty destination
        flatten(layout, tmp_path / "r", privileged=False)


def test_prepare_for_oscap_synthesises_distroless_dpkg_status(tmp_path):
    from posture.scap.rootfs import prepare_for_oscap

    r = tmp_path / "r"
    (r / "var/lib/dpkg/status.d").mkdir(parents=True)
    (r / "var/lib/dpkg/status.d/base").write_text("Package: base-files\nStatus: install ok installed\n")
    (r / "var/lib/dpkg/status.d/libc6").write_text("Package: libc6\nStatus: install ok installed\n\n")
    (r / "var/lib/dpkg/status.d/libc6.md5sums").write_text("x  /lib/libc.so\n")
    notes = prepare_for_oscap(r)
    status = (r / "var/lib/dpkg/status").read_text()
    assert status == ("Package: base-files\nStatus: install ok installed\n\n"
                      "Package: libc6\nStatus: install ok installed\n")
    assert (r / "var/cache/apt").is_dir() and "distroless" in notes[0]
    assert "pkgcache.bin" in (r / "etc/apt/apt.conf.d/zzzz-posture-oscap").read_text()
    assert prepare_for_oscap(r) == []  # existing status file is left alone
    (tmp_path / "empty").mkdir()
    assert prepare_for_oscap(tmp_path / "empty") == [] and not (tmp_path / "empty/var").exists()
