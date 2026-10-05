"""Pure helpers of posture.scap.stage: memory-capped parallelism, content fingerprint."""

from __future__ import annotations

from posture.scap.stage import content_fingerprint, effective_parallelism, memory_limit_bytes

GI = 1024**3


def test_parallelism_capped_by_memory_limit():
    assert effective_parallelism(3, None, 1152) == 3  # unlimited
    assert effective_parallelism(3, 4 * GI, 1152) == 3  # chart limit 4Gi: (4096 - 384) // 1152 = 3
    assert effective_parallelism(3, 3 * GI, 1152) == 2  # old 3Gi limit
    assert effective_parallelism(8, 2 * GI, 1152) == 1
    assert effective_parallelism(3, 512 * 1024**2, 1152) == 1  # never below one
    assert effective_parallelism(0, None, 1152) == 1
    assert effective_parallelism(5, 4 * GI, 0) == 5  # per-eval 0 = no memory cap


def test_memory_limit_reads_cgroup_v2(tmp_path):
    f = tmp_path / "memory.max"
    f.write_text("4294967296\n")
    assert memory_limit_bytes(f) == 4 * GI
    f.write_text("max\n")
    assert memory_limit_bytes(f) is None
    assert memory_limit_bytes(tmp_path / "missing") is None


def test_content_fingerprint_changes_with_content_only():
    a = [{"path": "ssg/ssg-rhel9-ds.xml", "benchmarkId": "b1", "sha256": "aa", "sizeBytes": 10, "title": "x"},
         {"path": "disa/rhel9.xml", "benchmarkId": "b2", "sha256": "bb", "sizeBytes": 20}]
    fp = content_fingerprint(a)
    assert fp and fp == content_fingerprint(list(reversed(a)))
    assert fp == content_fingerprint([{**a[0], "title": "renamed"}, a[1]])  # metadata only
    assert fp != content_fingerprint([{**a[0], "sha256": "cc"}, a[1]])  # new release
    assert fp != content_fingerprint(a[:1])  # content removed
    assert content_fingerprint([]) is None


def test_content_fingerprint_includes_the_rule_metadata_version(monkeypatch):
    from posture.scap import content

    a = [{"path": "ssg/ssg-rhel9-ds.xml", "benchmarkId": "b1", "sha256": "aa", "sizeBytes": 10}]
    fp = content_fingerprint(a)
    monkeypatch.setattr(content, "RULE_META_VERSION", content.RULE_META_VERSION + 1)
    assert content_fingerprint(a) != fp
