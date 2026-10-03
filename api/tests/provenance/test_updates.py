"""Ported from provenance-collector-pack internal/registry/updates_test.go + semver ordering."""

import pytest

from posture.provenance.updates import (
    UpdateInfo,
    Version,
    compute_update,
    needs_tag_list,
    parse_image_ref,
    parse_version,
    should_flag,
)


@pytest.mark.parametrize("ref,repo,tag", [
    ("nginx:1.27", "nginx", "1.27"),
    ("nginx", "nginx", "latest"),
    ("docker.io/library/nginx:1.27-alpine", "docker.io/library/nginx", "1.27-alpine"),
    ("ghcr.io/org/repo:v2.0.0", "ghcr.io/org/repo", "v2.0.0"),
    ("myregistry.com:5000/myimage:tag", "myregistry.com:5000/myimage", "tag"),
    ("nginx@sha256:abc123", "nginx", ""),
    ("ghcr.io/org/repo@sha256:abc", "ghcr.io/org/repo", ""),
])
def test_parse_image_ref(ref, repo, tag):
    assert parse_image_ref(ref) == (repo, tag)


@pytest.mark.parametrize("name,current,latest,newest,level,want", [
    ("patch: patch bump", "1.2.3", "1.2.5", "", "patch", True),
    ("patch: minor bump", "1.2.3", "1.3.0", "", "patch", True),
    ("patch: major bump", "1.2.3", "", "2.0.0", "patch", True),
    ("patch: no update", "1.2.3", "", "", "patch", False),
    ("minor: patch bump only", "1.2.3", "1.2.5", "", "minor", False),
    ("minor: minor bump", "1.2.3", "1.3.0", "", "minor", True),
    ("minor: major bump", "1.2.3", "", "2.0.0", "minor", True),
    ("minor: patch in major, minor in newest", "1.2.3", "1.2.5", "1.3.0", "minor", True),
    ("major: patch bump only", "1.2.3", "1.2.5", "", "major", False),
    ("major: minor bump only", "1.2.3", "1.3.0", "", "major", False),
    ("major: major bump", "1.2.3", "", "2.0.0", "major", True),
    ("major: minor in major, major in newest", "1.2.3", "1.5.0", "2.0.0", "major", True),
    ("major: no update", "2.0.0", "", "", "major", False),
    ("empty candidates", "1.0.0", "", "", "patch", False),
])
def test_should_flag(name, current, latest, newest, level, want):
    info = UpdateInfo(current_tag=current, latest_in_major=latest, newest_available=newest)
    assert should_flag(Version.parse(current), info, level) is want, name


@pytest.mark.parametrize("s,ok", [
    ("1.2.3", True), ("v1.2.3", True), ("1.27", True), ("1", True), ("1.27-alpine", True),
    ("2024.5.0-py3.12", True), ("1.0.0+build.5", True), ("1.0.0-rc.1+meta", True),
    ("latest", False), ("sha-bf9c57c", False), ("1.2.3.4", False), ("main-ce8b402", False),
    ("distroless-v1.32.2", False), ("1.0.0-01", False), ("", False), ("v", False),
])
def test_semver_parse_is_masterminds_loose(s, ok):
    assert (parse_version(s) is not None) is ok


def test_semver_original_and_coercion():
    v = Version.parse("v1.27")
    assert (v.major, v.minor, v.patch, v.original) == (1, 27, 0, "v1.27")


@pytest.mark.parametrize("a,b", [
    ("1.0.0-alpha", "1.0.0-alpha.1"), ("1.0.0-alpha.1", "1.0.0-alpha.beta"), ("1.0.0-alpha.beta", "1.0.0-beta"),
    ("1.0.0-beta", "1.0.0-beta.2"), ("1.0.0-beta.2", "1.0.0-beta.11"), ("1.0.0-beta.11", "1.0.0-rc.1"),
    ("1.0.0-rc.1", "1.0.0"), ("1.9.0", "1.10.0"), ("1.27-alpine", "1.27.0"), ("0.9.9", "1"),
])
def test_semver_precedence(a, b):
    assert Version.parse(a) < Version.parse(b)
    assert Version.parse(b).greater_than(Version.parse(a))


def test_metadata_ignored_in_precedence():
    assert Version.parse("1.0.0+a") == Version.parse("1.0.0+b")


TAGS = ["1.25.0", "1.26.0", "1.27.0", "1.27.1", "1.27.2", "1.28.0-rc.1", "2.0.0", "2.1.0-beta", "latest",
        "mainline", "1.27-alpine", "stable-alpine"]


def test_check_finds_latest_in_major_and_newest():
    info = compute_update("1.27.0", TAGS, skip_prerelease=True, update_level="patch")
    assert info == UpdateInfo("1.27.0", "1.27.2", "2.0.0", True)
    assert info.major_behind


def test_check_without_skip_prerelease_sees_prereleases():
    info = compute_update("1.27.0", TAGS, skip_prerelease=False, update_level="patch")
    assert info.latest_in_major == "1.28.0-rc.1" and info.newest_available == "2.1.0-beta"


def test_check_up_to_date():
    info = compute_update("2.0.0", TAGS)
    assert info == UpdateInfo("2.0.0", "", "", False)
    assert info.as_json() == {"currentTag": "2.0.0", "updateAvailable": False}


def test_check_levels():
    assert compute_update("1.27.1", TAGS, update_level="minor").update_available is True  # 2.0.0 newest
    assert compute_update("2.0.0", TAGS + ["2.0.1"], update_level="minor").update_available is False
    assert compute_update("2.0.0", TAGS + ["2.0.1"], update_level="patch").update_available is True
    assert compute_update("1.27.0", ["1.27.0", "1.28.0"], update_level="major").update_available is False


@pytest.mark.parametrize("tag", ["latest", "", "sha-bf9c57c", "main-ce8b402"])
def test_check_short_circuits_like_theirs(tag):
    assert not needs_tag_list(tag)
    assert compute_update(tag, None) == UpdateInfo(tag)


def test_v_prefix_original_is_reported():
    info = compute_update("v1.16.2", ["v1.16.2", "v1.16.3", "v1.17.0", "v2.0.0-alpha.1"])
    assert info.as_json() == {"currentTag": "v1.16.2", "latestInMajor": "v1.17.0", "newestAvailable": "v1.17.0",
                              "updateAvailable": True}


def test_update_info_roundtrip():
    j = {"currentTag": "1.0", "latestInMajor": "1.1", "updateAvailable": True}
    assert UpdateInfo.from_json(j).as_json() == j and UpdateInfo.from_json(None) is None
