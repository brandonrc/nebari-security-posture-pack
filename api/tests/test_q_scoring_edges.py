"""Consensus/scoring edge cases from the quality review (m5).

Tests marked `xfail(strict=True)` describe the behaviour the review recommends and fail today;
when the compliance/scoring owner changes the behaviour they XPASS, the strict marker turns that
into a failure, and the marker must be removed (so the decision is recorded in the diff). The
unmarked tests pin current behaviour that is intentional. Findings: docs/DECISIONS.md
("Scoring edge cases (quality m5)").
"""

from __future__ import annotations

import pytest

from posture.correlate import agreement_index, correlate, normalize_package
from posture.scanners.base import Finding
from posture.scoring import VULN_BASE, VulnInput, finding_penalty, image_vuln_score
from posture.severity import normalize_severity


def f(scanner, vid="CVE-2024-1111", pkg="openssl", sev="high", **kw):
    return Finding(vid, sev, pkg, kw.pop("installed", "1.0"), kw.pop("fixed", None), kw.pop("pkg_type", "deb"),
                   scanner, **kw)


ALL = ["trivy", "grype", "clair"]


# ---------------------------------------------------------------- identifiers

def test_cve_ids_are_case_insensitive():
    (c,) = correlate([f("trivy", vid="cve-2024-1111"), f("grype", vid="CVE-2024-1111")], ALL)
    assert c.vuln_id == "CVE-2024-1111" and c.scanners == ["trivy", "grype"]


def test_non_cve_ids_keep_their_case_and_do_not_merge_across_case():
    out = correlate([f("trivy", vid="DSA-1234-1"), f("clair", vid="dsa-1234-1")], ALL)
    assert sorted(c.vuln_id for c in out) == ["DSA-1234-1", "dsa-1234-1"]


@pytest.mark.xfail(strict=True, reason="m5: GHSA ids are upper-cased; GitHub's canonical form is "
                                       "GHSA-xxxx-xxxx-xxxx with lowercase segments (links break)")
def test_ghsa_ids_keep_their_canonical_lowercase_segments():
    (c,) = correlate([f("trivy", vid="GHSA-abcd-efgh-ijkl", pkg="requests", pkg_type="pip")], ALL)
    assert c.vuln_id == "GHSA-abcd-efgh-ijkl"


def test_ghsa_ids_from_two_scanners_merge_regardless_of_case():
    (c,) = correlate([f("trivy", vid="GHSA-abcd-efgh-ijkl", pkg="requests"),
                      f("grype", vid="ghsa-ABCD-efgh-ijkl", pkg="requests")], ALL)
    assert c.scanners == ["trivy", "grype"]


@pytest.mark.xfail(strict=True, reason="m5: GHSA <-> CVE aliases are never merged; the same issue "
                                       "reported as GHSA by one scanner and CVE by another becomes two "
                                       "findings at 1/3 agreement each (needs alias data on Finding)")
def test_ghsa_and_cve_aliases_for_the_same_issue_merge():
    out = correlate([f("trivy", vid="GHSA-abcd-efgh-ijkl", pkg="requests", pkg_type="pip"),
                     f("grype", vid="CVE-2024-2222", pkg="requests", pkg_type="pip")], ALL)
    assert len(out) == 1


# ---------------------------------------------------------------- package names

@pytest.mark.parametrize(("a", "b"), [("Pillow", "pillow"), ("zope.interface", "zope-interface"),
                                      ("typing_extensions", "typing-extensions"), ("a__b", "a-b"),
                                      ("  openssl ", "openssl")])
def test_package_normalization_merges(a, b):
    assert normalize_package(a) == normalize_package(b)


def test_trailing_separator_is_kept_like_pep503():
    # PEP 503 normalization keeps a trailing separator ("a_" -> "a-"), and PEP 508 names cannot
    # end with one, so "a_" vs "a" not merging is acceptable: pinned here, noted in DECISIONS.
    assert normalize_package("a_") == "a-" != normalize_package("a")


# ---------------------------------------------------------------- agreement

def test_agreement_counts_succeeded_scanners():
    (c,) = correlate([f("trivy"), f("grype")], ALL)
    assert c.agreement == round(2 / 3, 4)
    (c,) = correlate([f("trivy"), f("grype")], ["trivy", "grype"])  # clair failed
    assert c.agreement == 1.0


@pytest.mark.xfail(strict=True, reason="m5: a finding from a scanner that is NOT in `succeeded` "
                                       "(its run failed) still counts toward agreement")
def test_findings_from_failed_scanners_do_not_raise_agreement():
    (c,) = correlate([f("trivy"), f("clair")], ["trivy", "grype"])
    assert c.agreement == 0.5


def test_agreement_index_edges():
    assert agreement_index([], 0) is None   # nothing ran
    assert agreement_index([], 3) == 1.0    # clean image
    out = correlate([f("trivy", vid="CVE-2024-0001"), f("trivy", vid="CVE-2024-0002"), f("grype", vid="CVE-2024-0002")],
                    ["trivy", "grype"])
    assert agreement_index(out, 2) == 0.75


def test_severity_is_the_max_over_scanners_and_per_scanner_keeps_the_max_duplicate():
    (c,) = correlate([f("trivy", sev="medium"), f("trivy", sev="critical"), f("grype", sev="low")], ALL)
    assert c.severity == "critical" and c.per_scanner == {"trivy": "critical", "grype": "low"}


# ---------------------------------------------------------------- severity normalization

@pytest.mark.xfail(strict=True, reason="m5: finding_penalty silently scores a non-normalized "
                                       "severity ('CRITICAL') as unknown (0.05 instead of 10.0)")
def test_penalty_rejects_or_normalizes_raw_severities():
    assert finding_penalty(VulnInput("CRITICAL", 3, False), 3) == VULN_BASE["critical"]


def test_parsers_normalize_before_scoring():
    # the guard that makes the xfail above harmless today: every parser calls normalize_severity
    assert normalize_severity("CRITICAL") == "critical"
    assert finding_penalty(VulnInput(normalize_severity("CRITICAL"), 3, False), 3) == VULN_BASE["critical"]


@pytest.mark.xfail(strict=True, reason="m5: Debian's 'unimportant' urgency maps to unknown, not negligible")
def test_debian_unimportant_is_negligible():
    assert normalize_severity("unimportant") == "negligible"


# ---------------------------------------------------------------- scanner count / confidence

def test_zero_and_one_scanner():
    assert image_vuln_score([VulnInput("critical", 1, True)], 0).score is None
    s = image_vuln_score([VulnInput("critical", 1, True)], 1)
    assert s.confidence == "low" and s.score is not None
    # a lone surviving scanner is full agreement (no 0.6 down-weighting)
    assert finding_penalty(VulnInput("critical", 1, False), 1) == VULN_BASE["critical"]


def test_language_package_agreement_ignores_clair():
    both = VulnInput("high", 2, False, pkg_type="pip", succeeded=("trivy", "grype", "clair"))
    assert finding_penalty(both, 3) == VULN_BASE["high"]
    os_pkg = VulnInput("high", 2, False, pkg_type="deb", succeeded=("trivy", "grype", "clair"))
    assert finding_penalty(os_pkg, 3) < VULN_BASE["high"]
