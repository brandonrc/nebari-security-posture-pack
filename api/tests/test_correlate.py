from posture.analysis import analyze
from posture.correlate import agreement_index, correlate
from posture.scanners.base import Finding, ScanResult


def f(scanner, vid="CVE-2024-0001", pkg="openssl", sev="high", fixed=None, cvss=None):
    return Finding(vid, sev, pkg, "1.0", fixed, "apk", scanner, cvss=cvss)


def test_consensus_groups_by_vuln_and_package():
    c = correlate([f("trivy"), f("grype", sev="critical", fixed="1.1"), f("clair", sev="unknown"),
                   f("grype", pkg="libssl3")], ["trivy", "grype", "clair"])
    assert len(c) == 2
    top = next(x for x in c if x.package == "openssl")
    assert top.scanners == ["trivy", "grype", "clair"]
    assert top.severity == "critical"  # max
    assert top.agreement == 1.0
    assert top.per_scanner == {"trivy": "high", "grype": "critical", "clair": "unknown"}
    assert top.fixable and top.fixed_version == "1.1"
    other = next(x for x in c if x.package == "libssl3")
    assert other.scanners == ["grype"] and other.agreement == round(1 / 3, 4)


def test_package_name_normalization_and_case():
    c = correlate([f("trivy", pkg="Python_Dateutil"), f("grype", pkg="python-dateutil"),
                   f("clair", vid="cve-2024-0001", pkg="python.dateutil")], ["trivy", "grype", "clair"])
    assert len(c) == 1 and len(c[0].scanners) == 3


def test_agreement_relative_to_succeeded():
    c = correlate([f("trivy")], ["trivy", "grype"])
    assert c[0].agreement == 0.5
    assert agreement_index(c, 2) == 0.5
    assert agreement_index([], 2) == 1.0
    assert agreement_index([], 0) is None


def test_analyze_failed_scanner_never_counts():
    results = [
        ScanResult("trivy", "ok", findings=[f("trivy", sev="critical", fixed="2")]),
        ScanResult("grype", "ok", findings=[f("grype", sev="critical", fixed="2")]),
        ScanResult("clair", "error", error="boom", findings=[]),
    ]
    a = analyze(results)
    assert a.succeeded == ["trivy", "grype"]
    assert a.counts["critical"] == 1 and a.fixable["critical"] == 1
    # 2/2 succeeded scanners agree -> multiplier 1.0, fixable 1.25 -> 12.5
    assert a.score.score == 73.2
    assert a.score.confidence == "medium"
    assert a.scanners["clair"]["status"] == "error"


def test_analyze_all_failed():
    a = analyze([ScanResult("trivy", "timeout"), ScanResult("grype", "error")])
    assert a.score.score is None and a.score.grade == "?"
