import math

import pytest

from posture.scoring import (
    VulnInput,
    agreement_multiplier,
    check_weight,
    combine,
    grade,
    image_vuln_score,
    posture_score,
    weighted_mean,
)


def test_worked_example_one_critical_fixable_all_agree():
    s = image_vuln_score([VulnInput("critical", 3, True)], 3)
    assert s.penalty == pytest.approx(12.5)
    assert s.score == 73.2
    assert s.grade == "C"


def test_worked_example_five_highs_agreed():
    s = image_vuln_score([VulnInput("high", 3, False)] * 5, 3)
    assert s.penalty == pytest.approx(20)
    assert s.score == 60.7
    assert s.grade == "D"


def test_worked_example_thirty_mediums():
    s = image_vuln_score([VulnInput("medium", 3, False)] * 30, 3)
    assert s.penalty == pytest.approx(30)
    assert s.score == 47.2
    assert s.grade == "F"


def test_clean_image_is_100_A():
    s = image_vuln_score([], 3)
    assert (s.score, s.grade, s.confidence) == (100.0, "A", "high")


def test_no_scanner_succeeded_is_null():
    s = image_vuln_score([VulnInput("critical", 1, True)], 0)
    assert s.score is None and s.grade == "?" and s.confidence == "none"


@pytest.mark.parametrize("n,ok,mult", [(1, 3, 0.6), (2, 3, 0.85), (3, 3, 1.0), (1, 1, 1.0), (1, 2, 0.6), (2, 2, 1.0)])
def test_agreement_multiplier(n, ok, mult):
    assert agreement_multiplier(n, ok) == mult


def test_single_scanner_low_confidence_full_weight():
    s = image_vuln_score([VulnInput("high", 1, False)], 1)
    assert s.confidence == "low"
    assert s.penalty == pytest.approx(4.0)


def test_low_agreement_reduces_penalty():
    s = image_vuln_score([VulnInput("critical", 1, False)], 3)
    assert s.penalty == pytest.approx(6.0)
    assert s.score == round(100 * math.exp(-6 / 40), 1)


def test_negligible_and_unknown_weights():
    s = image_vuln_score([VulnInput("negligible", 3, False), VulnInput("unknown", 3, False)], 3)
    assert s.penalty == pytest.approx(0.1)


@pytest.mark.parametrize("score,g", [(100, "A"), (90, "A"), (89.9, "B"), (80, "B"), (65, "C"), (64.9, "D"),
                                     (50, "D"), (49.9, "F"), (0, "F"), (None, "?")])
def test_grades(score, g):
    assert grade(score) == g


def test_posture_score_and_system_namespace_weight():
    assert posture_score([]) == 100.0
    assert posture_score([10, 4]) == round(100 * math.exp(-14 / 20), 1)
    assert check_weight("critical", "kube-system") == 5.0
    assert check_weight("critical", "default") == 10.0
    assert check_weight("low") == 0.2


def test_combine_and_weighted_mean():
    assert combine(80, 60) == 74.0
    assert combine(None, 60) is None
    assert weighted_mean([(100, 1), (50, 3), (None, 5)]) == 62.5
    assert weighted_mean([]) is None


def test_agreement_only_over_capable_scanners_and_kev_never_downweighted():
    """Compliance review S4: a language-package finding Clair cannot see is not penalised for
    Clair's silence, and a CISA KEV finding is never down-weighted."""
    from posture.scoring import SYSTEM_NAMESPACES, VulnInput, capable_scanners, finding_penalty

    all3 = ("trivy", "grype", "clair")
    assert capable_scanners("debian", all3) == 3 and capable_scanners("python-pkg", all3) == 2
    assert capable_scanners("gobinary", ("clair",)) == 1 and capable_scanners(None, all3) == 3
    lang = VulnInput("high", 2, False, pkg_type="jar", succeeded=all3)
    assert finding_penalty(lang, 3) == 4.0  # 2 of the 2 capable scanners: full agreement
    os_pkg = VulnInput("high", 2, False, pkg_type="deb", succeeded=all3)
    assert finding_penalty(os_pkg, 3) == 4.0 * 0.85
    single_kev = VulnInput("critical", 1, False, pkg_type="deb", kev=True, succeeded=all3)
    assert finding_penalty(single_kev, 3) == 10.0  # was 6.0 with the 1-of-3 multiplier
    legacy = VulnInput("critical", 1, False)  # callers without package / scanner detail keep the old rule
    assert finding_penalty(legacy, 3) == 6.0
    from posture.reports._common import SYSTEM_NAMESPACES as REPORT_NS

    assert SYSTEM_NAMESPACES is REPORT_NS and SYSTEM_NAMESPACES == {"kube-system", "kube-public", "kube-node-lease"}
