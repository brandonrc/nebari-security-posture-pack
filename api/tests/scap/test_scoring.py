"""STIG score (SCORING.md addendum) and its effect on the configuration dimension."""

from __future__ import annotations

from posture.scap.scoring import configuration_score, image_stig, open_by_cat, stig_score, weights


def test_stig_score_formula():
    assert stig_score([]) is None
    assert stig_score([("cat1", "notchecked"), ("cat2", "notapplicable")]) is None
    assert stig_score([("cat1", "pass"), ("cat2", "pass")]) == 100.0
    # 1 CAT I fail (10) of 10 + 4 + 1 evaluated -> 100 * (1 - 10/15)
    rows = [("cat1", "fail"), ("cat2", "pass"), ("cat3", "pass"), ("cat2", "notchecked")]
    assert stig_score(rows) == 33.3
    assert open_by_cat(rows) == {"cat1Open": 1, "cat2Open": 0, "cat3Open": 0}
    assert weights(rows) == (15.0, 10.0)


def test_image_stig_combines_benchmarks_by_weight():
    s = image_stig([{"status": "evaluated", "benchmarkKey": "a", "evaluatedWeight": 10, "failedWeight": 0,
                     "pass": 1, "fail": 0}, {"status": "evaluated", "benchmarkKey": "b", "evaluatedWeight": 10,
                                             "failedWeight": 5, "pass": 1, "fail": 2, "cat2Open": 1}])
    assert s["score"] == 75.0 and s["benchmarks"] == 2 and s["fail"] == 2 and s["cat2Open"] == 1
    assert image_stig([{"status": "notApplicable", "error": "no benchmark"}]) == {
        "status": "notApplicable", "score": None, "benchmarks": 0, "error": "no benchmark"}
    assert image_stig([])["status"] == "notEvaluated"


def test_configuration_score():
    assert configuration_score(80.0, []) == 80.0
    assert configuration_score(80.0, [None]) == 80.0
    assert configuration_score(80.0, [60.0, 40.0]) == 60.0
    assert configuration_score(None, [50.0]) == 50.0


def test_aggregate_uses_stig_in_posture(container_factory):
    from posture.aggregate import ImageInfo, aggregate
    from posture.inventory_model import InventorySnapshot
    from posture.posture_checks import evaluate_inventory

    c = container_factory(image_id="ghcr.io/org/web@sha256:" + "1" * 64)
    c.image_key = "k"
    inv = InventorySnapshot(containers=[c], namespaces={}, network_policies=[], nebari_apps=[])
    posture = evaluate_inventory(inv)
    base = aggregate(inv, {"k": ImageInfo(1, "r", 90.0, {})}, posture)[0][0]
    with_stig = aggregate(inv, {"k": ImageInfo(1, "r", 90.0, {}, stig_score=20.0)}, posture)[0][0]
    assert with_stig.posture_score == round((base.posture_score + 20.0) / 2, 1)
    assert with_stig.score < base.score and with_stig.vuln_score == base.vuln_score
