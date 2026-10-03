"""Supply-chain score (SCORING.md / DESIGN §12) and the 0.6/0.25/0.15 cluster weights."""

import pytest

from posture.aggregate import ImageInfo, aggregate
from posture.inventory_model import InventorySnapshot
from posture.provenance.scoring import (
    SupplyChainInputs,
    cluster_supply_chain_score,
    container_score,
    image_penalties,
    inputs_from_json,
    provenance_controls,
    supply_chain_score,
)
from posture.scoring import combine, combine_cluster

from ..conftest import make_container

ALL_GOOD = SupplyChainInputs(signed=True, verified=True, has_sbom=True, has_provenance=True, update_available=False)


@pytest.mark.parametrize("inputs,mutable,score", [
    (ALL_GOOD, False, 100.0),
    (ALL_GOOD, True, 90.0),
    (SupplyChainInputs(signed=False, has_sbom=False, has_provenance=False, update_available=False), False, 25.0),
    (SupplyChainInputs(signed=True, verified=False, has_sbom=True, has_provenance=True, update_available=False), False, 80.0),
    (SupplyChainInputs(signed=True, verified=True, has_sbom=False, has_provenance=True, update_available=True), False, 65.0),
    (SupplyChainInputs(signed=True, verified=True, has_sbom=True, has_provenance=False, update_available=True,
                       major_behind=True), False, 60.0),
    # everything bad: 40+20+15+25+10 = 110 -> floor 0
    (SupplyChainInputs(signed=False, has_sbom=False, has_provenance=False, update_available=True, major_behind=True), True, 0.0),
])
def test_image_score(inputs, mutable, score):
    assert supply_chain_score(inputs, mutable) == score


def test_disabled_checks_do_not_count_and_unchecked_is_none():
    assert supply_chain_score(SupplyChainInputs(signed=False), False) == 60.0  # only the signature check ran
    assert supply_chain_score(SupplyChainInputs(), False) is None and supply_chain_score(None) is None
    assert container_score(ALL_GOOD, "nginx") == 90.0 and container_score(ALL_GOOD, "nginx@sha256:" + "a" * 64) == 100.0
    assert container_score(ALL_GOOD, "nginx:1.27") == 100.0


def test_penalty_ids_and_controls():
    ids = [i for i, _ in image_penalties(SupplyChainInputs(signed=False, has_sbom=False, has_provenance=False,
                                                           update_available=True))]
    assert ids == ["unsigned", "no-sbom", "no-provenance", "update-available"]
    assert provenance_controls("unsigned")[:2] == ["CM-14", "SR-4"]
    assert provenance_controls("no-provenance") == ["SR-3", "SR-4", "SA-10"]
    assert provenance_controls("update-available") == ["SI-2"]
    assert provenance_controls("helm-release-behind") == ["SI-2", "CM-3"]
    assert provenance_controls("nope") == []


def test_inputs_from_report_json():
    i = inputs_from_json({"signed": True, "verified": False}, {"hasSBOM": True}, None, {"updateAvailable": True},
                         verification_configured=False, sbom_checked=True, provenance_checked=False,
                         updates_checked=True)
    assert (i.signed, i.verified, i.has_sbom, i.has_provenance, i.update_available) == (True, False, True, None, True)
    assert supply_chain_score(i) == 100 - 20 - 15


def test_combine_cluster_weights():
    assert combine_cluster(80, 60, None) == combine(80, 60) == 74.0  # pre-§12 0.7/0.3
    assert combine_cluster(80, 60, 40) == round(0.6 * 80 + 0.25 * 60 + 0.15 * 40, 1) == 69.0
    assert combine_cluster(80, None, 40) == round((0.6 * 80 + 0.15 * 40) / 0.75, 1)
    assert combine_cluster(None, 60, 40) is None
    assert cluster_supply_chain_score([100, None, 50]) == 75.0 and cluster_supply_chain_score([]) is None


def test_aggregate_container_weighted_supply_chain():
    cs = [make_container(pod="w1", image="ghcr.io/org/web:1.0"), make_container(pod="w2", image="ghcr.io/org/web:1.0"),
          make_container(namespace="other", pod="x", workload_name="x", image="alpine")]  # mutable tag
    for c in cs:
        c.image_key = "alpine" if c.image == "alpine" else "web"
    images = {"web": ImageInfo(1, "web", 90.0), "alpine": ImageInfo(2, "alpine", 90.0)}
    inv = InventorySnapshot(containers=cs)
    _, _, without = aggregate(inv, images, {})
    supply = {1: ALL_GOOD, 2: SupplyChainInputs(signed=False, has_sbom=False, has_provenance=False,
                                                update_available=False)}
    _, _, cl = aggregate(inv, images, {}, supply)
    # containers: 100, 100, (25 - 10 mutable) = 15 -> mean 71.7
    assert cl.supply_chain_score == round((100 + 100 + 15) / 3, 1)
    assert without.supply_chain_score is None and without.score == 90.0
    assert cl.score == round((0.6 * 90 + 0.15 * cl.supply_chain_score) / 0.75, 1)  # no posture results here
