"""GET /images `stig=` filter semantics (DESIGN §14)."""

from posture.routers.images import SORT_KEYS, stig_filter


def test_stig_filter_values():
    ev = {"stig": {"status": "evaluated", "score": 80.0, "cat1Open": 2}}
    ev0 = {"stig": {"status": "evaluated", "score": 99.0, "cat1Open": 0}}
    na = {"stig": {"status": "notApplicable"}}
    nc = {"stig": {"status": "noContent"}}
    err = {"stig": {"status": "error"}}
    none = {"stig": None}
    assert [stig_filter(d, "evaluated") for d in (ev, ev0, na, nc, err, none)] == [True, True, False, False, False, False]
    assert [stig_filter(d, "na") for d in (ev, na, nc, err, none)] == [False, True, True, False, False]
    assert [stig_filter(d, "cat1") for d in (ev, ev0, na)] == [True, False, False]
    assert stig_filter(na, "cat1,na") and not stig_filter(none, "bogus")
    assert sorted([ev, none, ev0], key=SORT_KEYS["stig"]) == [ev, ev0, none]
