"""Alignment check between the real ReportSnapshot (owned by the API) and our contract."""
import pytest

from conftest import make_snapshot, snapshot_data


def test_real_model_accepts_factory_data():
    try:
        from posture.reports.models import ReportSnapshot  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on integration state
        pytest.skip(f"posture.reports.models not available yet: {exc}")
    snap = ReportSnapshot.model_validate(snapshot_data())
    for name in ("generated_at", "system", "scan", "scope", "sla_days", "scanners", "images", "findings",
                 "workloads", "checks", "posture_results", "trend"):
        assert hasattr(snap, name), f"ReportSnapshot lacks contract attribute {name!r} (see models_contract.md)"


def test_factory_is_realistic():
    s = make_snapshot()
    assert len(s.images) >= 3 and len(s.findings) >= 20 and s.posture_results
