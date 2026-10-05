from types import SimpleNamespace

import pytest

from conftest import NOW, snapshot_data
from posture.reports.registry import REPORT_TYPES, GeneratedReport, UnsupportedReport, generate


def test_catalogue_shape():
    types = {t["type"]: t for t in REPORT_TYPES}
    assert set(types) == {"poam", "stig-checklist", "sar", "oscal-ar", "inventory", "vuln-export", "oscal-ssp",
                          "oscal-component-definition", "crm", "oscal-poam"}
    system_level = {"oscal-ssp", "oscal-component-definition", "crm"}  # DESIGN §13: whole-system documents
    for t in REPORT_TYPES:
        assert t["formats"] and t["description"]
        assert t["scopes"] == (["cluster"] if t["type"] in system_level else ["cluster", "namespace", "workload"])
    assert types["stig-checklist"]["formats"] == ["ckl", "cklb", "zip"]  # zip: stig-bundle.zip (DESIGN §14)
    assert types["poam"]["formats"] == ["xlsx", "csv"]


def test_unsupported():
    with pytest.raises(UnsupportedReport):
        generate("nope", "csv", None)
    with pytest.raises(UnsupportedReport):
        generate("poam", "pdf", None)


@pytest.mark.parametrize("t,fmt", [(t["type"], f) for t in REPORT_TYPES for f in t["formats"] if f != "pdf"])
def test_every_type_generates(snapshot, opts, t, fmt):
    rep = generate(t, fmt, snapshot, opts)
    assert isinstance(rep, GeneratedReport)
    data, name, ctype = rep  # tuple-compatible
    assert data and isinstance(data, bytes)
    assert name.startswith("lab-") and "scan42" in name
    assert ctype


MAPPING_FIELDS = {"sla_days", "counts", "fixable", "per_scanner", "scanner_status", "scanner_versions", "posture"}


def _ns(x):
    """Objects become namespaces; contract fields typed as dict[str, ...] stay dicts."""
    if isinstance(x, dict):
        return SimpleNamespace(**{k: (v if k in MAPPING_FIELDS else _ns(v)) for k, v in x.items()})
    if isinstance(x, list):
        return [_ns(i) for i in x]
    return x


@pytest.mark.parametrize("kind", ["dict", "namespace"])
def test_duck_typed_inputs(kind, opts):
    data = snapshot_data()
    snap = data if kind == "dict" else _ns(data)
    for t, fmt in [("poam", "csv"), ("stig-checklist", "cklb"), ("oscal-ar", "json"), ("sar", "html")]:
        assert generate(t, fmt, snap, opts).content


def test_camelcase_dict_input(opts):
    """API-shaped camelCase dicts are accepted too."""
    data = snapshot_data()
    data["scan"] = {"id": 7, "startedAt": NOW.isoformat(), "finishedAt": NOW.isoformat(), "grade": "B"}
    data["findings"] = [{"imageId": 1, "vulnId": "CVE-2024-0001", "severity": "high", "package": "x",
                         "fixedVersion": "2", "firstSeenAt": NOW.isoformat()}]
    rep = generate("vuln-export", "json", data, opts)
    assert b"CVE-2024-0001" in rep.content and b'"fixable": true' in rep.content
