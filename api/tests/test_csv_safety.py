"""Formula-injection neutralisation in the CSV exports (security review M5)."""

from posture.provenance.report import export_csv


def test_compat_csv_escapes_formulas():
    doc = {"images": [{"image": "=HYPERLINK(\"x\")", "namespace": "@ns", "workload": {"kind": "Deployment",
                                                                                 "name": "-w"}, "digest": "+d"}]}
    line = export_csv(doc).splitlines()[1]
    assert line.startswith("\"'=HYPERLINK") and ",'@ns,Deployment,'-w,'+d," in line
