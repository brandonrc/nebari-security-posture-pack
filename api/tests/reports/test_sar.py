import pytest

from conftest import make_snapshot
from posture.reports.registry import ReportDependencyMissing, generate


def test_html_sections(snapshot, opts):
    rep = generate("sar", "html", snapshot, opts)
    html = rep.content.decode()
    assert rep.content_type.startswith("text/html")
    for s in ("Security Assessment Report", "1. Executive summary", "2. System and assessment scope", "3. Methodology",
              "4. Vulnerability results", "5. Configuration (posture) results", "6. Control and STIG coverage",
              "7. Scanner versions and database freshness", "8. Limitations", "Appendix A. Inventory",
              "Appendix B. All open vulnerability findings"):
        assert s in html, s
    assert "#9547c0" in html and "<svg" in html  # brand colour + logo/trend chart
    assert "CVE-2024-45490" in html
    assert "Clair database is 5.0 days old" in html
    assert "sha256" not in html or "a1a1a1a1a1a1" in html
    assert "page-break" in html and "@page" in html
    assert "UNCLASSIFIED" in html


def test_html_without_trend(opts):
    html = generate("sar", "html", make_snapshot(trend=[]), opts).content.decode()
    assert "Score trend" not in html


def test_pdf(snapshot, opts):
    try:
        rep = generate("sar", "pdf", snapshot, opts)
    except ReportDependencyMissing as exc:
        pytest.skip(f"WeasyPrint system libraries unavailable on this host: {exc}")
    assert rep.content.startswith(b"%PDF")
    assert rep.content_type == "application/pdf"
    assert len(rep.content) > 20_000
