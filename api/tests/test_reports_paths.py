"""Security review L7 + report path handling: deletions are attributed, files outside
REPORTS_DIR are never read or unlinked."""

import contextlib
import logging
import uuid

import pytest
from fastapi import HTTPException

from posture.auth import User
from posture.db.models import Report
from posture.routers import reports as rr


class FakeSession:
    def __init__(self, row):
        self.row, self.deleted = row, False

    @contextlib.asynccontextmanager
    async def begin(self):
        yield

    async def get(self, model, key, **kw):
        return self.row if self.row is not None and self.row.id == key else None

    async def delete(self, row):
        self.deleted = True


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    d = tmp_path / "reports"
    d.mkdir()
    monkeypatch.setattr(rr.report_jobs, "reports_dir", lambda: d)
    return d


def _row(path, **kw):
    return Report(id=uuid.uuid4(), type="poam", format="csv", status="done", path=str(path) if path else None,
                  filename="r.csv", content_type="text/csv", scan_id=3, created_by="bob", **kw)


ADMIN = User("alice", None, ["admin"], True)


async def test_delete_is_logged_with_user(reports_dir, caplog):
    f = reports_dir / "x.csv"
    f.write_text("a")
    row = _row(f)
    with caplog.at_level(logging.INFO):
        resp = await rr.delete_report(str(row.id), ADMIN, FakeSession(row))
    assert resp.status_code == 204 and not f.exists()
    rec = [r for r in caplog.records if "report.deleted" in r.getMessage()]
    assert rec and rec[0].kv["user"] == "alice" and rec[0].kv["report_id"] == str(row.id)
    assert rec[0].kv["type"] == "poam" and rec[0].kv["created_by"] == "bob"


async def test_delete_never_unlinks_outside_reports_dir(reports_dir, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    for p in (victim, reports_dir / ".." / "victim.txt"):
        row = _row(p)
        s = FakeSession(row)
        assert (await rr.delete_report(str(row.id), ADMIN, s)).status_code == 204
        assert s.deleted and victim.read_text() == "keep"


async def test_download_refuses_path_outside_reports_dir(reports_dir, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    row = _row(secret)
    with pytest.raises(HTTPException) as e:
        await rr.download_report(str(row.id), FakeSession(row))
    assert e.value.status_code == 410
    inside = reports_dir / f"{row.id}.csv"
    inside.write_text("ok")
    row.path = str(inside)
    resp = await rr.download_report(str(row.id), FakeSession(row))
    assert str(resp.path) == str(inside.resolve())


async def test_symlink_escape_refused(reports_dir, tmp_path):
    target = tmp_path / "outside"
    target.write_text("x")
    link = reports_dir / "link.csv"
    link.symlink_to(target)
    assert rr._report_path(_row(link)) is None


async def test_default_path_when_row_has_none(reports_dir):
    row = _row(None)
    assert rr._report_path(row) == (reports_dir / f"{row.id}.csv").resolve()
