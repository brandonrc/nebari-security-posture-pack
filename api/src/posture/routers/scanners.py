from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..db.session import get_session
from ..views import SCANNERS, scanner_dict, scanner_rows

router = APIRouter(tags=["scanners"])


@router.get("/scanners")
async def list_scanners(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    settings = await app_settings.load(session)
    enabled = settings.scanners.model_dump()
    rows = await scanner_rows(session)
    from .stig import scap_scanner_entry

    # DESIGN §14: `scap` (OpenSCAP) after the vulnerability scanners, with its content catalogue;
    # dbUpdatedAt = newest content fetch
    return [scanner_dict(n, rows.get(n), enabled[n]) for n in SCANNERS] + [
        await scap_scanner_entry(session, rows.get("scap"), bool(enabled.get("scap")))]
