from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..auth import User, require_admin
from ..db.session import get_session
from ..logs import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["settings"])


@router.get("/settings")
async def get_settings_(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return (await app_settings.load(session)).model_dump(by_alias=True)


@router.put("/settings")
async def put_settings(body: dict[str, Any] = Body(...), user: User = Depends(require_admin),
                       session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    current = await app_settings.load(session)
    try:
        new = app_settings.apply_patch(current, body)
    except ValidationError as e:
        raise HTTPException(422, detail=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()]) from e
    saved = await app_settings.save(session, new, user.username)
    log.info("settings.updated", user=user.username, keys=",".join(sorted(body)))
    return saved.model_dump(by_alias=True)
