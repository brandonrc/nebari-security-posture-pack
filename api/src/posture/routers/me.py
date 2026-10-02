from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import User, current_user

router = APIRouter(tags=["me"])


@router.get("/me")
async def me(user: User = Depends(current_user)) -> dict:
    """Identity of the caller. Valid token required; admin group NOT required so the UI
    can explain a 403 to non-admins."""
    return user.as_dict()
