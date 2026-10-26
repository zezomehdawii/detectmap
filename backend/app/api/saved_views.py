"""Saved filter views CRUD — per-tenant."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.services.saved_views import delete_view, list_views, upsert_view

router = APIRouter(prefix="/views", tags=["views"])


class SavedViewOut(BaseModel):
    id: str
    name: str
    kind: str
    payload: dict
    author_email: Optional[str]
    updated_at: str


class SavedViewCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    kind: str = Field(..., min_length=1, max_length=40)
    payload: dict = Field(default_factory=dict)


@router.get("", response_model=list[SavedViewOut])
async def list_(
    kind: Optional[str] = None,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[SavedViewOut]:
    rows = await list_views(kind=kind)
    return [SavedViewOut(**r.__dict__) for r in rows]


@router.post("", response_model=SavedViewOut, status_code=201)
async def create_(
    payload: SavedViewCreate,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SavedViewOut:
    out = await upsert_view(
        name=payload.name.strip(),
        kind=payload.kind.strip(),
        payload=payload.payload,
        author_email=principal.user.email,
    )
    return SavedViewOut(**out.__dict__)


@router.delete("/{view_id}")
async def delete_(
    view_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    ok = await delete_view(view_id)
    if not ok:
        raise HTTPException(404, "view not found")
    return Response(status_code=204)


__all__ = ["router"]
