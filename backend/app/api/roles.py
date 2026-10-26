"""Roles & permissions endpoints.

  GET    /roles/permissions     full Permission catalog with metadata
  GET    /roles/builtin         the immutable built-in role → perms matrix
  GET    /roles                 caller's MSSP-org custom roles
  POST   /roles                 create a custom role
  GET    /roles/{role_id}       fetch a custom role
  PATCH  /roles/{role_id}       update a custom role's label/desc/perms
  DELETE /roles/{role_id}       delete a custom role (users keep built-in role)
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.api.deps import TenantPrincipal, require_perm
from app.api.settings import _record_audit
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.models.public import CustomRole
from app.services.roles import (
    builtin_role_grants,
    create_custom_role,
    delete_custom_role,
    get_custom_role,
    list_custom_roles,
    permission_catalog,
    update_custom_role,
)

router = APIRouter(prefix="/roles", tags=["roles"])


# ---- read-only catalogs --------------------------------------------------

class PermissionOut(BaseModel):
    key: str
    category: str
    label: str
    description: str


class BuiltinRoleOut(BaseModel):
    key: str
    label: str
    is_builtin: bool
    permissions: list[str]


@router.get("/permissions", response_model=list[PermissionOut])
async def get_permission_catalog(
    _: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> list[PermissionOut]:
    """All Permission keys, grouped by category. Drives the role editor's
    permission picker so the UI doesn't have to hardcode the list."""
    return [PermissionOut(**r) for r in permission_catalog()]


@router.get("/builtin", response_model=list[BuiltinRoleOut])
async def get_builtin_roles(
    _: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> list[BuiltinRoleOut]:
    """Built-in role → permissions matrix. Read-only; shown as the baseline
    next to the custom roles in the admin UI."""
    return [BuiltinRoleOut(**r) for r in builtin_role_grants()]


# ---- custom roles --------------------------------------------------------

class CustomRoleOut(BaseModel):
    id: str
    mssp_org_id: str
    key: str
    label: str
    description: Optional[str]
    permissions: list[str]
    is_builtin: bool = False
    created_at: str
    updated_at: str


class CustomRoleCreate(BaseModel):
    key: str = Field(..., min_length=2, max_length=60)
    label: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=4000)
    permissions: list[str] = Field(default_factory=list)


class CustomRolePatch(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=4000)
    permissions: Optional[list[str]] = None


def _out(r: CustomRole) -> CustomRoleOut:
    return CustomRoleOut(
        id=str(r.id),
        mssp_org_id=str(r.mssp_org_id),
        key=r.key,
        label=r.label,
        description=r.description,
        permissions=list(r.permissions or []),
        is_builtin=False,
        created_at=r.created_at.isoformat() if r.created_at else "",
        updated_at=r.updated_at.isoformat() if r.updated_at else "",
    )


def _require_org_id(principal: TenantPrincipal) -> uuid.UUID:
    org_id = principal.user.mssp_org_id
    if org_id is None:
        raise HTTPException(403, "user has no MSSP org")
    return org_id


@router.get("", response_model=list[CustomRoleOut])
async def list_roles(
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> list[CustomRoleOut]:
    org_id = _require_org_id(principal)
    rows = await list_custom_roles(org_id)
    return [_out(r) for r in rows]


@router.get("/{role_id}", response_model=CustomRoleOut)
async def get_role(
    role_id: uuid.UUID,
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> CustomRoleOut:
    org_id = _require_org_id(principal)
    row = await get_custom_role(role_id, org_id)
    if row is None:
        raise HTTPException(404, "custom role not found")
    return _out(row)


@router.post("", response_model=CustomRoleOut, status_code=201)
async def create_role(
    payload: CustomRoleCreate = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> CustomRoleOut:
    org_id = _require_org_id(principal)
    try:
        row = await create_custom_role(
            mssp_org_id=org_id,
            key=payload.key,
            label=payload.label,
            description=payload.description,
            permissions=payload.permissions,
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    async with AsyncSessionLocal() as session:
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="role.create",
            target=row.key,
            detail=f"label={row.label} perms={len(row.permissions)}",
        )
        await session.commit()
    return _out(row)


@router.patch("/{role_id}", response_model=CustomRoleOut)
async def patch_role(
    role_id: uuid.UUID,
    payload: CustomRolePatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> CustomRoleOut:
    org_id = _require_org_id(principal)
    try:
        row = await update_custom_role(
            role_id=role_id,
            mssp_org_id=org_id,
            label=payload.label,
            description=payload.description,
            permissions=payload.permissions,
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    if row is None:
        raise HTTPException(404, "custom role not found")
    async with AsyncSessionLocal() as session:
        changed = sorted(payload.model_dump(exclude_none=True).keys())
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="role.update",
            target=row.key,
            detail="changed: " + ", ".join(changed) if changed else "no-op",
        )
        await session.commit()
    return _out(row)


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: uuid.UUID,
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
):
    org_id = _require_org_id(principal)
    row = await get_custom_role(role_id, org_id)
    if row is None:
        raise HTTPException(404, "custom role not found")
    key = row.key
    deleted, n_unassigned = await delete_custom_role(role_id, org_id)
    if not deleted:
        raise HTTPException(404, "custom role not found")
    async with AsyncSessionLocal() as session:
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="role.delete",
            target=key,
            detail=f"{n_unassigned} users reverted to their built-in role",
        )
        await session.commit()
    return Response(status_code=204)


__all__ = ["router"]
