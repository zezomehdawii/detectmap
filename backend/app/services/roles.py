"""Role + permission service.

Bridges the static built-in `Role` enum (and its hardcoded permission
grants in `app.core.rbac._GRANTS`) with the DB-backed `CustomRole` table.

Resolution rules:
  - If a user has `custom_role_id` set, the resolved permission set comes
    from that row's `permissions` JSON. The built-in `users.role` enum
    still indicates the user's "kind" (MSSP vs customer-scoped) and is
    used for tenant gating, but permission checks defer to the custom row.
  - Otherwise the built-in grants for `users.role` apply.

This module is the single source of truth for "what can this user do?".
`app.api.deps.require_perm` calls into `user_has_permission` here so the
two sides never drift.
"""
from __future__ import annotations

import re
import uuid
from typing import Iterable, Optional

from sqlalchemy import select

from app.core.rbac import (
    PERMISSION_METADATA,
    Permission,
    builtin_grants,
    role_has,
)
from app.db.base import AsyncSessionLocal
from app.models.public import CustomRole, Role, User


_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,58}$")
_BUILTIN_KEYS = {r.value for r in Role}


def _normalise_permissions(perms: Iterable[str]) -> list[str]:
    """Validate a list of permission keys and return them sorted+deduped.

    Raises ValueError if any key is not a recognised Permission. We use
    string keys at the API boundary because the Permission enum values
    are already strings — keeping the JSON shape stable is more
    important than typing it as an enum in transit.
    """
    valid = {p.value for p in Permission}
    out: set[str] = set()
    for p in perms:
        if p not in valid:
            raise ValueError(f"unknown permission: {p!r}")
        out.add(p)
    return sorted(out)


def _validate_key(key: str) -> str:
    key = key.strip().lower()
    if not _KEY_RE.match(key):
        raise ValueError(
            "role key must be 2-59 chars, start with a letter, and contain "
            "only lowercase letters, digits, or underscores"
        )
    if key in _BUILTIN_KEYS:
        raise ValueError(f"role key {key!r} is reserved for a built-in role")
    return key


# ---- queries -------------------------------------------------------------

async def list_custom_roles(mssp_org_id: uuid.UUID) -> list[CustomRole]:
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(CustomRole)
                .where(CustomRole.mssp_org_id == mssp_org_id)
                .order_by(CustomRole.label)
            )
        ).scalars().all()
    return list(rows)


async def get_custom_role(
    role_id: uuid.UUID, mssp_org_id: uuid.UUID
) -> Optional[CustomRole]:
    async with AsyncSessionLocal() as session:
        return (
            await session.execute(
                select(CustomRole).where(
                    CustomRole.id == role_id,
                    CustomRole.mssp_org_id == mssp_org_id,
                )
            )
        ).scalar_one_or_none()


# ---- mutations -----------------------------------------------------------

async def create_custom_role(
    *,
    mssp_org_id: uuid.UUID,
    key: str,
    label: str,
    description: Optional[str],
    permissions: Iterable[str],
) -> CustomRole:
    key = _validate_key(key)
    perms = _normalise_permissions(permissions)
    async with AsyncSessionLocal() as session:
        row = CustomRole(
            id=uuid.uuid4(),
            mssp_org_id=mssp_org_id,
            key=key,
            label=label.strip()[:120] or key,
            description=(description or None),
            permissions=perms,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row


async def update_custom_role(
    *,
    role_id: uuid.UUID,
    mssp_org_id: uuid.UUID,
    label: Optional[str] = None,
    description: Optional[str] = None,
    permissions: Optional[Iterable[str]] = None,
) -> Optional[CustomRole]:
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(
                select(CustomRole).where(
                    CustomRole.id == role_id,
                    CustomRole.mssp_org_id == mssp_org_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        if label is not None:
            row.label = label.strip()[:120] or row.label
        if description is not None:
            row.description = description or None
        if permissions is not None:
            row.permissions = _normalise_permissions(permissions)
        await session.commit()
        await session.refresh(row)
        return row


async def delete_custom_role(
    role_id: uuid.UUID, mssp_org_id: uuid.UUID
) -> tuple[bool, int]:
    """Delete the role; returns (deleted, users_unassigned).

    Because the FK on users.custom_role_id is ON DELETE SET NULL, users
    keep their built-in role and just lose the override. We pre-count to
    surface the impact to the caller for confirmation messaging.
    """
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(
                select(CustomRole).where(
                    CustomRole.id == role_id,
                    CustomRole.mssp_org_id == mssp_org_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return False, 0
        users_affected = (
            await session.execute(
                select(User).where(User.custom_role_id == role_id)
            )
        ).scalars().all()
        n = len(users_affected)
        await session.delete(row)
        await session.commit()
        return True, n


# ---- permission resolution (the single source of truth) ------------------

async def resolve_permissions(user: User) -> set[Permission]:
    """The effective permission set for a user.

    If the user has a custom role, that's authoritative (we re-resolve
    against the live `permissions` JSON each time so role edits take
    effect on the next request, no token refresh needed). Otherwise the
    built-in grants for `users.role` apply.
    """
    if user.custom_role_id is not None:
        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(
                    select(CustomRole).where(CustomRole.id == user.custom_role_id)
                )
            ).scalar_one_or_none()
        if row is not None:
            valid = {p.value: p for p in Permission}
            return {valid[k] for k in (row.permissions or []) if k in valid}
        # Role was deleted mid-flight — fall through to built-in.
    return builtin_grants(user.role)


async def user_has_permission(user: User, perm: Permission) -> bool:
    """Whether `user` is granted `perm` — honours custom_role_id."""
    if user.custom_role_id is None:
        # Fast path: no DB hit needed for users on built-in roles.
        return role_has(user.role, perm)
    perms = await resolve_permissions(user)
    return perm in perms


# ---- catalog (for the admin UI) ------------------------------------------

def permission_catalog() -> list[dict]:
    """All permissions, with their human-readable metadata, sorted by category."""
    out: list[dict] = []
    for p in Permission:
        meta = PERMISSION_METADATA.get(p, {})
        out.append(
            {
                "key": p.value,
                "category": meta.get("category", "Other"),
                "label": meta.get("label", p.name.replace("_", " ").title()),
                "description": meta.get("description", ""),
            }
        )
    out.sort(key=lambda r: (r["category"], r["label"]))
    return out


def builtin_role_grants() -> list[dict]:
    """The full built-in role × permission matrix, for read-only display."""
    out: list[dict] = []
    for role in Role:
        out.append(
            {
                "key": role.value,
                "label": role.value.replace("_", " ").title(),
                "is_builtin": True,
                "permissions": sorted(p.value for p in builtin_grants(role)),
            }
        )
    return out


__all__ = [
    "list_custom_roles",
    "get_custom_role",
    "create_custom_role",
    "update_custom_role",
    "delete_custom_role",
    "resolve_permissions",
    "user_has_permission",
    "permission_catalog",
    "builtin_role_grants",
]
