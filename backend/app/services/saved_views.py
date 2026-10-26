"""Saved filter views — CRUD wrapped in the tenant_session pattern.

Views are namespaced by `kind` (e.g. 'coverage_matrix', 'detections') so
the UI can list "all views for this page" without filtering client-side.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select

from app.db.tenant import tenant_session
from app.models.customer import SavedView


@dataclass
class SavedViewOut:
    id: str
    name: str
    kind: str
    payload: dict
    author_email: Optional[str]
    updated_at: str


def _to_out(v: SavedView) -> SavedViewOut:
    return SavedViewOut(
        id=str(v.id),
        name=v.name,
        kind=v.kind,
        payload=dict(v.payload or {}),
        author_email=v.author_email,
        updated_at=v.updated_at.isoformat() if v.updated_at else "",
    )


async def list_views(kind: Optional[str] = None) -> list[SavedViewOut]:
    async with tenant_session() as session:
        stmt = select(SavedView).order_by(SavedView.name)
        if kind:
            stmt = stmt.where(SavedView.kind == kind)
        rows = (await session.execute(stmt)).scalars().all()
        return [_to_out(v) for v in rows]


async def upsert_view(
    *,
    name: str,
    kind: str,
    payload: dict,
    author_email: Optional[str] = None,
) -> SavedViewOut:
    async with tenant_session() as session:
        existing = (
            await session.execute(
                select(SavedView).where(
                    SavedView.kind == kind,
                    SavedView.name == name,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row = SavedView(
                id=uuid.uuid4(),
                name=name,
                kind=kind,
                payload=payload,
                author_email=author_email,
            )
            session.add(row)
        else:
            existing.payload = payload
            existing.author_email = author_email
            row = existing
        await session.flush()
        await session.refresh(row)
        return _to_out(row)


async def delete_view(view_id: str) -> bool:
    try:
        uid = uuid.UUID(view_id)
    except ValueError:
        return False
    async with tenant_session() as session:
        row = (
            await session.execute(select(SavedView).where(SavedView.id == uid))
        ).scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        return True


__all__ = ["SavedViewOut", "delete_view", "list_views", "upsert_view"]
