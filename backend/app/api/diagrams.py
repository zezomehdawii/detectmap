"""Customer-profile network diagrams.

Uploads land on the filesystem under DIAGRAM_STORAGE_ROOT; the DB row
holds only metadata. The list / detail endpoints return JSON (no bytes);
`GET /diagrams/{id}/file` streams the bytes back with a sensible
Content-Disposition (inline for image/PDF, attachment for binaries).

Authorisation reuses ASSET_READ / ASSET_WRITE — diagrams are part of the
same "profile" surface as assets and contacts, so a user authorised to
manage the asset register can manage the diagram set too.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.config import settings
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import CustomerDiagram
from app.services import diagram_storage

router = APIRouter(prefix="", tags=["customer-profile"])


# ---- payloads -----------------------------------------------------------


class DiagramOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    filename: str
    mime_type: str
    size_bytes: int
    kind: str  # image | pdf | binary
    is_primary: bool
    uploaded_by_email: Optional[str]
    uploaded_at: Optional[datetime]
    updated_at: Optional[datetime]


class DiagramPatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    is_primary: Optional[bool] = None


def _serialise(d: CustomerDiagram) -> DiagramOut:
    return DiagramOut(
        id=str(d.id),
        title=d.title,
        description=d.description,
        filename=d.filename,
        mime_type=d.mime_type,
        size_bytes=d.size_bytes,
        kind=d.kind,
        is_primary=d.is_primary,
        uploaded_by_email=d.uploaded_by_email,
        uploaded_at=d.uploaded_at,
        updated_at=d.updated_at,
    )


# ---- list / upload ------------------------------------------------------


@router.get("/diagrams", response_model=list[DiagramOut])
async def list_diagrams(
    kind: Optional[str] = Query(None, description="image | pdf | binary"),
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[DiagramOut]:
    async with tenant_session() as session:
        stmt = select(CustomerDiagram).order_by(
            CustomerDiagram.is_primary.desc(),
            CustomerDiagram.uploaded_at.desc(),
        )
        if kind:
            stmt = stmt.where(CustomerDiagram.kind == kind)
        rows = (await session.execute(stmt)).scalars().all()
    return [_serialise(r) for r in rows]


@router.post("/diagrams", response_model=DiagramOut, status_code=201)
async def upload_diagram(
    file: UploadFile = File(...),
    title: str = Form(..., min_length=1, max_length=200),
    description: Optional[str] = Form(default=None),
    is_primary: bool = Form(default=False),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> DiagramOut:
    # `principal.customer` is non-None thanks to require_active_customer.
    codename = principal.customer.codename  # type: ignore[union-attr]

    mime = (file.content_type or "application/octet-stream").lower()
    if diagram_storage.is_forbidden_mime(mime):
        raise HTTPException(415, f"unsupported file type: {mime}")

    # Read the whole payload — diagrams are small (default cap 50 MB) so
    # streaming-to-disk isn't worth the complexity. Enforce the cap as
    # we read so a malicious client can't fill the disk.
    data = await file.read()
    if len(data) > settings.diagram_max_bytes:
        raise HTTPException(
            413,
            f"file too large ({len(data)} bytes; max {settings.diagram_max_bytes})",
        )
    if not data:
        raise HTTPException(422, "file is empty")

    diagram_id = uuid.uuid4()
    stored_path = diagram_storage.write_bytes(
        codename=codename,
        diagram_id=diagram_id,
        filename=file.filename or "diagram",
        data=data,
    )
    kind = diagram_storage.kind_for_mime(mime)

    async with tenant_session() as session:
        if is_primary:
            # At most one primary diagram per tenant. Clear the previous
            # one before inserting so the post-condition holds even if
            # multiple uploads race.
            await session.execute(
                update(CustomerDiagram)
                .where(CustomerDiagram.is_primary.is_(True))
                .values(is_primary=False)
            )
        row = CustomerDiagram(
            id=diagram_id,
            title=title.strip(),
            description=(description or None),
            filename=file.filename or "diagram",
            stored_path=stored_path,
            mime_type=mime,
            size_bytes=len(data),
            kind=kind,
            is_primary=is_primary,
            uploaded_by_email=principal.user.email,
        )
        session.add(row)
        await session.flush()
    return _serialise(row)


# ---- single diagram (metadata / bytes / patch / delete) -----------------


@router.get("/diagrams/{diagram_id}", response_model=DiagramOut)
async def get_diagram(
    diagram_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> DiagramOut:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CustomerDiagram).where(CustomerDiagram.id == diagram_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "diagram not found")
        return _serialise(row)


@router.get("/diagrams/{diagram_id}/file")
async def download_diagram(
    diagram_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> FileResponse:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CustomerDiagram).where(CustomerDiagram.id == diagram_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "diagram not found")
        # Snapshot the bits we need before the session closes — the
        # FileResponse executes after this context exits.
        stored = row.stored_path
        mime = row.mime_type
        kind = row.kind
        filename = row.filename

    path = diagram_storage.absolute_path(stored)
    if not path.exists():
        raise HTTPException(410, "stored file missing on disk")
    # Inline for things the browser can render safely; attachment for
    # anything we'd hand off (Visio, Packet Tracer, zip, …).
    disposition = "inline" if kind in {"image", "pdf"} else "attachment"
    return FileResponse(
        path,
        media_type=mime,
        filename=filename,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
        },
    )


@router.patch("/diagrams/{diagram_id}", response_model=DiagramOut)
async def patch_diagram(
    diagram_id: uuid.UUID,
    payload: DiagramPatch,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> DiagramOut:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CustomerDiagram).where(CustomerDiagram.id == diagram_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "diagram not found")
        if payload.title is not None:
            row.title = payload.title.strip()
        if payload.description is not None:
            row.description = payload.description or None
        if payload.is_primary is not None:
            if payload.is_primary and not row.is_primary:
                await session.execute(
                    update(CustomerDiagram)
                    .where(CustomerDiagram.is_primary.is_(True))
                    .values(is_primary=False)
                )
            row.is_primary = payload.is_primary
        await session.flush()
        # Server-side onupdate fires on flush — refresh so the response
        # carries the new `updated_at` without a lazy-load after the
        # session closes (see _serialise_asset for the same pattern).
        await session.refresh(row)
        return _serialise(row)


@router.delete("/diagrams/{diagram_id}", status_code=204)
async def delete_diagram(
    diagram_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CustomerDiagram).where(CustomerDiagram.id == diagram_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "diagram not found")
        stored = row.stored_path
        await session.delete(row)
    # File goes after the DB commit — a stranded row would be worse than
    # a stranded file (the file gets garbage-collected on next
    # fresh-setup; a row referencing a missing file would 410 forever).
    diagram_storage.delete_file(stored)
    return Response(status_code=204)


__all__ = ["router"]
