"""Gap analysis — top uncovered techniques + per-gap workflow.

Workflow endpoints (per (technique_id, domain)):
  GET    /gaps/{technique_id}                    detail bundle for the drawer
  GET    /gaps/{technique_id}/comments           thread of analyst comments
  POST   /gaps/{technique_id}/comments           append a comment
  DELETE /gaps/comments/{comment_id}             delete (author or admin)
  GET    /gaps/{technique_id}/ignore             current ignore record (or null)
  POST   /gaps/{technique_id}/ignore             accept the gap with a reason
  DELETE /gaps/{technique_id}/ignore             un-ignore (re-surface the gap)
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import (
    DetectionTechnique,
    GapComment,
    GapIgnore,
)
from app.models.public import (
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackSoftwareTechnique,
    AttackTechnique,
    Role,
)
from app.services.apt_analysis import gap_ranking
from app.services.coverage import DenominatorKind

router = APIRouter(prefix="/gaps", tags=["gaps"])


# ============================================================================
# Top-gaps ranking (existing)
# ============================================================================

class GapSampleGroup(BaseModel):
    group_id: str
    name: str


class GapEntryOut(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    apt_count: int
    direct_group_count: int
    software_group_count: int
    sample_groups: list[GapSampleGroup]
    detection_count: int
    # Workflow state attached for the row (so the UI can render badges
    # without an extra request per technique).
    comment_count: int = 0
    is_ignored: bool = False


class GapTopOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    items: list[GapEntryOut]


def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator kind: {s!r}") from e


async def _active_ignore_tids(domain: str) -> set[str]:
    """Technique IDs the tenant has actively ignored for this domain.

    Ignores with an expired `ignored_until` date are NOT included so the
    gap re-surfaces automatically — matches the "deferred until Q3" use case.
    """
    today = date.today()
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(GapIgnore.technique_id).where(
                    GapIgnore.domain == domain,
                    (GapIgnore.ignored_until.is_(None))
                    | (GapIgnore.ignored_until >= today),
                )
            )
        ).scalars().all()
    return set(rows)


async def _comment_counts(domain: str, tids: list[str]) -> dict[str, int]:
    if not tids:
        return {}
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(GapComment.technique_id, func.count(GapComment.id))
                .where(
                    GapComment.domain == domain,
                    GapComment.technique_id.in_(tids),
                )
                .group_by(GapComment.technique_id)
            )
        ).all()
    return {tid: int(n) for tid, n in rows}


@router.get("/top", response_model=GapTopOut)
async def top_gaps(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    limit: int = Query(25, ge=1, le=200),
    include_ignored: bool = Query(
        False,
        description="When True, ignored gaps stay in the ranking with is_ignored=True. "
        "Default hides them.",
    ),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> GapTopOut:
    kind = _parse_kind(denominator)
    # Pull a slightly wider ranking when we need to filter ignores so the
    # final list still has `limit` rows in the common case.
    rank_limit = limit if include_ignored else max(limit * 2, limit + 10)
    entries = await gap_ranking(domain, kind, ref, limit=rank_limit)

    ignored = await _active_ignore_tids(domain)
    if not include_ignored:
        entries = [e for e in entries if e.technique_id not in ignored]
    entries = entries[:limit]

    counts = await _comment_counts(domain, [e.technique_id for e in entries])

    return GapTopOut(
        domain=domain,
        denominator_kind=kind.value,
        denominator_ref=ref,
        items=[
            GapEntryOut(
                technique_id=e.technique_id,
                name=e.name,
                tactics=e.tactics,
                is_subtechnique=e.is_subtechnique,
                parent_technique_id=e.parent_technique_id,
                apt_count=e.apt_count,
                direct_group_count=e.direct_group_count,
                software_group_count=e.software_group_count,
                sample_groups=[GapSampleGroup(**g) for g in e.sample_groups],
                detection_count=e.detection_count,
                comment_count=counts.get(e.technique_id, 0),
                is_ignored=e.technique_id in ignored,
            )
            for e in entries
        ],
    )


# ============================================================================
# Gap detail bundle
# ============================================================================

class GapCommentOut(BaseModel):
    id: str
    technique_id: str
    domain: str
    body: str
    author_email: Optional[str]
    created_at: str


class GapIgnoreOut(BaseModel):
    id: str
    technique_id: str
    domain: str
    reason: str
    author_email: Optional[str]
    ignored_until: Optional[str]
    created_at: str


class GapAPTRef(BaseModel):
    group_id: str
    name: str
    via: str  # "direct" | "software"


class GapDetailOut(BaseModel):
    technique_id: str
    domain: str
    name: str
    description: Optional[str]
    url: Optional[str]
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    deprecated: bool
    revoked: bool
    detection_count: int
    apt_groups: list[GapAPTRef]
    comments: list[GapCommentOut]
    ignore: Optional[GapIgnoreOut]


def _comment_out(c: GapComment) -> GapCommentOut:
    return GapCommentOut(
        id=str(c.id),
        technique_id=c.technique_id,
        domain=c.domain,
        body=c.body,
        author_email=c.author_email,
        created_at=c.created_at.isoformat() if c.created_at else "",
    )


def _ignore_out(i: GapIgnore) -> GapIgnoreOut:
    return GapIgnoreOut(
        id=str(i.id),
        technique_id=i.technique_id,
        domain=i.domain,
        reason=i.reason,
        author_email=i.author_email,
        ignored_until=i.ignored_until.isoformat() if i.ignored_until else None,
        created_at=i.created_at.isoformat() if i.created_at else "",
    )


@router.get("/{technique_id}", response_model=GapDetailOut)
async def gap_detail(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> GapDetailOut:
    # ATT&CK catalog row (public)
    async with AsyncSessionLocal() as session:
        tech = (
            await session.execute(
                select(AttackTechnique).where(
                    AttackTechnique.domain == domain,
                    AttackTechnique.technique_id == technique_id,
                )
            )
        ).scalar_one_or_none()
        if tech is None:
            raise HTTPException(404, f"technique {technique_id!r} not found in {domain}")

        # APT groups using this technique — direct + via software.
        direct_rows = (
            await session.execute(
                select(AttackGroup.group_id, AttackGroup.name)
                .join(
                    AttackGroupTechnique,
                    (AttackGroupTechnique.group_id == AttackGroup.group_id)
                    & (AttackGroupTechnique.domain == AttackGroup.domain),
                )
                .where(
                    AttackGroupTechnique.domain == domain,
                    AttackGroupTechnique.technique_id == technique_id,
                )
                .distinct()
            )
        ).all()
        direct_set = {gid: name for gid, name in direct_rows}

        sw_rows = (
            await session.execute(
                select(AttackGroup.group_id, AttackGroup.name)
                .join(
                    AttackGroupSoftware,
                    (AttackGroupSoftware.group_id == AttackGroup.group_id)
                    & (AttackGroupSoftware.domain == AttackGroup.domain),
                )
                .join(
                    AttackSoftwareTechnique,
                    (AttackSoftwareTechnique.software_id == AttackGroupSoftware.software_id)
                    & (AttackSoftwareTechnique.domain == AttackGroupSoftware.domain),
                )
                .where(
                    AttackSoftwareTechnique.domain == domain,
                    AttackSoftwareTechnique.technique_id == technique_id,
                )
                .distinct()
            )
        ).all()

    apt_refs: list[GapAPTRef] = []
    seen: set[str] = set()
    for gid, name in direct_rows:
        if gid in seen:
            continue
        seen.add(gid)
        apt_refs.append(GapAPTRef(group_id=gid, name=name, via="direct"))
    for gid, name in sw_rows:
        if gid in seen:
            continue
        seen.add(gid)
        apt_refs.append(GapAPTRef(group_id=gid, name=name, via="software"))
    apt_refs.sort(key=lambda r: r.group_id)

    # Tenant-side: detection count + comments + ignore.
    today = date.today()
    async with tenant_session() as session:
        det_count = (
            await session.execute(
                select(func.count(func.distinct(DetectionTechnique.detection_id))).where(
                    DetectionTechnique.technique_id == technique_id,
                )
            )
        ).scalar_one() or 0
        comments = (
            await session.execute(
                select(GapComment)
                .where(
                    GapComment.technique_id == technique_id,
                    GapComment.domain == domain,
                )
                .order_by(GapComment.created_at.desc())
            )
        ).scalars().all()
        ignore_row = (
            await session.execute(
                select(GapIgnore).where(
                    GapIgnore.technique_id == technique_id,
                    GapIgnore.domain == domain,
                    (GapIgnore.ignored_until.is_(None))
                    | (GapIgnore.ignored_until >= today),
                )
            )
        ).scalar_one_or_none()

    return GapDetailOut(
        technique_id=tech.technique_id,
        domain=tech.domain,
        name=tech.name,
        description=tech.description,
        url=tech.url,
        tactics=list(tech.tactics or []),
        platforms=list(tech.platforms or []),
        is_subtechnique=tech.is_subtechnique,
        parent_technique_id=tech.parent_technique_id,
        deprecated=tech.deprecated,
        revoked=tech.revoked,
        detection_count=int(det_count),
        apt_groups=apt_refs,
        comments=[_comment_out(c) for c in comments],
        ignore=_ignore_out(ignore_row) if ignore_row else None,
    )


# ============================================================================
# Comments
# ============================================================================

class GapCommentIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)
    domain: str = "enterprise"


@router.get("/{technique_id}/comments", response_model=list[GapCommentOut])
async def list_gap_comments(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[GapCommentOut]:
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(GapComment)
                .where(
                    GapComment.technique_id == technique_id,
                    GapComment.domain == domain,
                )
                .order_by(GapComment.created_at.desc())
            )
        ).scalars().all()
    return [_comment_out(r) for r in rows]


@router.post(
    "/{technique_id}/comments",
    response_model=GapCommentOut,
    status_code=201,
)
async def add_gap_comment(
    technique_id: str,
    payload: GapCommentIn = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> GapCommentOut:
    body = payload.body.strip()
    if not body:
        raise HTTPException(422, "comment body must not be empty")
    async with tenant_session() as session:
        row = GapComment(
            id=uuid.uuid4(),
            technique_id=technique_id,
            domain=payload.domain,
            body=body,
            author_email=principal.user.email,
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        # tenant_session() owns the transaction (async with session.begin())
        # — it commits on exit. Don't call session.commit() here; doing so
        # closes the outer transaction and any follow-up op raises.
    return _comment_out(row)


@router.delete("/comments/{comment_id}", status_code=204)
async def delete_gap_comment(
    comment_id: uuid.UUID,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
):
    async with tenant_session() as session:
        row = (
            await session.execute(select(GapComment).where(GapComment.id == comment_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "comment not found")
        is_admin = principal.user.role in (Role.MSSP_ADMIN, Role.MSSP_ANALYST)
        if row.author_email != principal.user.email and not is_admin:
            raise HTTPException(403, "you can only delete your own comments")
        await session.delete(row)
        # tenant_session() commits on exit.
    return Response(status_code=204)


# ============================================================================
# Ignore / un-ignore
# ============================================================================

class GapIgnoreIn(BaseModel):
    reason: str = Field(..., min_length=3, max_length=2000)
    domain: str = "enterprise"
    ignored_until: Optional[date] = Field(
        default=None,
        description="Optional date when the ignore expires and the gap re-surfaces.",
    )


@router.get("/{technique_id}/ignore", response_model=Optional[GapIgnoreOut])
async def get_gap_ignore(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Optional[GapIgnoreOut]:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(GapIgnore).where(
                    GapIgnore.technique_id == technique_id,
                    GapIgnore.domain == domain,
                )
            )
        ).scalar_one_or_none()
    return _ignore_out(row) if row else None


@router.post("/{technique_id}/ignore", response_model=GapIgnoreOut)
async def upsert_gap_ignore(
    technique_id: str,
    payload: GapIgnoreIn = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> GapIgnoreOut:
    reason = payload.reason.strip()
    if not reason:
        raise HTTPException(422, "reason must not be empty")
    if payload.ignored_until is not None and payload.ignored_until < date.today():
        raise HTTPException(422, "ignored_until cannot be in the past")
    async with tenant_session() as session:
        existing = (
            await session.execute(
                select(GapIgnore).where(
                    GapIgnore.technique_id == technique_id,
                    GapIgnore.domain == payload.domain,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row = GapIgnore(
                id=uuid.uuid4(),
                technique_id=technique_id,
                domain=payload.domain,
                reason=reason,
                author_email=principal.user.email,
                ignored_until=payload.ignored_until,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
        else:
            existing.reason = reason
            existing.author_email = principal.user.email
            existing.ignored_until = payload.ignored_until
            row = existing
        # tenant_session() commits on exit. The row already carries every
        # field we return (created_at is set Python-side for new rows; the
        # update path doesn't change created_at), so no refresh needed.
    return _ignore_out(row)


@router.delete("/{technique_id}/ignore", status_code=204)
async def delete_gap_ignore(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
):
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(GapIgnore).where(
                    GapIgnore.technique_id == technique_id,
                    GapIgnore.domain == domain,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "no ignore record to remove")
        await session.delete(row)
        # tenant_session() commits on exit.
    return Response(status_code=204)


__all__ = ["router"]
