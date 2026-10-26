"""APT (intrusion-set) reference + per-group coverage breakdown."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.models.public import AttackGroup
from app.services.apt_analysis import group_coverage_breakdown
from app.services.coverage import DenominatorKind, compute_score

router = APIRouter(prefix="/apt", tags=["apt"])


class APTGroupOut(BaseModel):
    group_id: str
    name: str
    aliases: list[str]
    description: Optional[str]
    deprecated: bool
    revoked: bool


class PaginatedAPT(BaseModel):
    items: list[APTGroupOut]
    total: int
    page: int
    page_size: int


class GroupBreakdownTechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    state: str
    detection_count: int
    max_depth: int
    sources: list[str]


class GroupBreakdownOut(BaseModel):
    group_id: str
    name: str
    aliases: list[str]
    description: Optional[str]
    technique_count: int
    covered_count: int
    deployed_count: int
    breadth_pct: float
    breadth_grade: str
    depth_grade: str
    posture_grade: str
    by_tactic: dict[str, list[GroupBreakdownTechniqueOut]]


@router.get("/groups", response_model=PaginatedAPT)
async def list_groups(
    domain: str = Query("enterprise"),
    q: Optional[str] = Query(None, description="ILIKE on name"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    include_deprecated: bool = Query(False),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> PaginatedAPT:
    async with AsyncSessionLocal() as session:
        base = select(AttackGroup).where(AttackGroup.domain == domain)
        count_q = select(func.count()).select_from(AttackGroup).where(AttackGroup.domain == domain)
        if not include_deprecated:
            base = base.where(
                AttackGroup.deprecated.is_(False),
                AttackGroup.revoked.is_(False),
            )
            count_q = count_q.where(
                AttackGroup.deprecated.is_(False),
                AttackGroup.revoked.is_(False),
            )
        if q:
            base = base.where(AttackGroup.name.ilike(f"%{q}%"))
            count_q = count_q.where(AttackGroup.name.ilike(f"%{q}%"))
        base = base.order_by(AttackGroup.name).offset((page - 1) * page_size).limit(page_size)
        total = (await session.execute(count_q)).scalar_one()
        rows = (await session.execute(base)).scalars().all()

    return PaginatedAPT(
        items=[
            APTGroupOut(
                group_id=r.group_id,
                name=r.name,
                aliases=list(r.aliases or []),
                description=r.description,
                deprecated=r.deprecated,
                revoked=r.revoked,
            )
            for r in rows
        ],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/groups/{group_id}", response_model=GroupBreakdownOut)
async def get_group(
    group_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> GroupBreakdownOut:
    breakdown = await group_coverage_breakdown(domain, group_id)
    if breakdown is None:
        raise HTTPException(404, f"group {group_id!r} not found")

    score = await compute_score(domain, DenominatorKind.APT, group_id)

    return GroupBreakdownOut(
        group_id=breakdown.group_id,
        name=breakdown.name,
        aliases=breakdown.aliases,
        description=breakdown.description,
        technique_count=breakdown.technique_count,
        covered_count=breakdown.covered_count,
        deployed_count=breakdown.deployed_count,
        breadth_pct=score.breadth_pct,
        breadth_grade=score.breadth_grade,
        depth_grade=score.depth_grade,
        posture_grade=score.posture_grade,
        by_tactic={
            tac: [
                GroupBreakdownTechniqueOut(
                    technique_id=t.technique_id,
                    name=t.name,
                    tactics=t.tactics,
                    is_subtechnique=t.is_subtechnique,
                    parent_technique_id=t.parent_technique_id,
                    state=t.state.value,
                    detection_count=t.detection_count,
                    max_depth=t.max_depth,
                    sources=t.sources,
                )
                for t in cells
            ]
            for tac, cells in breakdown.by_tactic.items()
        },
    )


__all__ = ["router"]
