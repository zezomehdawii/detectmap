"""Posture trend endpoint — chronological coverage_snapshots for charting."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import CoverageSnapshot
from app.services.coverage import DenominatorKind

router = APIRouter(prefix="/posture", tags=["posture"])


class TrendPoint(BaseModel):
    id: str
    taken_at: str
    breadth_pct: float
    depth_avg: float
    breadth_grade: str
    depth_grade: str
    posture_grade: str
    covered_count: int
    denominator_size: int
    deployed_count: int
    denominator_kind: str
    denominator_ref: Optional[str]


class TrendOut(BaseModel):
    domain: str
    denominator_kind: Optional[str]
    denominator_ref: Optional[str]
    points: list[TrendPoint]


def _parse_kind_opt(s: Optional[str]) -> Optional[DenominatorKind]:
    if s is None:
        return None
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator kind: {s!r}") from e


@router.get("/trend", response_model=TrendOut)
async def get_trend(
    domain: str = Query("enterprise"),
    denominator: Optional[str] = Query(None),
    ref: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> TrendOut:
    """Return snapshots ordered oldest→newest (so charts render left-to-right)."""
    kind = _parse_kind_opt(denominator)
    async with tenant_session() as session:
        stmt = select(CoverageSnapshot).order_by(CoverageSnapshot.taken_at.asc())
        if kind is not None:
            stmt = stmt.where(CoverageSnapshot.denominator_kind == kind.value)
            if ref is not None:
                stmt = stmt.where(CoverageSnapshot.denominator_ref == ref)
            elif kind == DenominatorKind.FULL:
                # 'full' snapshots store NULL ref; matching kind alone is enough.
                pass
        stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).scalars().all()

    return TrendOut(
        domain=domain,
        denominator_kind=kind.value if kind else None,
        denominator_ref=ref,
        points=[
            TrendPoint(
                id=str(r.id),
                taken_at=r.taken_at.isoformat() if r.taken_at else "",
                breadth_pct=float((r.payload or {}).get("breadth_pct") or 0.0),
                depth_avg=float((r.payload or {}).get("depth_avg") or 0.0),
                breadth_grade=r.breadth_score,
                depth_grade=r.depth_score,
                posture_grade=r.posture_grade,
                covered_count=int((r.payload or {}).get("covered_count") or 0),
                denominator_size=int((r.payload or {}).get("denominator_size") or 0),
                deployed_count=int((r.payload or {}).get("deployed_count") or 0),
                denominator_kind=r.denominator_kind,
                denominator_ref=r.denominator_ref,
            )
            for r in rows
        ],
    )


__all__ = ["router"]
