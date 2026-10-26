"""Collection Management Framework — visibility + guidance endpoints.

Tenant-scoped, read-only analytics over the CMF collection inventory
(`asset_data_sources`). The management CRUD for assets and data sources lives
in `app/api/assets.py`; this module is the *guide* half — it tells the analyst
what their collection lets them see and what to collect next.

Gated on ASSET_READ + an active customer, same as the asset endpoints.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.services.cmf_visibility import (
    DenominatorKind,
    compute_overview,
    compute_recommendations,
    compute_visibility_matrix,
    compute_visibility_score,
)

router = APIRouter(prefix="/cmf", tags=["cmf"])


# ---- response shapes ------------------------------------------------------

class VisibilityCellOut(BaseModel):
    technique_id: str
    name: str
    parent_technique_id: Optional[str]
    is_subtechnique: bool
    tactics: list[str]
    state: str
    required: list[str]
    missing: list[str]
    quality_avg: Optional[float]


class VisibilityMatrixOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    technique_count: int
    tactics: list[str]
    by_tactic: dict[str, list[VisibilityCellOut]]


class VisibilityScoreOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    denominator_size: int
    assessable_count: int
    visible_count: int
    partial_count: int
    not_collected_count: int
    no_data_source_count: int
    visibility_pct: float
    visible_pct: float
    quality_avg: float
    visibility_grade: str
    quality_grade: str
    state_counts: dict[str, int]


class RecommendationOut(BaseModel):
    raw: str
    data_source: str
    data_component: Optional[str]
    touches: int
    unlocks: int
    sample_technique_ids: list[str]


class OverviewOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    asset_count: int
    assets_by_category: dict[str, int]
    data_source_count: int
    enabled_data_source_count: int
    distinct_attack_sources: int
    scored_source_count: int
    unscored_source_count: int
    score: VisibilityScoreOut
    top_recommendations: list[RecommendationOut]


# ---- helpers --------------------------------------------------------------

def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator kind: {s!r}") from e


def _score_out(score) -> VisibilityScoreOut:
    return VisibilityScoreOut(
        domain=score.domain,
        denominator_kind=score.denominator_kind.value,
        denominator_ref=score.denominator_ref,
        denominator_size=score.denominator_size,
        assessable_count=score.assessable_count,
        visible_count=score.visible_count,
        partial_count=score.partial_count,
        not_collected_count=score.not_collected_count,
        no_data_source_count=score.no_data_source_count,
        visibility_pct=score.visibility_pct,
        visible_pct=score.visible_pct,
        quality_avg=score.quality_avg,
        visibility_grade=score.visibility_grade,
        quality_grade=score.quality_grade,
        state_counts=score.state_counts,
    )


def _rec_out(r) -> RecommendationOut:
    return RecommendationOut(
        raw=r.raw,
        data_source=r.data_source,
        data_component=r.data_component,
        touches=r.touches,
        unlocks=r.unlocks,
        sample_technique_ids=r.sample_technique_ids,
    )


# ---- endpoints ------------------------------------------------------------

@router.get("/overview", response_model=OverviewOut)
async def get_overview(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> OverviewOut:
    kind = _parse_kind(denominator)
    ov = await compute_overview(domain, kind, ref)
    return OverviewOut(
        domain=ov.domain,
        denominator_kind=ov.denominator_kind.value,
        denominator_ref=ov.denominator_ref,
        asset_count=ov.asset_count,
        assets_by_category=ov.assets_by_category,
        data_source_count=ov.data_source_count,
        enabled_data_source_count=ov.enabled_data_source_count,
        distinct_attack_sources=ov.distinct_attack_sources,
        scored_source_count=ov.scored_source_count,
        unscored_source_count=ov.unscored_source_count,
        score=_score_out(ov.score),
        top_recommendations=[_rec_out(r) for r in ov.top_recommendations],
    )


@router.get("/visibility/matrix", response_model=VisibilityMatrixOut)
async def get_visibility_matrix(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> VisibilityMatrixOut:
    kind = _parse_kind(denominator)
    matrix = await compute_visibility_matrix(domain, kind, ref)
    return VisibilityMatrixOut(
        domain=matrix.domain,
        denominator_kind=matrix.denominator_kind.value,
        denominator_ref=matrix.denominator_ref,
        technique_count=matrix.technique_count,
        tactics=matrix.tactics,
        by_tactic={
            tac: [
                VisibilityCellOut(
                    technique_id=c.technique_id,
                    name=c.name,
                    parent_technique_id=c.parent_technique_id,
                    is_subtechnique=c.is_subtechnique,
                    tactics=c.tactics,
                    state=c.state.value,
                    required=c.required,
                    missing=c.missing,
                    quality_avg=c.quality_avg,
                )
                for c in cells
            ]
            for tac, cells in matrix.by_tactic.items()
        },
    )


@router.get("/visibility/score", response_model=VisibilityScoreOut)
async def get_visibility_score(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> VisibilityScoreOut:
    kind = _parse_kind(denominator)
    score = await compute_visibility_score(domain, kind, ref)
    return _score_out(score)


@router.get("/visibility/recommendations", response_model=list[RecommendationOut])
async def get_recommendations(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    limit: int = Query(25, ge=1, le=100),
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[RecommendationOut]:
    kind = _parse_kind(denominator)
    recs = await compute_recommendations(domain, kind, ref, limit=limit)
    return [_rec_out(r) for r in recs]
