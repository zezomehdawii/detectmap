"""Coverage matrix + scoring + APT/sector reference endpoints — tenant-scoped."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import CoverageSnapshot
from app.models.public import (
    AttackGroup,
    AttackTechnique,
    SectorProfile,
)
from app.services.coverage import (
    DenominatorKind,
    compute_matrix,
    compute_score,
    delete_snapshot,
    list_snapshots,
    save_snapshot,
    update_snapshot_notes,
)
from app.services.denominator_custom import (
    CustomDenominatorSpec,
    compute_custom_denominator,
)
from app.services.technique_detail import (
    delete_note,
    get_technique_detail,
    upsert_note,
)

router = APIRouter(prefix="/coverage", tags=["coverage"])


# ---- response shapes ------------------------------------------------------

class TechniqueCellOut(BaseModel):
    technique_id: str
    name: str
    parent_technique_id: Optional[str]
    is_subtechnique: bool
    tactics: list[str]
    state: str
    detection_count: int
    max_depth: int
    deployed_count: int


class CoverageMatrixOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    technique_count: int
    tactics: list[str]
    by_tactic: dict[str, list[TechniqueCellOut]]


class CoverageScoreOut(BaseModel):
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    denominator_size: int
    covered_count: int
    deployed_count: int
    breadth_pct: float
    depth_avg: float
    breadth_grade: str
    depth_grade: str
    posture_grade: str
    state_counts: dict[str, int]


class SectorProfileOut(BaseModel):
    sector: str
    label: str
    description: Optional[str]
    technique_count: int


class GroupOut(BaseModel):
    group_id: str
    name: str
    aliases: list[str]
    description: Optional[str]


class SnapshotOut(BaseModel):
    id: str
    taken_at: str
    denominator_kind: str
    denominator_ref: Optional[str]
    breadth_score: str
    depth_score: str
    posture_grade: str
    payload: dict
    notes: Optional[str]


class SnapshotCreate(BaseModel):
    domain: str = "enterprise"
    denominator_kind: str = "full"
    denominator_ref: Optional[str] = None
    notes: Optional[str] = None


# ---- helpers --------------------------------------------------------------

def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator kind: {s!r}") from e


# ---- endpoints ------------------------------------------------------------

@router.get("/matrix", response_model=CoverageMatrixOut)
async def get_matrix(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CoverageMatrixOut:
    kind = _parse_kind(denominator)
    matrix = await compute_matrix(domain, kind, ref)
    return CoverageMatrixOut(
        domain=matrix.domain,
        denominator_kind=matrix.denominator_kind.value,
        denominator_ref=matrix.denominator_ref,
        technique_count=matrix.technique_count,
        tactics=matrix.tactics,
        by_tactic={
            tac: [
                TechniqueCellOut(
                    technique_id=c.technique_id,
                    name=c.name,
                    parent_technique_id=c.parent_technique_id,
                    is_subtechnique=c.is_subtechnique,
                    tactics=c.tactics,
                    state=c.state.value,
                    detection_count=c.detection_count,
                    max_depth=c.max_depth,
                    deployed_count=c.deployed_count,
                )
                for c in cells
            ]
            for tac, cells in matrix.by_tactic.items()
        },
    )


@router.get("/score", response_model=CoverageScoreOut)
async def get_score(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CoverageScoreOut:
    kind = _parse_kind(denominator)
    score = await compute_score(domain, kind, ref)
    return CoverageScoreOut(
        domain=score.domain,
        denominator_kind=score.denominator_kind.value,
        denominator_ref=score.denominator_ref,
        denominator_size=score.denominator_size,
        covered_count=score.covered_count,
        deployed_count=score.deployed_count,
        breadth_pct=score.breadth_pct,
        depth_avg=score.depth_avg,
        breadth_grade=score.breadth_grade,
        depth_grade=score.depth_grade,
        posture_grade=score.posture_grade,
        state_counts=score.state_counts,
    )


@router.get("/sectors", response_model=list[SectorProfileOut])
async def list_sectors(
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[SectorProfileOut]:
    """Available sector profiles — UI populates the denominator picker from here."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(select(SectorProfile).order_by(SectorProfile.label))
        ).scalars().all()
        return [
            SectorProfileOut(
                sector=r.sector,
                label=r.label,
                description=r.description,
                technique_count=len(r.technique_ids or []),
            )
            for r in rows
        ]


@router.get("/groups", response_model=list[GroupOut])
async def list_groups(
    domain: str = Query("enterprise"),
    q: Optional[str] = Query(None, description="ILIKE on name/alias"),
    limit: int = Query(50, ge=1, le=500),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[GroupOut]:
    async with AsyncSessionLocal() as session:
        stmt = select(AttackGroup).where(
            AttackGroup.domain == domain,
            AttackGroup.deprecated.is_(False),
            AttackGroup.revoked.is_(False),
        )
        if q:
            stmt = stmt.where(AttackGroup.name.ilike(f"%{q}%"))
        stmt = stmt.order_by(AttackGroup.name).limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        return [
            GroupOut(
                group_id=r.group_id,
                name=r.name,
                aliases=list(r.aliases or []),
                description=r.description,
            )
            for r in rows
        ]


@router.get("/snapshots", response_model=list[SnapshotOut])
async def list_snapshots_endpoint(
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[SnapshotOut]:
    rows = await list_snapshots()
    return [
        SnapshotOut(
            id=str(r.id),
            taken_at=r.taken_at.isoformat() if r.taken_at else "",
            denominator_kind=r.denominator_kind,
            denominator_ref=r.denominator_ref,
            breadth_score=r.breadth_score,
            depth_score=r.depth_score,
            posture_grade=r.posture_grade,
            payload=dict(r.payload or {}),
            notes=r.notes,
        )
        for r in rows
    ]


@router.post("/snapshots", response_model=SnapshotOut, status_code=201)
async def create_snapshot(
    payload: SnapshotCreate,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SnapshotOut:
    kind = _parse_kind(payload.denominator_kind)
    snap = await save_snapshot(payload.domain, kind, payload.denominator_ref, notes=payload.notes)
    return SnapshotOut(
        id=str(snap.id),
        taken_at=snap.taken_at.isoformat() if snap.taken_at else "",
        denominator_kind=snap.denominator_kind,
        denominator_ref=snap.denominator_ref,
        breadth_score=snap.breadth_score,
        depth_score=snap.depth_score,
        posture_grade=snap.posture_grade,
        payload=dict(snap.payload or {}),
        notes=snap.notes,
    )


class SnapshotNotePatch(BaseModel):
    notes: Optional[str] = None


@router.patch("/snapshots/{snapshot_id}", response_model=SnapshotOut)
async def patch_snapshot(
    snapshot_id: str,
    payload: SnapshotNotePatch,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SnapshotOut:
    try:
        sid = uuid.UUID(snapshot_id)
    except ValueError as e:
        raise HTTPException(422, "invalid snapshot id") from e
    snap = await update_snapshot_notes(sid, payload.notes)
    if snap is None:
        raise HTTPException(404, "snapshot not found")
    return SnapshotOut(
        id=str(snap.id),
        taken_at=snap.taken_at.isoformat() if snap.taken_at else "",
        denominator_kind=snap.denominator_kind,
        denominator_ref=snap.denominator_ref,
        breadth_score=snap.breadth_score,
        depth_score=snap.depth_score,
        posture_grade=snap.posture_grade,
        payload=dict(snap.payload or {}),
        notes=snap.notes,
    )


@router.delete("/snapshots/{snapshot_id}", status_code=204)
async def remove_snapshot(
    snapshot_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    try:
        sid = uuid.UUID(snapshot_id)
    except ValueError as e:
        raise HTTPException(422, "invalid snapshot id") from e
    removed = await delete_snapshot(sid)
    if not removed:
        raise HTTPException(404, "snapshot not found")
    return Response(status_code=204)


# ---- technique detail + notes + delta ------------------------------------

class MitigationOut(BaseModel):
    mitigation_id: str
    name: str
    description: Optional[str]
    url: Optional[str]


class APTUsageOut(BaseModel):
    group_id: str
    name: str
    via: list[str]


class DetectionRefOut(BaseModel):
    id: str
    sigma_id: str
    title: str
    detection_status: str
    source: str
    score_breadth: int
    score_depth: int
    level: Optional[str]
    upstream_global_id: Optional[str]
    version: int
    review_status: str


class TechniqueNoteOut(BaseModel):
    body: str
    author_email: Optional[str]
    updated_at: str


class D3FENDDefenseOut(BaseModel):
    d3fend_id: str
    name: str
    relation: Optional[str]
    url: Optional[str]


class TechniqueDetailResponse(BaseModel):
    technique_id: str
    domain: str
    name: str
    description: Optional[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    deprecated: bool
    revoked: bool
    url: Optional[str]
    mitigations: list[MitigationOut]
    apt_groups: list[APTUsageOut]
    detections: list[DetectionRefOut]
    d3fend: list[D3FENDDefenseOut]
    note: Optional[TechniqueNoteOut]


class NotePut(BaseModel):
    body: str = Field(..., min_length=1, max_length=8000)


@router.get(
    "/techniques/{technique_id}",
    response_model=TechniqueDetailResponse,
)
async def get_technique(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> TechniqueDetailResponse:
    detail = await get_technique_detail(technique_id, domain=domain)
    if detail is None:
        raise HTTPException(404, f"technique {technique_id!r} not found")
    return TechniqueDetailResponse(
        technique_id=detail.technique_id,
        domain=detail.domain,
        name=detail.name,
        description=detail.description,
        is_subtechnique=detail.is_subtechnique,
        parent_technique_id=detail.parent_technique_id,
        tactics=detail.tactics,
        platforms=detail.platforms,
        data_sources=detail.data_sources,
        deprecated=detail.deprecated,
        revoked=detail.revoked,
        url=detail.url,
        mitigations=[MitigationOut(**m.__dict__) for m in detail.mitigations],
        apt_groups=[APTUsageOut(**g.__dict__) for g in detail.apt_groups],
        detections=[DetectionRefOut(**d.__dict__) for d in detail.detections],
        d3fend=[D3FENDDefenseOut(**d.__dict__) for d in detail.d3fend],
        note=TechniqueNoteOut(**detail.note.__dict__) if detail.note else None,
    )


@router.put(
    "/techniques/{technique_id}/note",
    response_model=TechniqueNoteOut,
)
async def put_technique_note(
    technique_id: str,
    payload: NotePut,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> TechniqueNoteOut:
    note = await upsert_note(
        technique_id,
        payload.body.strip(),
        author_email=principal.user.email,
    )
    return TechniqueNoteOut(**note.__dict__)


@router.delete("/techniques/{technique_id}/note")
async def delete_technique_note(
    technique_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    removed = await delete_note(technique_id)
    if not removed:
        raise HTTPException(404, "note not found")
    return Response(status_code=204)


class MatrixDeltaCell(BaseModel):
    technique_id: str
    previous_state: Optional[str]
    previous_depth: Optional[int]
    current_state: str
    current_depth: int
    change: str  # "improved" | "regressed" | "unchanged" | "new" | "removed"


class MatrixDeltaResponse(BaseModel):
    snapshot_id: str
    snapshot_taken_at: str
    domain: str
    denominator_kind: str
    denominator_ref: Optional[str]
    summary: dict[str, int]
    cells: list[MatrixDeltaCell]


# Ordinal ordering for state — used to compute "improved" vs "regressed".
# Higher = better posture for the cell.
_STATE_RANK = {
    "gap": 0,
    "out_of_scope": 1,
    "not_applicable": 2,
    "idea": 3,
    "in_progress": 4,
    "deployed": 5,
}


def _change(prev: Optional[str], cur: str) -> str:
    if prev is None:
        return "new"
    if prev == cur:
        return "unchanged"
    return (
        "improved"
        if _STATE_RANK.get(cur, 0) > _STATE_RANK.get(prev, 0)
        else "regressed"
    )


@router.get(
    "/matrix-delta",
    response_model=MatrixDeltaResponse,
)
async def get_matrix_delta(
    snapshot_id: str = Query(..., description="snapshot to compare against"),
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> MatrixDeltaResponse:
    try:
        snap_uuid = uuid.UUID(snapshot_id)
    except ValueError as e:
        raise HTTPException(422, "invalid snapshot id") from e

    async with tenant_session() as session:
        snap = (
            await session.execute(
                select(CoverageSnapshot).where(CoverageSnapshot.id == snap_uuid)
            )
        ).scalar_one_or_none()
        if snap is None:
            raise HTTPException(404, "snapshot not found")
        prev_payload = dict(snap.payload or {})
        prev_states: dict[str, str] = dict(
            prev_payload.get("technique_states") or {}
        )
        prev_depth: dict[str, int] = dict(
            prev_payload.get("technique_depth") or {}
        )
        if not prev_states:
            raise HTTPException(
                422,
                "snapshot predates per-technique state capture and cannot be diffed",
            )
        snap_taken = snap.taken_at.isoformat() if snap.taken_at else ""

    kind = _parse_kind(denominator)
    cur_matrix = await compute_matrix(domain, kind, ref)
    cur_states: dict[str, str] = {}
    cur_depth: dict[str, int] = {}
    for cells in cur_matrix.by_tactic.values():
        for c in cells:
            cur_states[c.technique_id] = c.state.value
            cur_depth[c.technique_id] = c.max_depth

    cells: list[MatrixDeltaCell] = []
    summary = {"improved": 0, "regressed": 0, "unchanged": 0, "new": 0, "removed": 0}

    for tid, cur in cur_states.items():
        prev = prev_states.get(tid)
        change = _change(prev, cur)
        summary[change] += 1
        cells.append(
            MatrixDeltaCell(
                technique_id=tid,
                previous_state=prev,
                previous_depth=prev_depth.get(tid),
                current_state=cur,
                current_depth=cur_depth.get(tid, 0),
                change=change,
            )
        )
    for tid in prev_states.keys() - cur_states.keys():
        summary["removed"] += 1
        cells.append(
            MatrixDeltaCell(
                technique_id=tid,
                previous_state=prev_states[tid],
                previous_depth=prev_depth.get(tid),
                current_state="out_of_scope",
                current_depth=0,
                change="removed",
            )
        )

    return MatrixDeltaResponse(
        snapshot_id=str(snap.id),
        snapshot_taken_at=snap_taken,
        domain=domain,
        denominator_kind=kind.value,
        denominator_ref=ref,
        summary=summary,
        cells=cells,
    )


class CustomDenominatorIn(BaseModel):
    sectors: list[str] = []
    apt_groups: list[str] = []
    platforms: list[str] = []
    operator: str = "union"  # union | intersection


class CustomDenominatorOut(BaseModel):
    technique_count: int
    technique_ids: list[str]
    sectors: list[str]
    apt_groups: list[str]
    platforms: list[str]
    operator: str


@router.post("/denominator/custom", response_model=CustomDenominatorOut)
async def compute_custom(
    payload: CustomDenominatorIn,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CustomDenominatorOut:
    if payload.operator not in {"union", "intersection"}:
        raise HTTPException(422, "operator must be 'union' or 'intersection'")
    spec = CustomDenominatorSpec(
        sectors=payload.sectors,
        apt_groups=payload.apt_groups,
        platforms=payload.platforms,
        operator=payload.operator,
    )
    tids = await compute_custom_denominator(spec)
    return CustomDenominatorOut(
        technique_count=len(tids),
        technique_ids=sorted(tids),
        sectors=payload.sectors,
        apt_groups=payload.apt_groups,
        platforms=payload.platforms,
        operator=payload.operator,
    )


@router.post("/matrix-custom", response_model=CoverageMatrixOut)
async def matrix_custom(
    payload: CustomDenominatorIn,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CoverageMatrixOut:
    """Coverage matrix scored against a custom-composed denominator."""
    spec = CustomDenominatorSpec(
        sectors=payload.sectors,
        apt_groups=payload.apt_groups,
        platforms=payload.platforms,
        operator=payload.operator,
    )
    tids = await compute_custom_denominator(spec)
    if not tids:
        raise HTTPException(422, "custom denominator is empty")
    matrix = await compute_matrix(
        domain,
        DenominatorKind.FULL,  # placeholder; we override below
        None,
        precomputed_denominator=tids,
    )
    # label the denominator distinctly so the UI knows it's custom
    matrix.denominator_kind = DenominatorKind.FULL
    return CoverageMatrixOut(
        domain=matrix.domain,
        denominator_kind="custom",
        denominator_ref=";".join(
            filter(
                None,
                [
                    f"sectors={','.join(payload.sectors)}" if payload.sectors else "",
                    f"apt={','.join(payload.apt_groups)}" if payload.apt_groups else "",
                    f"plat={','.join(payload.platforms)}" if payload.platforms else "",
                    f"op={payload.operator}",
                ],
            )
        ),
        technique_count=matrix.technique_count,
        tactics=matrix.tactics,
        by_tactic={
            tac: [
                TechniqueCellOut(
                    technique_id=c.technique_id,
                    name=c.name,
                    parent_technique_id=c.parent_technique_id,
                    is_subtechnique=c.is_subtechnique,
                    tactics=c.tactics,
                    state=c.state.value,
                    detection_count=c.detection_count,
                    max_depth=c.max_depth,
                    deployed_count=c.deployed_count,
                )
                for c in cells
            ]
            for tac, cells in matrix.by_tactic.items()
        },
    )


@router.post("/score-custom", response_model=CoverageScoreOut)
async def score_custom(
    payload: CustomDenominatorIn,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CoverageScoreOut:
    spec = CustomDenominatorSpec(
        sectors=payload.sectors,
        apt_groups=payload.apt_groups,
        platforms=payload.platforms,
        operator=payload.operator,
    )
    tids = await compute_custom_denominator(spec)
    if not tids:
        raise HTTPException(422, "custom denominator is empty")
    score = await compute_score(
        domain,
        DenominatorKind.FULL,
        None,
        precomputed_denominator=tids,
    )
    return CoverageScoreOut(
        domain=score.domain,
        denominator_kind="custom",
        denominator_ref=None,
        denominator_size=score.denominator_size,
        covered_count=score.covered_count,
        deployed_count=score.deployed_count,
        breadth_pct=score.breadth_pct,
        depth_avg=score.depth_avg,
        breadth_grade=score.breadth_grade,
        depth_grade=score.depth_grade,
        posture_grade=score.posture_grade,
        state_counts=score.state_counts,
    )


# ---- deployed SIEM use-case overlay --------------------------------------

class SiemUseCaseRef(BaseModel):
    id: str
    name: str
    connector_label: str
    connector_kind: str
    severity: Optional[str]
    enabled: bool


class SiemOverlayOut(BaseModel):
    technique_ids: list[str]
    use_case_count: int
    by_technique: dict[str, list[SiemUseCaseRef]]


@router.get("/siem-overlay", response_model=SiemOverlayOut)
async def get_siem_overlay(
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SiemOverlayOut:
    """Which techniques are covered by rules deployed in the customer's SIEM
    (imported via connectors). Read-only overlay — does not affect scoring."""
    from app.services import deployed_usecases as uc

    async with tenant_session() as session:
        by_tech = await uc.siem_overlay(session)
    distinct: set[str] = set()
    for lst in by_tech.values():
        for e in lst:
            distinct.add(e["id"])
    return SiemOverlayOut(
        technique_ids=sorted(by_tech.keys()),
        use_case_count=len(distinct),
        by_technique={
            tid: [SiemUseCaseRef(**e) for e in lst] for tid, lst in by_tech.items()
        },
    )


__all__ = ["router"]
