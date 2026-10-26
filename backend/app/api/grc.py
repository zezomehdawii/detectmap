"""GRC crosswalk endpoints — frameworks, controls, mappings, evidence."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.deps import (
    TenantPrincipal,
    require_active_customer,
    require_feature,
    require_perm,
)
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.models.public import (
    GRCControl,
    GRCFramework,
    GRCMitigationMapping,
    GRCTechniqueMapping,
)
from app.services.grc import (
    control_coverage,
    control_d3fend,
    evidence_csv,
    evidence_json,
    evidence_payload,
    evidence_pdf,
    framework_summary,
    scorecard,
)

router = APIRouter(prefix="/grc", tags=["grc"])


# ---- response shapes ------------------------------------------------------

class FrameworkSummary(BaseModel):
    key: str
    label: str
    version: Optional[str]
    description: Optional[str]
    control_count: int
    technique_mapping_count: int
    mitigation_mapping_count: int


class ControlOut(BaseModel):
    id: str
    control_id: str
    parent_control_id: Optional[str]
    family: Optional[str]
    name: str
    description: Optional[str]
    sort_order: int
    technique_count: int
    mapped_techniques: list[str]
    seeded_count: int
    user_count: int
    state: str
    deployed_count: int
    in_progress_count: int
    idea_count: int
    gap_count: int
    d3fend_count: int


class FrameworkCoverageOut(BaseModel):
    framework_key: str
    framework_label: str
    framework_version: Optional[str]
    counts_by_state: dict[str, int]
    controls: list[ControlOut]


class MappingOut(BaseModel):
    id: str
    control_id: str
    domain: str
    target_kind: str  # "technique" or "mitigation"
    target_id: str    # technique_id or mitigation_id
    source: str
    rationale: Optional[str]
    author: Optional[str]


class MappingUpsertIn(BaseModel):
    control_id: uuid.UUID
    target_kind: str = Field(..., description='"technique" or "mitigation"')
    target_id: str = Field(..., description="ATT&CK technique_id or mitigation_id")
    domain: str = "enterprise"
    rationale: Optional[str] = None


# ---- endpoints ------------------------------------------------------------

@router.get("/frameworks", response_model=list[FrameworkSummary])
async def list_frameworks(
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[FrameworkSummary]:
    rows = await framework_summary()
    return [FrameworkSummary(**r) for r in rows]


@router.get("/frameworks/{key}/controls", response_model=FrameworkCoverageOut)
async def list_controls(
    key: str,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> FrameworkCoverageOut:
    cov = await control_coverage(key)
    if cov is None:
        raise HTTPException(404, f"framework {key!r} not found")
    return FrameworkCoverageOut(
        framework_key=cov.framework_key,
        framework_label=cov.framework_label,
        framework_version=cov.framework_version,
        counts_by_state=cov.counts_by_state,
        controls=[ControlOut(**c.__dict__) for c in cov.controls],
    )


class FrameworkTechniquesOut(BaseModel):
    framework_key: str
    technique_ids: list[str]


@router.get(
    "/frameworks/{key}/techniques", response_model=FrameworkTechniquesOut
)
async def framework_techniques(
    key: str,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> FrameworkTechniquesOut:
    """Distinct ATT&CK technique IDs that any control of this framework maps to.

    Used by the coverage matrix to scope the view to a single compliance
    framework — analysts can see ATT&CK coverage limited to controls of
    NCA ECC, NIST CSF, etc. No tenant context needed; the catalog is
    global reference data.
    """
    async with AsyncSessionLocal() as session:
        fw = (
            await session.execute(
                select(GRCFramework).where(GRCFramework.key == key)
            )
        ).scalar_one_or_none()
        if fw is None:
            raise HTTPException(404, f"framework {key!r} not found")
        rows = (
            await session.execute(
                select(GRCTechniqueMapping.technique_id)
                .join(GRCControl, GRCControl.id == GRCTechniqueMapping.control_id)
                .where(GRCControl.framework_id == fw.id)
                .distinct()
            )
        ).scalars().all()
    return FrameworkTechniquesOut(
        framework_key=fw.key, technique_ids=sorted(rows)
    )


@router.get("/controls/{control_uuid}/mappings", response_model=list[MappingOut])
async def control_mappings(
    control_uuid: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[MappingOut]:
    async with AsyncSessionLocal() as session:
        ctrl = (
            await session.execute(select(GRCControl).where(GRCControl.id == control_uuid))
        ).scalar_one_or_none()
        if ctrl is None:
            raise HTTPException(404, "control not found")
        tm = (
            await session.execute(
                select(GRCTechniqueMapping).where(
                    GRCTechniqueMapping.control_id == control_uuid
                )
            )
        ).scalars().all()
        mm = (
            await session.execute(
                select(GRCMitigationMapping).where(
                    GRCMitigationMapping.control_id == control_uuid
                )
            )
        ).scalars().all()
    out: list[MappingOut] = []
    for r in tm:
        out.append(
            MappingOut(
                id=str(r.id),
                control_id=str(r.control_id),
                domain=r.domain,
                target_kind="technique",
                target_id=r.technique_id,
                source=r.source,
                rationale=r.rationale,
                author=r.author,
            )
        )
    for r in mm:
        out.append(
            MappingOut(
                id=str(r.id),
                control_id=str(r.control_id),
                domain=r.domain,
                target_kind="mitigation",
                target_id=r.mitigation_id,
                source=r.source,
                rationale=r.rationale,
                author=r.author,
            )
        )
    return out


class ControlD3FENDOut(BaseModel):
    d3fend_id: str
    name: str
    relations: list[str]
    via_techniques: list[str]


@router.get("/controls/{control_uuid}/d3fend", response_model=list[ControlD3FENDOut])
async def control_d3fend_endpoint(
    control_uuid: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[ControlD3FENDOut]:
    """Defensive countermeasures (D3FEND) derived from a control's mapped
    ATT&CK techniques. Empty list if the control has no technique mappings
    or no D3FEND linkage; 404 if the control doesn't exist."""
    rows = await control_d3fend(str(control_uuid))
    if rows is None:
        raise HTTPException(404, "control not found")
    return [ControlD3FENDOut(**r.__dict__) for r in rows]


@router.post("/mappings", response_model=MappingOut, status_code=201)
async def upsert_mapping(
    payload: MappingUpsertIn = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    # GRC mappings live in `public.grc_*` (cross-tenant). The toggle still
    # gates customer-pinned users and MSSP staff working under X-Customer,
    # but MSSP admin edits without a tenant context aren't blocked.
    __: TenantPrincipal = Depends(
        require_feature("grc_editing", optional_customer=True)
    ),
) -> MappingOut:
    """Create or update a control↔technique/mitigation mapping owned by the user.

    Always stored with `source='user'` so the seeder won't overwrite it.
    """
    if payload.target_kind not in ("technique", "mitigation"):
        raise HTTPException(422, "target_kind must be 'technique' or 'mitigation'")

    async with AsyncSessionLocal() as session:
        ctrl = (
            await session.execute(
                select(GRCControl).where(GRCControl.id == payload.control_id)
            )
        ).scalar_one_or_none()
        if ctrl is None:
            raise HTTPException(404, "control not found")

        try:
            if payload.target_kind == "technique":
                stmt = (
                    pg_insert(GRCTechniqueMapping.__table__)
                    .values(
                        id=uuid.uuid4(),
                        control_id=payload.control_id,
                        domain=payload.domain,
                        technique_id=payload.target_id,
                        source="user",
                        rationale=payload.rationale,
                        author=principal.user.email,
                    )
                    .on_conflict_do_update(
                        constraint="uq_grc_control_technique",
                        set_={
                            "source": "user",
                            "rationale": payload.rationale,
                            "author": principal.user.email,
                        },
                    )
                    .returning(GRCTechniqueMapping.__table__)
                )
                row = (await session.execute(stmt)).one()
                await session.commit()
                return MappingOut(
                    id=str(row.id),
                    control_id=str(row.control_id),
                    domain=row.domain,
                    target_kind="technique",
                    target_id=row.technique_id,
                    source=row.source,
                    rationale=row.rationale,
                    author=row.author,
                )

            stmt = (
                pg_insert(GRCMitigationMapping.__table__)
                .values(
                    id=uuid.uuid4(),
                    control_id=payload.control_id,
                    domain=payload.domain,
                    mitigation_id=payload.target_id,
                    source="user",
                    rationale=payload.rationale,
                    author=principal.user.email,
                )
                .on_conflict_do_update(
                    constraint="uq_grc_control_mitigation",
                    set_={
                        "source": "user",
                        "rationale": payload.rationale,
                        "author": principal.user.email,
                    },
                )
                .returning(GRCMitigationMapping.__table__)
            )
            row = (await session.execute(stmt)).one()
            await session.commit()
            return MappingOut(
                id=str(row.id),
                control_id=str(row.control_id),
                domain=row.domain,
                target_kind="mitigation",
                target_id=row.mitigation_id,
                source=row.source,
                rationale=row.rationale,
                author=row.author,
            )
        except Exception:
            await session.rollback()
            raise


@router.delete("/mappings/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: uuid.UUID,
    target_kind: str = Query(..., description='"technique" or "mitigation"'),
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(
        require_feature("grc_editing", optional_customer=True)
    ),
) -> Response:
    if target_kind not in ("technique", "mitigation"):
        raise HTTPException(422, "target_kind must be 'technique' or 'mitigation'")
    model = (
        GRCTechniqueMapping if target_kind == "technique" else GRCMitigationMapping
    )
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(select(model).where(model.id == mapping_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "mapping not found")
        await session.delete(row)
        await session.commit()
    return Response(status_code=204)


class ScorecardRow(BaseModel):
    key: str
    label: str
    version: Optional[str]
    total_controls: int
    counts_by_state: dict[str, int]
    deployed_pct: float
    addressed_pct: float
    weighted_pct: float


@router.get("/scorecard", response_model=list[ScorecardRow])
async def get_scorecard(
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[ScorecardRow]:
    """Per-framework compliance posture for the active tenant."""
    return [ScorecardRow(**r) for r in await scorecard()]


@router.get("/evidence/{key}.pdf")
async def evidence_pdf_endpoint(
    key: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    payload = await evidence_payload(key)
    if payload is None:
        raise HTTPException(404, f"framework {key!r} not found")
    # Thread the tenant context into the PDF header so the artifact is
    # board-ready without the analyst having to re-add a cover sheet.
    payload["tenant"] = {
        "codename": principal.customer.codename,
        "name": principal.customer.name,
    }
    body = evidence_pdf(payload)
    stem = f"evidence-{principal.customer.codename}-{key}"
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
    )


@router.get("/evidence/{key}.json")
async def evidence_json_endpoint(
    key: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    payload = await evidence_payload(key)
    if payload is None:
        raise HTTPException(404, f"framework {key!r} not found")
    body = evidence_json(payload)
    stem = f"evidence-{principal.customer.codename}-{key}"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{stem}.json"'},
    )


@router.get("/evidence/{key}.csv")
async def evidence_csv_endpoint(
    key: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    payload = await evidence_payload(key)
    if payload is None:
        raise HTTPException(404, f"framework {key!r} not found")
    body = evidence_csv(payload)
    stem = f"evidence-{principal.customer.codename}-{key}"
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{stem}.csv"'},
    )


__all__ = ["router"]
