"""Verified-coverage API — evidence ladder for the active tenant."""
from __future__ import annotations

import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import (
    TenantPrincipal,
    require_active_customer,
    require_feature,
    require_perm,
)
from app.core.rbac import Permission, role_has
from app.db.tenant import tenant_session
from app.models.customer import (
    DeployedUseCase,
    Detection,
    DetectionDeploymentLink,
)
from app.services import customer_features
from app.services.roles import user_has_permission
from app.services.verified_coverage import (
    DetectionEvidence,
    TechniqueEvidence,
    VerifiedCoverage,
    compute_verified_coverage,
)

router = APIRouter(prefix="/verified", tags=["verified"])


class DeploymentMatchOut(BaseModel):
    id: str
    name: str
    connector: str
    enabled: bool
    match_reason: str
    decision: Optional[str] = None


class DetectionEvidenceOut(BaseModel):
    id: str
    title: str
    sigma_id: str
    status: str
    source: str
    score_depth: int
    technique_ids: list[str]
    level: int
    level_label: str
    blockers: list[str]
    next_action: str
    deployed_matches: list[DeploymentMatchOut]
    samples_total: int
    samples_passed: int
    samples_failed: int
    samples_pending: int
    tp_count: int
    fp_count: int
    telemetry_state: str
    missing_data_sources: list[str]


class TechniqueEvidenceOut(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    claimed_state: str
    visibility_state: str
    detection_count: int
    level: int
    level_label: str
    blockers: list[str]
    next_action: str
    detections: list[DetectionEvidenceOut]


class VerifiedCoverageOut(BaseModel):
    domain: str
    generated_at: str
    total_techniques: int
    not_applicable_count: int
    designed_count: int
    claimed_deployed_count: int
    verified_deployed_count: int
    effective_count: int
    proven_count: int
    level_counts: dict[str, int]
    detections_total: int
    detection_level_counts: dict[str, int]
    can_edit: bool
    techniques: list[TechniqueEvidenceOut]


class DeploymentDecisionIn(BaseModel):
    status: Literal["confirmed", "rejected"]
    note: Optional[str] = None


class DeploymentDecisionOut(BaseModel):
    detection_id: str
    deployed_use_case_id: str
    status: str


async def _can_edit(principal: TenantPrincipal) -> bool:
    if principal.customer is None:
        return False
    if not customer_features.is_enabled(
        principal.customer.features, "detection_editing"
    ):
        return False
    if principal.user.custom_role_id is None:
        return role_has(principal.user.role, Permission.DETECTION_WRITE)
    return await user_has_permission(
        principal.user, Permission.DETECTION_WRITE
    )


def _detection_out(item: DetectionEvidence) -> DetectionEvidenceOut:
    return DetectionEvidenceOut(
        id=item.id,
        title=item.title,
        sigma_id=item.sigma_id,
        status=item.status,
        source=item.source,
        score_depth=item.score_depth,
        technique_ids=item.technique_ids,
        level=item.level,
        level_label=item.level_label,
        blockers=item.blockers,
        next_action=item.next_action,
        deployed_matches=[
            DeploymentMatchOut(
                id=match.id,
                name=match.name,
                connector=match.connector,
                enabled=match.enabled,
                match_reason=match.match_reason,
                decision=match.decision,
            )
            for match in item.deployed_matches
        ],
        samples_total=item.samples_total,
        samples_passed=item.samples_passed,
        samples_failed=item.samples_failed,
        samples_pending=item.samples_pending,
        tp_count=item.tp_count,
        fp_count=item.fp_count,
        telemetry_state=item.telemetry_state,
        missing_data_sources=item.missing_data_sources,
    )


def _technique_out(
    item: TechniqueEvidence, *, include_details: bool = True
) -> TechniqueEvidenceOut:
    return TechniqueEvidenceOut(
        technique_id=item.technique_id,
        name=item.name,
        tactics=item.tactics,
        is_subtechnique=item.is_subtechnique,
        claimed_state=item.claimed_state,
        visibility_state=item.visibility_state,
        detection_count=item.detection_count,
        level=item.level,
        level_label=item.level_label,
        blockers=item.blockers,
        next_action=item.next_action,
        detections=(
            [_detection_out(detection) for detection in item.detections]
            if include_details
            else []
        ),
    )


@router.get("/coverage", response_model=VerifiedCoverageOut)
async def get_verified_coverage(
    domain: str = Query("enterprise"),
    include_details: bool = Query(
        True,
        description=(
            "Include each technique's full detection evidence. Set false for the "
            "summary table and fetch /verified/techniques/{id} on demand."
        ),
    ),
    principal: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> VerifiedCoverageOut:
    """Return the evidence ladder for every applicable technique in scope."""
    result: VerifiedCoverage = await compute_verified_coverage(domain)
    return VerifiedCoverageOut(
        domain=result.domain,
        generated_at=result.generated_at,
        total_techniques=result.total_techniques,
        not_applicable_count=result.not_applicable_count,
        designed_count=result.designed_count,
        claimed_deployed_count=result.claimed_deployed_count,
        verified_deployed_count=result.verified_deployed_count,
        effective_count=result.effective_count,
        proven_count=result.proven_count,
        level_counts=result.level_counts,
        detections_total=result.detections_total,
        detection_level_counts=result.detection_level_counts,
        can_edit=await _can_edit(principal),
        techniques=[
            _technique_out(item, include_details=include_details)
            for item in result.techniques
        ],
    )


@router.get(
    "/techniques/{technique_id:path}",
    response_model=TechniqueEvidenceOut,
)
async def get_verified_technique(
    technique_id: str,
    domain: str = Query("enterprise"),
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> TechniqueEvidenceOut:
    """Return one technique and the detection evidence behind its level.

    The summary endpoint deliberately omits detection detail to keep the
    table payload small; this endpoint is what the expansion panel loads.
    """
    result: VerifiedCoverage = await compute_verified_coverage(domain)
    for item in result.techniques:
        if item.technique_id == technique_id:
            return _technique_out(item, include_details=True)
    raise HTTPException(404, f"technique not found in scope: {technique_id}")


@router.put(
    "/matches/{detection_id}/{deployed_use_case_id}",
    response_model=DeploymentDecisionOut,
)
async def set_deployment_decision(
    detection_id: uuid.UUID,
    deployed_use_case_id: uuid.UUID,
    payload: DeploymentDecisionIn,
    principal: TenantPrincipal = Depends(
        require_perm(Permission.DETECTION_WRITE)
    ),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> DeploymentDecisionOut:
    """Confirm or reject a curated-detection ↔ deployed-rule pair.

    Confirmation is persisted as evidence; rejection suppresses a heuristic
    match. Omitting a row keeps the automatic heuristic in charge.
    """
    async with tenant_session() as session:
        detection = (
            await session.execute(
                select(Detection).where(Detection.id == detection_id)
            )
        ).scalar_one_or_none()
        if detection is None:
            raise HTTPException(404, "detection not found")

        deployment = (
            await session.execute(
                select(DeployedUseCase).where(
                    DeployedUseCase.id == deployed_use_case_id
                )
            )
        ).scalar_one_or_none()
        if deployment is None:
            raise HTTPException(404, "deployed use-case not found")

        link = (
            await session.execute(
                select(DetectionDeploymentLink).where(
                    DetectionDeploymentLink.detection_id == detection_id,
                    DetectionDeploymentLink.deployed_use_case_id
                    == deployed_use_case_id,
                )
            )
        ).scalar_one_or_none()

        if link is None:
            link = DetectionDeploymentLink(
                id=uuid.uuid4(),
                detection_id=detection_id,
                deployed_use_case_id=deployed_use_case_id,
                status=payload.status,
                note=payload.note,
                created_by_email=principal.user.email,
            )
            session.add(link)
        else:
            link.status = payload.status
            if payload.note is not None:
                link.note = payload.note
        link.updated_by_email = principal.user.email
        await session.flush()

    return DeploymentDecisionOut(
        detection_id=str(detection_id),
        deployed_use_case_id=str(deployed_use_case_id),
        status=payload.status,
    )


@router.delete(
    "/matches/{detection_id}/{deployed_use_case_id}",
    status_code=204,
    response_class=Response,
)
async def clear_deployment_decision(
    detection_id: uuid.UUID,
    deployed_use_case_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> Response:
    """Remove a confirmation/rejection and return to automatic matching."""
    async with tenant_session() as session:
        link = (
            await session.execute(
                select(DetectionDeploymentLink).where(
                    DetectionDeploymentLink.detection_id == detection_id,
                    DetectionDeploymentLink.deployed_use_case_id
                    == deployed_use_case_id,
                )
            )
        ).scalar_one_or_none()
        if link is not None:
            await session.delete(link)
    return Response(status_code=204)
