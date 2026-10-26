"""Verified-coverage API — evidence ladder for the active tenant."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.services.verified_coverage import (
    DetectionEvidence,
    TechniqueEvidence,
    VerifiedCoverage,
    compute_verified_coverage,
)

router = APIRouter(prefix="/verified", tags=["verified"])


class DeploymentMatchOut(BaseModel):
    name: str
    connector: str
    enabled: bool
    match_reason: str


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
    techniques: list[TechniqueEvidenceOut]


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
                name=match.name,
                connector=match.connector,
                enabled=match.enabled,
                match_reason=match.match_reason,
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
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
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
