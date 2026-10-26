"""Report + export endpoints — tenant-scoped, gated by REPORT_EXPORT."""
from __future__ import annotations

import json
import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import and_, select

from app.api.deps import (
    TenantPrincipal,
    require_active_customer,
    require_feature,
    require_perm,
)
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import Detection, DetectionSource, DetectionStatus
from app.services.apt_analysis import gap_ranking
from app.services.coverage import DenominatorKind, compute_matrix, compute_score
from app.services.d3fend_ingest import d3fend_for_techniques
from app.services.exports import (
    bundle_sigma_yaml,
    to_csv,
    to_navigator_layer,
    to_pdf,
    to_xlsx,
)
from app.services.sigma_convert import SigmaBackend, convert_many

router = APIRouter(prefix="/reports", tags=["reports"])


# ---- helpers --------------------------------------------------------------

def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator: {s!r}") from e


def _parse_backend(s: str) -> SigmaBackend:
    try:
        return SigmaBackend(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid backend: {s!r}") from e


def _filename_stem(
    customer_codename: str, kind: DenominatorKind, ref: Optional[str]
) -> str:
    parts = ["coverage", customer_codename, kind.value]
    if ref:
        parts.append(ref)
    return "-".join(parts)


def _matrix_technique_ids(matrix) -> list[str]:
    ids: set[str] = set()
    for cells in matrix.by_tactic.values():
        for c in cells:
            ids.add(c.technique_id)
    return sorted(ids)


# ---- coverage exports -----------------------------------------------------

@router.get("/coverage.csv")
async def coverage_csv(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> Response:
    kind = _parse_kind(denominator)
    matrix = await compute_matrix(domain, kind, ref)
    body = to_csv(matrix)
    stem = _filename_stem(principal.customer.codename, kind, ref)
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{stem}.csv"'},
    )


@router.get("/coverage.xlsx")
async def coverage_xlsx(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> Response:
    kind = _parse_kind(denominator)
    matrix = await compute_matrix(domain, kind, ref)
    score = await compute_score(domain, kind, ref)
    body = to_xlsx(matrix, score)
    stem = _filename_stem(principal.customer.codename, kind, ref)
    return Response(
        content=body,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={"Content-Disposition": f'attachment; filename="{stem}.xlsx"'},
    )


@router.get("/coverage.navigator.json")
async def coverage_navigator(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> Response:
    kind = _parse_kind(denominator)
    matrix = await compute_matrix(domain, kind, ref)
    score = await compute_score(domain, kind, ref)
    d3 = await d3fend_for_techniques(_matrix_technique_ids(matrix))
    layer = to_navigator_layer(
        matrix,
        score,
        customer_name=principal.customer.name,
        d3fend_by_technique=d3["by_technique"],
    )
    stem = _filename_stem(principal.customer.codename, kind, ref)
    return Response(
        content=json.dumps(layer, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{stem}.navigator.json"'
        },
    )


@router.get("/coverage.pdf")
async def coverage_pdf(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> Response:
    kind = _parse_kind(denominator)
    matrix = await compute_matrix(domain, kind, ref)
    score = await compute_score(domain, kind, ref)
    top_gaps = await gap_ranking(domain, kind, ref, limit=15)
    d3 = await d3fend_for_techniques(_matrix_technique_ids(matrix))
    body = to_pdf(
        customer_name=principal.customer.name,
        matrix=matrix,
        score=score,
        top_gaps=top_gaps,
        branding=dict(principal.customer.branding or {}),
        d3fend_defenses=d3["defenses"],
    )
    stem = _filename_stem(principal.customer.codename, kind, ref)
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
    )


# ---- sigma bundle / convert -----------------------------------------------

@router.get("/sigma-bundle.zip")
async def sigma_bundle(
    source: Optional[str] = Query(None, description="filter: global|customized|custom"),
    status: Optional[str] = Query(None, description="filter: detection_status"),
    principal: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> Response:
    clauses = []
    if source:
        try:
            clauses.append(Detection.source == DetectionSource(source))
        except ValueError as e:
            raise HTTPException(422, f"invalid source: {source!r}") from e
    if status:
        try:
            clauses.append(Detection.detection_status == DetectionStatus(status))
        except ValueError as e:
            raise HTTPException(422, f"invalid status: {status!r}") from e

    async with tenant_session() as session:
        stmt = select(Detection)
        if clauses:
            stmt = stmt.where(and_(*clauses))
        rows = (await session.execute(stmt)).scalars().all()

    body = bundle_sigma_yaml(rows)
    stem = f"sigma-{principal.customer.codename}"
    return Response(
        content=body,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{stem}.zip"'},
    )


class SigmaConvertIn(BaseModel):
    backend: str  # splunk|elastic|sentinel
    detection_ids: Optional[list[uuid.UUID]] = None  # None → convert ALL


class SigmaConvertResult(BaseModel):
    detection_id: str
    sigma_id: str
    title: str
    queries: list[str]
    error: Optional[str]


class SigmaConvertOut(BaseModel):
    backend: str
    results: list[SigmaConvertResult]
    total: int
    converted: int
    failed: int


@router.post("/sigma-convert", response_model=SigmaConvertOut)
async def sigma_convert(
    payload: SigmaConvertIn = Body(...),
    _: TenantPrincipal = Depends(require_perm(Permission.REPORT_EXPORT)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("bulk_export")),
) -> SigmaConvertOut:
    backend = _parse_backend(payload.backend)
    async with tenant_session() as session:
        stmt = select(Detection)
        if payload.detection_ids:
            stmt = stmt.where(Detection.id.in_(payload.detection_ids))
        rows = (await session.execute(stmt)).scalars().all()

    if not rows:
        return SigmaConvertOut(
            backend=backend.value, results=[], total=0, converted=0, failed=0
        )

    converted = convert_many(((str(r.id), r.raw_yaml or "") for r in rows), backend)
    # Attach metadata back per row
    meta = {str(r.id): r for r in rows}
    results: list[SigmaConvertResult] = []
    for c in converted:
        r = meta.get(c["detection_id"])
        results.append(
            SigmaConvertResult(
                detection_id=c["detection_id"],
                sigma_id=r.sigma_id if r else "",
                title=r.title if r else "",
                queries=c["queries"],
                error=c["error"],
            )
        )
    failed = sum(1 for c in results if c.error)
    return SigmaConvertOut(
        backend=backend.value,
        results=results,
        total=len(results),
        converted=len(results) - failed,
        failed=failed,
    )


__all__ = ["router"]
