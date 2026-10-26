"""ATT&CK catalog endpoints."""
from __future__ import annotations

from typing import Any, Optional

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import TenantPrincipal, current_super_admin, current_tenant_user
from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackCatalogVersion,
    AttackMitigation,
    AttackTechnique,
    AttackTechniqueMitigation,
    SuperAdmin,
)
from app.models.public import SigmaHQIngestRun
from app.services.attack_ingest import DOMAINS
from app.tasks.catalog import refresh_attack_catalog
from app.tasks.sigmahq import refresh_sigmahq_catalog
from app.worker import celery_app

router = APIRouter(prefix="/catalog/attack", tags=["catalog"])


class RefreshRequest(BaseModel):
    domains: Optional[list[str]] = None
    force: bool = False


class RefreshResponse(BaseModel):
    task_id: str
    domains: list[str]
    force: bool


class TaskStatusResponse(BaseModel):
    task_id: str
    state: str
    ready: bool
    successful: Optional[bool] = None
    result: Optional[Any] = None


class TechniqueOut(BaseModel):
    technique_id: str
    domain: str
    parent_technique_id: Optional[str]
    name: str
    description: Optional[str]
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    is_subtechnique: bool
    deprecated: bool
    revoked: bool
    url: Optional[str]


class MitigationOut(BaseModel):
    mitigation_id: str
    domain: str
    name: str
    description: Optional[str]
    deprecated: bool
    revoked: bool
    url: Optional[str]


class TechniqueWithMitigationsOut(TechniqueOut):
    mitigations: list[MitigationOut]


class PaginatedTechniques(BaseModel):
    items: list[TechniqueOut]
    total: int
    page: int
    page_size: int


class PaginatedMitigations(BaseModel):
    items: list[MitigationOut]
    total: int
    page: int
    page_size: int


class VersionOut(BaseModel):
    id: str
    domain: str
    version: str
    ingested_at: str
    is_current: bool
    summary: dict


def _serialize_technique(t: AttackTechnique) -> TechniqueOut:
    return TechniqueOut(
        technique_id=t.technique_id,
        domain=t.domain,
        parent_technique_id=t.parent_technique_id,
        name=t.name,
        description=t.description,
        tactics=list(t.tactics or []),
        platforms=list(t.platforms or []),
        data_sources=list(t.data_sources or []),
        is_subtechnique=t.is_subtechnique,
        deprecated=t.deprecated,
        revoked=t.revoked,
        url=t.url,
    )


def _serialize_mitigation(m: AttackMitigation) -> MitigationOut:
    return MitigationOut(
        mitigation_id=m.mitigation_id,
        domain=m.domain,
        name=m.name,
        description=m.description,
        deprecated=m.deprecated,
        revoked=m.revoked,
        url=m.url,
    )


async def _paginate(
    session: AsyncSession,
    base_stmt,
    count_stmt,
    *,
    page: int,
    page_size: int,
):
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (
        await session.execute(
            base_stmt.offset((page - 1) * page_size).limit(page_size)
        )
    ).scalars().all()
    return rows, int(total)


@router.post("/refresh", response_model=RefreshResponse, status_code=202)
async def refresh_catalog(
    payload: RefreshRequest,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> RefreshResponse:
    requested = payload.domains or list(DOMAINS)
    unknown = [d for d in requested if d not in DOMAINS]
    if unknown:
        raise HTTPException(400, f"unknown domains: {unknown}")
    async_result = refresh_attack_catalog.delay(domains=requested, force=payload.force)
    return RefreshResponse(
        task_id=async_result.id, domains=requested, force=payload.force
    )


@router.get("/refresh/{task_id}", response_model=TaskStatusResponse)
async def refresh_status(
    task_id: str,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> TaskStatusResponse:
    result = AsyncResult(task_id, app=celery_app)
    return TaskStatusResponse(
        task_id=task_id,
        state=result.state,
        ready=result.ready(),
        successful=result.successful() if result.ready() else None,
        result=result.result if result.ready() and result.successful() else None,
    )


@router.get("/techniques", response_model=PaginatedTechniques)
async def list_techniques(
    domain: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    is_subtechnique: Optional[bool] = Query(None),
    include_deprecated: bool = Query(False),
    include_revoked: bool = Query(False),
    q: Optional[str] = Query(None, description="ILIKE filter on name"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> PaginatedTechniques:
    clauses = []
    if domain:
        clauses.append(AttackTechnique.domain == domain)
    if tactic:
        clauses.append(AttackTechnique.tactics.contains([tactic]))
    if platform:
        clauses.append(AttackTechnique.platforms.contains([platform]))
    if is_subtechnique is not None:
        clauses.append(AttackTechnique.is_subtechnique.is_(is_subtechnique))
    if not include_deprecated:
        clauses.append(AttackTechnique.deprecated.is_(False))
    if not include_revoked:
        clauses.append(AttackTechnique.revoked.is_(False))
    if q:
        clauses.append(AttackTechnique.name.ilike(f"%{q}%"))

    where = and_(*clauses) if clauses else None
    base = select(AttackTechnique)
    count_stmt = select(func.count()).select_from(AttackTechnique)
    if where is not None:
        base = base.where(where)
        count_stmt = count_stmt.where(where)
    base = base.order_by(AttackTechnique.domain, AttackTechnique.technique_id)

    async with AsyncSessionLocal() as session:
        rows, total = await _paginate(
            session, base, count_stmt, page=page, page_size=page_size
        )
        return PaginatedTechniques(
            items=[_serialize_technique(t) for t in rows],
            total=total,
            page=page,
            page_size=page_size,
        )


@router.get(
    "/techniques/{technique_id}", response_model=TechniqueWithMitigationsOut
)
async def get_technique(
    technique_id: str,
    domain: Optional[str] = Query(None),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> TechniqueWithMitigationsOut:
    async with AsyncSessionLocal() as session:
        stmt = select(AttackTechnique).where(
            AttackTechnique.technique_id == technique_id
        )
        if domain:
            stmt = stmt.where(AttackTechnique.domain == domain)
        techniques = (await session.execute(stmt)).scalars().all()
        if not techniques:
            raise HTTPException(404, f"technique not found: {technique_id}")
        if len(techniques) > 1:
            raise HTTPException(
                400,
                f"technique {technique_id} exists in multiple domains; "
                "specify ?domain=",
            )
        t = techniques[0]

        mit_join = (
            select(AttackMitigation)
            .join(
                AttackTechniqueMitigation,
                (AttackTechniqueMitigation.mitigation_id == AttackMitigation.mitigation_id)
                & (AttackTechniqueMitigation.domain == AttackMitigation.domain),
            )
            .where(
                AttackTechniqueMitigation.technique_id == t.technique_id,
                AttackTechniqueMitigation.domain == t.domain,
            )
            .order_by(AttackMitigation.mitigation_id)
        )
        mitigations = (await session.execute(mit_join)).scalars().all()

        return TechniqueWithMitigationsOut(
            **_serialize_technique(t).model_dump(),
            mitigations=[_serialize_mitigation(m) for m in mitigations],
        )


class DataSourceVocabItem(BaseModel):
    raw: str
    data_source: str
    data_component: Optional[str]
    technique_count: int


class DataSourceVocabResponse(BaseModel):
    items: list[DataSourceVocabItem]
    total: int


@router.get("/data-sources", response_model=DataSourceVocabResponse)
async def list_data_source_vocab(
    domain: Optional[str] = Query(None),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> DataSourceVocabResponse:
    """Distinct ATT&CK data-source strings, derived from the per-technique
    `data_sources` JSONB array (e.g. "Process: Process Creation").

    This is the vocabulary the Collection Management Framework picker uses
    so analysts tag their data sources with canonical ATT&CK names — which
    is what lets visibility coverage (DeTT&CT) join collection back to the
    techniques each source illuminates. No separate STIX ingest needed.
    """
    # Unnest the JSONB array in a subquery (set-returning function in the
    # inner target list references the table column directly — allowed in
    # Postgres, no LATERAL needed). One inner row per (technique, source);
    # grouping + count gives techniques-per-source.
    clauses = [AttackTechnique.deprecated.is_(False), AttackTechnique.revoked.is_(False)]
    if domain:
        clauses.append(AttackTechnique.domain == domain)
    subq = (
        select(
            func.jsonb_array_elements_text(AttackTechnique.data_sources).label("value")
        )
        .where(and_(*clauses))
        .subquery()
    )
    stmt = (
        select(subq.c.value, func.count().label("n"))
        .group_by(subq.c.value)
        .order_by(subq.c.value)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()

    items: list[DataSourceVocabItem] = []
    for raw, n in rows:
        if not raw:
            continue
        source, _, component = raw.partition(": ")
        items.append(
            DataSourceVocabItem(
                raw=raw,
                data_source=source.strip(),
                data_component=component.strip() or None,
                technique_count=int(n or 0),
            )
        )
    return DataSourceVocabResponse(items=items, total=len(items))


@router.get("/mitigations", response_model=PaginatedMitigations)
async def list_mitigations(
    domain: Optional[str] = Query(None),
    include_deprecated: bool = Query(False),
    include_revoked: bool = Query(False),
    q: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> PaginatedMitigations:
    clauses = []
    if domain:
        clauses.append(AttackMitigation.domain == domain)
    if not include_deprecated:
        clauses.append(AttackMitigation.deprecated.is_(False))
    if not include_revoked:
        clauses.append(AttackMitigation.revoked.is_(False))
    if q:
        clauses.append(AttackMitigation.name.ilike(f"%{q}%"))

    where = and_(*clauses) if clauses else None
    base = select(AttackMitigation)
    count_stmt = select(func.count()).select_from(AttackMitigation)
    if where is not None:
        base = base.where(where)
        count_stmt = count_stmt.where(where)
    base = base.order_by(AttackMitigation.domain, AttackMitigation.mitigation_id)

    async with AsyncSessionLocal() as session:
        rows, total = await _paginate(
            session, base, count_stmt, page=page, page_size=page_size
        )
        return PaginatedMitigations(
            items=[_serialize_mitigation(m) for m in rows],
            total=total,
            page=page,
            page_size=page_size,
        )


@router.get("/versions", response_model=list[VersionOut])
async def list_versions(
    domain: Optional[str] = Query(None),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> list[VersionOut]:
    stmt = select(AttackCatalogVersion).order_by(
        AttackCatalogVersion.domain, AttackCatalogVersion.ingested_at.desc()
    )
    if domain:
        stmt = stmt.where(AttackCatalogVersion.domain == domain)
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).scalars().all()
        return [
            VersionOut(
                id=str(v.id),
                domain=v.domain,
                version=v.version,
                ingested_at=v.ingested_at.isoformat() if v.ingested_at else "",
                is_current=v.is_current,
                summary=dict(v.summary or {}),
            )
            for v in rows
        ]


# ---- SigmaHQ catalog -----------------------------------------------------
sigmahq_router = APIRouter(prefix="/catalog/sigmahq", tags=["catalog"])


class SigmaHQRefreshRequest(BaseModel):
    ref: Optional[str] = None
    force: bool = False


class SigmaHQRefreshResponse(BaseModel):
    task_id: str
    ref: Optional[str]
    force: bool


class SigmaHQIngestRunOut(BaseModel):
    id: str
    ref: str
    commit_sha: Optional[str]
    ingested_at: str
    is_current: bool
    summary: dict


@sigmahq_router.post("/refresh", response_model=SigmaHQRefreshResponse, status_code=202)
async def refresh_sigmahq(
    payload: SigmaHQRefreshRequest,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> SigmaHQRefreshResponse:
    async_result = refresh_sigmahq_catalog.delay(ref=payload.ref, force=payload.force)
    return SigmaHQRefreshResponse(
        task_id=async_result.id, ref=payload.ref, force=payload.force
    )


@sigmahq_router.get("/refresh/{task_id}", response_model=TaskStatusResponse)
async def sigmahq_refresh_status(
    task_id: str,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> TaskStatusResponse:
    result = AsyncResult(task_id, app=celery_app)
    return TaskStatusResponse(
        task_id=task_id,
        state=result.state,
        ready=result.ready(),
        successful=result.successful() if result.ready() else None,
        result=result.result if result.ready() and result.successful() else None,
    )


@sigmahq_router.get("/runs", response_model=list[SigmaHQIngestRunOut])
async def list_sigmahq_runs(
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> list[SigmaHQIngestRunOut]:
    stmt = select(SigmaHQIngestRun).order_by(SigmaHQIngestRun.ingested_at.desc())
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).scalars().all()
        return [
            SigmaHQIngestRunOut(
                id=str(r.id),
                ref=r.ref,
                commit_sha=r.commit_sha,
                ingested_at=r.ingested_at.isoformat() if r.ingested_at else "",
                is_current=r.is_current,
                summary=dict(r.summary or {}),
            )
            for r in rows
        ]


# ---- D3FEND catalog ------------------------------------------------------
d3fend_router = APIRouter(prefix="/catalog/d3fend", tags=["catalog"])


class D3FENDRefreshRequest(BaseModel):
    force: bool = False


class D3FENDRefreshResponse(BaseModel):
    task_id: str
    force: bool


class D3FENDTechniqueOut(BaseModel):
    d3fend_id: str
    name: str
    definition: Optional[str]
    parent_d3fend_id: Optional[str]
    kind: Optional[str]
    url: Optional[str]


class D3FENDRunOut(BaseModel):
    id: str
    ingested_at: str
    source_url: Optional[str]
    is_current: bool
    summary: dict


@d3fend_router.post("/refresh", response_model=D3FENDRefreshResponse, status_code=202)
async def refresh_d3fend_catalog(
    payload: D3FENDRefreshRequest,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> D3FENDRefreshResponse:
    from app.tasks.d3fend import refresh_d3fend
    async_result = refresh_d3fend.delay(force=payload.force)
    return D3FENDRefreshResponse(task_id=async_result.id, force=payload.force)


@d3fend_router.get("/refresh/{task_id}", response_model=TaskStatusResponse)
async def d3fend_refresh_status(
    task_id: str,
    _admin: SuperAdmin = Depends(current_super_admin),
) -> TaskStatusResponse:
    result = AsyncResult(task_id, app=celery_app)
    return TaskStatusResponse(
        task_id=task_id,
        state=result.state,
        ready=result.ready(),
        successful=result.successful() if result.ready() else None,
        result=result.result if result.ready() and result.successful() else None,
    )


@d3fend_router.get("/techniques", response_model=list[D3FENDTechniqueOut])
async def list_d3fend_techniques(
    q: Optional[str] = Query(None),
    _principal: TenantPrincipal = Depends(current_tenant_user),
) -> list[D3FENDTechniqueOut]:
    from app.models.public import D3FENDTechnique
    stmt = select(D3FENDTechnique).order_by(D3FENDTechnique.d3fend_id)
    if q:
        stmt = stmt.where(D3FENDTechnique.name.ilike(f"%{q}%"))
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).scalars().all()
        return [
            D3FENDTechniqueOut(
                d3fend_id=r.d3fend_id,
                name=r.name,
                definition=r.definition,
                parent_d3fend_id=r.parent_d3fend_id,
                kind=r.kind,
                url=r.url,
            )
            for r in rows
        ]


@d3fend_router.get("/runs", response_model=list[D3FENDRunOut])
async def list_d3fend_runs(
    _admin: SuperAdmin = Depends(current_super_admin),
) -> list[D3FENDRunOut]:
    from app.models.public import D3FENDIngestRun
    stmt = select(D3FENDIngestRun).order_by(D3FENDIngestRun.ingested_at.desc())
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).scalars().all()
        return [
            D3FENDRunOut(
                id=str(r.id),
                ingested_at=r.ingested_at.isoformat() if r.ingested_at else "",
                source_url=r.source_url,
                is_current=r.is_current,
                summary=dict(r.summary or {}),
            )
            for r in rows
        ]
