"""Customer profile endpoints: assets, contacts, and asset↔detection linkage.

All routes are tenant-scoped — the active customer is resolved from the
X-Customer header (MSSP staff) or the JWT customer pin (customer_user)
via the standard `current_tenant_user` dependency. Permissions are
ASSET_READ for GETs, ASSET_WRITE for mutations.

Coverage rollup per asset is computed at read time (no denormalised
column to keep stale): join asset_detections → detections →
detection_techniques and tally.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import (
    Asset,
    AssetDataSource,
    AssetDetection,
    Connector,
    CustomerContact,
    Detection,
    DetectionTechnique,
)

router = APIRouter(prefix="", tags=["customer-profile"])


# ---- enums (string-validated; not DB enums for forward compat) -----------

_ASSET_KINDS = {
    "server", "workstation", "network_device", "cloud_resource",
    "database", "application", "container", "mobile_device",
    "iot_ot", "other",
}
_ENVIRONMENTS = {"production", "staging", "development", "dr"}
_CRITICALITIES = {"low", "medium", "high", "critical"}
_DATA_CLASSIFICATIONS = {None, "", "public", "internal", "confidential", "restricted"}
_STATUSES = {"active", "decommissioned", "planned", "maintenance"}
_COMPLIANCE_FRAMEWORKS = {
    "pci", "hipaa", "sox", "gdpr",
    "nca_ecc", "nca_cscc", "nca_ccc_csp", "nca_ccc_cst", "nca_otcc",
    "iso_27001", "nist_csf", "nist_800_53",
}
# CMF functional grouping. None/"" = uncategorised. Kept in lockstep with
# CMF_CATEGORIES in frontend/lib/api.ts.
_CMF_CATEGORIES = {
    None, "", "endpoint", "network", "identity", "cloud", "application",
    "email", "saas", "ot", "physical", "other",
}


def _validate_enum(value: str, allowed: set, field: str) -> str:
    if value not in allowed:
        raise HTTPException(
            422,
            f"{field} must be one of {sorted(v for v in allowed if v)}",
        )
    return value


def _validate_compliance(scope: list[str] | None) -> list[str]:
    if not scope:
        return []
    bad = [s for s in scope if s not in _COMPLIANCE_FRAMEWORKS]
    if bad:
        raise HTTPException(
            422,
            f"compliance_scope: unknown framework(s) {bad}. "
            f"Allowed: {sorted(_COMPLIANCE_FRAMEWORKS)}",
        )
    # dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for s in scope:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


_QUALITY_FIELDS = (
    "device_completeness_q",
    "data_field_completeness_q",
    "timeliness_q",
    "consistency_q",
    "retention_q",
)


def _validate_quality(value: Optional[int], field: str) -> Optional[int]:
    """DeTT&CT data-quality scores are 0–5. NULL means unscored."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 5):
        raise HTTPException(422, f"{field} must be an integer 0–5 (or null)")
    return value


# ---- payloads -----------------------------------------------------------


class AssetCoverageSummary(BaseModel):
    """Read-time rollup over the asset's linked detections."""
    linked_detections: int = 0
    deployed_detections: int = 0
    techniques_covered: int = 0


class AssetOut(BaseModel):
    id: str
    name: str
    kind: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os: Optional[str]
    environment: str
    location: Optional[str]
    owner: Optional[str]
    business_function: Optional[str]
    cmf_category: Optional[str]
    criticality: str
    data_classification: Optional[str]
    compliance_scope: list[str]
    status: str
    tags: list[str]
    notes: Optional[str]
    external_id: Optional[str]
    created_by_email: Optional[str]
    updated_by_email: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    coverage: AssetCoverageSummary
    data_source_count: int = 0


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    kind: str = Field(...)
    hostname: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    os: Optional[str] = Field(default=None, max_length=120)
    environment: str = "production"
    location: Optional[str] = Field(default=None, max_length=200)
    owner: Optional[str] = Field(default=None, max_length=200)
    business_function: Optional[str] = Field(default=None, max_length=200)
    cmf_category: Optional[str] = Field(default=None, max_length=40)
    criticality: str = "medium"
    data_classification: Optional[str] = None
    compliance_scope: list[str] = Field(default_factory=list)
    status: str = "active"
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
    external_id: Optional[str] = Field(default=None, max_length=120)


class AssetPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    kind: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    business_function: Optional[str] = None
    cmf_category: Optional[str] = None
    criticality: Optional[str] = None
    data_classification: Optional[str] = None
    compliance_scope: Optional[list[str]] = None
    status: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    external_id: Optional[str] = None


# ---- helpers ------------------------------------------------------------


async def _coverage_for_assets(
    session, asset_ids: list[uuid.UUID]
) -> dict[uuid.UUID, AssetCoverageSummary]:
    """Compute the coverage summary for a batch of assets in one round trip.

    Cheaper than per-asset COUNT(*) loops. Returns empty summaries for
    assets with no detection links so the caller can rely on the dict
    always having a key per requested id.
    """
    out: dict[uuid.UUID, AssetCoverageSummary] = {
        aid: AssetCoverageSummary() for aid in asset_ids
    }
    if not asset_ids:
        return out

    # Linked + deployed detection counts in one grouped query.
    rows = (
        await session.execute(
            select(
                AssetDetection.asset_id,
                func.count(AssetDetection.id).label("linked"),
                func.count(
                    Detection.id
                ).filter(Detection.detection_status == "deployed").label("deployed"),
            )
            .join(Detection, Detection.id == AssetDetection.detection_id)
            .where(AssetDetection.asset_id.in_(asset_ids))
            .group_by(AssetDetection.asset_id)
        )
    ).all()
    for asset_id, linked, deployed in rows:
        out[asset_id].linked_detections = int(linked or 0)
        out[asset_id].deployed_detections = int(deployed or 0)

    # Distinct techniques covered per asset (any linked detection).
    tech_rows = (
        await session.execute(
            select(
                AssetDetection.asset_id,
                func.count(func.distinct(DetectionTechnique.technique_id)),
            )
            .join(Detection, Detection.id == AssetDetection.detection_id)
            .join(
                DetectionTechnique,
                DetectionTechnique.detection_id == Detection.id,
            )
            .where(AssetDetection.asset_id.in_(asset_ids))
            .group_by(AssetDetection.asset_id)
        )
    ).all()
    for asset_id, n in tech_rows:
        out[asset_id].techniques_covered = int(n or 0)

    return out


async def _data_source_counts(
    session, asset_ids: list[uuid.UUID]
) -> dict[uuid.UUID, int]:
    """Collection-source count per asset, one grouped query."""
    out: dict[uuid.UUID, int] = {aid: 0 for aid in asset_ids}
    if not asset_ids:
        return out
    rows = (
        await session.execute(
            select(
                AssetDataSource.asset_id,
                func.count(AssetDataSource.id),
            )
            .where(AssetDataSource.asset_id.in_(asset_ids))
            .group_by(AssetDataSource.asset_id)
        )
    ).all()
    for asset_id, n in rows:
        out[asset_id] = int(n or 0)
    return out


def _serialise_asset(
    a: Asset, coverage: AssetCoverageSummary, data_source_count: int = 0
) -> AssetOut:
    return AssetOut(
        id=str(a.id),
        name=a.name,
        kind=a.kind,
        hostname=a.hostname,
        ip_address=a.ip_address,
        os=a.os,
        environment=a.environment,
        location=a.location,
        owner=a.owner,
        business_function=a.business_function,
        cmf_category=a.cmf_category,
        criticality=a.criticality,
        data_classification=a.data_classification,
        compliance_scope=list(a.compliance_scope or []),
        status=a.status,
        tags=list(a.tags or []),
        notes=a.notes,
        external_id=a.external_id,
        created_by_email=a.created_by_email,
        updated_by_email=a.updated_by_email,
        created_at=a.created_at,
        updated_at=a.updated_at,
        coverage=coverage,
        data_source_count=data_source_count,
    )


# ---- /assets -----------------------------------------------------------


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    kind: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="ILIKE filter on name + hostname"),
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[AssetOut]:
    clauses = []
    if kind:
        clauses.append(Asset.kind == kind)
    if criticality:
        clauses.append(Asset.criticality == criticality)
    if environment:
        clauses.append(Asset.environment == environment)
    if status:
        clauses.append(Asset.status == status)
    if q:
        pattern = f"%{q.strip()}%"
        clauses.append(
            (Asset.name.ilike(pattern)) | (Asset.hostname.ilike(pattern))
        )
    async with tenant_session() as session:
        stmt = select(Asset)
        if clauses:
            stmt = stmt.where(and_(*clauses))
        stmt = stmt.order_by(Asset.criticality.desc(), Asset.name.asc())
        rows = (await session.execute(stmt)).scalars().all()
        ids = [r.id for r in rows]
        coverage = await _coverage_for_assets(session, ids)
        ds_counts = await _data_source_counts(session, ids)
    return [
        _serialise_asset(
            r, coverage.get(r.id, AssetCoverageSummary()), ds_counts.get(r.id, 0)
        )
        for r in rows
    ]


@router.post("/assets", response_model=AssetOut, status_code=201)
async def create_asset(
    payload: AssetCreate = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetOut:
    _validate_enum(payload.kind, _ASSET_KINDS, "kind")
    _validate_enum(payload.environment, _ENVIRONMENTS, "environment")
    _validate_enum(payload.criticality, _CRITICALITIES, "criticality")
    _validate_enum(payload.status, _STATUSES, "status")
    if payload.data_classification not in _DATA_CLASSIFICATIONS:
        raise HTTPException(
            422,
            f"data_classification must be one of "
            f"{sorted(v for v in _DATA_CLASSIFICATIONS if v)}",
        )
    _validate_enum(payload.cmf_category, _CMF_CATEGORIES, "cmf_category")
    compliance = _validate_compliance(payload.compliance_scope)

    async with tenant_session() as session:
        asset = Asset(
            id=uuid.uuid4(),
            name=payload.name.strip(),
            kind=payload.kind,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            os=payload.os,
            environment=payload.environment,
            location=payload.location,
            owner=payload.owner,
            business_function=payload.business_function,
            cmf_category=payload.cmf_category or None,
            criticality=payload.criticality,
            data_classification=payload.data_classification or None,
            compliance_scope=compliance,
            status=payload.status,
            tags=list(payload.tags or []),
            notes=payload.notes,
            external_id=payload.external_id,
            created_by_email=principal.user.email,
            updated_by_email=principal.user.email,
        )
        session.add(asset)
        await session.flush()
        coverage = await _coverage_for_assets(session, [asset.id])
        return _serialise_asset(asset, coverage[asset.id], 0)


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetOut:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Asset).where(Asset.id == asset_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "asset not found")
        coverage = await _coverage_for_assets(session, [row.id])
        ds_counts = await _data_source_counts(session, [row.id])
        return _serialise_asset(row, coverage[row.id], ds_counts[row.id])


@router.patch("/assets/{asset_id}", response_model=AssetOut)
async def patch_asset(
    asset_id: uuid.UUID,
    payload: AssetPatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetOut:
    if payload.kind is not None:
        _validate_enum(payload.kind, _ASSET_KINDS, "kind")
    if payload.environment is not None:
        _validate_enum(payload.environment, _ENVIRONMENTS, "environment")
    if payload.criticality is not None:
        _validate_enum(payload.criticality, _CRITICALITIES, "criticality")
    if payload.status is not None:
        _validate_enum(payload.status, _STATUSES, "status")
    if payload.data_classification is not None and payload.data_classification not in _DATA_CLASSIFICATIONS:
        raise HTTPException(
            422,
            f"data_classification must be one of "
            f"{sorted(v for v in _DATA_CLASSIFICATIONS if v)}",
        )
    if payload.cmf_category is not None:
        _validate_enum(payload.cmf_category, _CMF_CATEGORIES, "cmf_category")
    compliance: Optional[list[str]] = None
    if payload.compliance_scope is not None:
        compliance = _validate_compliance(payload.compliance_scope)

    async with tenant_session() as session:
        row = (
            await session.execute(select(Asset).where(Asset.id == asset_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "asset not found")
        for field in (
            "name", "kind", "hostname", "ip_address", "os", "environment",
            "location", "owner", "business_function", "criticality",
            "status", "tags", "notes", "external_id",
        ):
            v = getattr(payload, field)
            if v is not None:
                if field == "tags":
                    setattr(row, field, list(v))
                elif field == "name":
                    setattr(row, field, v.strip())
                else:
                    setattr(row, field, v)
        if payload.data_classification is not None:
            row.data_classification = payload.data_classification or None
        if payload.cmf_category is not None:
            row.cmf_category = payload.cmf_category or None
        if compliance is not None:
            row.compliance_scope = compliance
        row.updated_by_email = principal.user.email
        await session.flush()
        # `updated_at` has a server-side `onupdate=now()` — refresh so the
        # serialiser sees the new value without triggering a lazy load
        # after the session closes.
        await session.refresh(row)
        coverage = await _coverage_for_assets(session, [row.id])
        ds_counts = await _data_source_counts(session, [row.id])
        return _serialise_asset(row, coverage[row.id], ds_counts[row.id])


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Asset).where(Asset.id == asset_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "asset not found")
        await session.delete(row)
    return Response(status_code=204)


# ---- /assets/{id}/detections ---------------------------------------------


class AssetDetectionRef(BaseModel):
    detection_id: str
    sigma_id: str
    title: str
    detection_status: str
    source: str
    techniques: list[str]


class AssetDetectionLinkIn(BaseModel):
    """Replace the linked-detection set wholesale.

    Idempotent: send the full desired list. Anything not in the list is
    unlinked; anything new is linked. UI passes the current selection
    from a transfer-list — simpler than juggling add/remove deltas.
    """
    detection_ids: list[uuid.UUID]


class AssetDetectionLinkResult(BaseModel):
    linked: int
    unlinked: int
    total: int


@router.get(
    "/assets/{asset_id}/detections", response_model=list[AssetDetectionRef]
)
async def list_asset_detections(
    asset_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[AssetDetectionRef]:
    async with tenant_session() as session:
        # Confirm the asset exists before returning an empty list — a
        # 404 here is much friendlier than silent success.
        asset_exists = (
            await session.execute(
                select(Asset.id).where(Asset.id == asset_id)
            )
        ).scalar_one_or_none()
        if asset_exists is None:
            raise HTTPException(404, "asset not found")
        rows = (
            await session.execute(
                select(Detection)
                .join(
                    AssetDetection,
                    AssetDetection.detection_id == Detection.id,
                )
                .where(AssetDetection.asset_id == asset_id)
                .order_by(Detection.title.asc())
            )
        ).scalars().all()
        if not rows:
            return []
        det_ids = [r.id for r in rows]
        tech_rows = (
            await session.execute(
                select(DetectionTechnique).where(
                    DetectionTechnique.detection_id.in_(det_ids)
                )
            )
        ).scalars().all()
        techs: dict[uuid.UUID, list[str]] = {}
        for t in tech_rows:
            techs.setdefault(t.detection_id, []).append(t.technique_id)
    return [
        AssetDetectionRef(
            detection_id=str(d.id),
            sigma_id=d.sigma_id,
            title=d.title,
            detection_status=d.detection_status.value
            if hasattr(d.detection_status, "value")
            else str(d.detection_status),
            source=d.source.value if hasattr(d.source, "value") else str(d.source),
            techniques=sorted(set(techs.get(d.id, []))),
        )
        for d in rows
    ]


@router.put(
    "/assets/{asset_id}/detections",
    response_model=AssetDetectionLinkResult,
)
async def replace_asset_detections(
    asset_id: uuid.UUID,
    payload: AssetDetectionLinkIn = Body(...),
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetDetectionLinkResult:
    """Replace the asset's linked-detection set with `payload.detection_ids`.

    Validates every id exists in the tenant's detections table — silent
    misses would be a footgun ("I added 10 rules, why does it say 7?").
    """
    desired = list({did for did in payload.detection_ids})
    async with tenant_session() as session:
        asset_exists = (
            await session.execute(
                select(Asset.id).where(Asset.id == asset_id)
            )
        ).scalar_one_or_none()
        if asset_exists is None:
            raise HTTPException(404, "asset not found")

        if desired:
            found = set(
                (
                    await session.execute(
                        select(Detection.id).where(Detection.id.in_(desired))
                    )
                ).scalars().all()
            )
            missing = [str(d) for d in desired if d not in found]
            if missing:
                raise HTTPException(
                    422,
                    {
                        "detail": "unknown detection_id(s) in this tenant",
                        "missing": missing,
                    },
                )

        current = set(
            (
                await session.execute(
                    select(AssetDetection.detection_id).where(
                        AssetDetection.asset_id == asset_id
                    )
                )
            ).scalars().all()
        )
        desired_set = set(desired)
        to_add = desired_set - current
        to_remove = current - desired_set

        if to_remove:
            await session.execute(
                delete(AssetDetection).where(
                    AssetDetection.asset_id == asset_id,
                    AssetDetection.detection_id.in_(to_remove),
                )
            )
        if to_add:
            # ON CONFLICT DO NOTHING in case of a race (uq_asset_detection).
            await session.execute(
                pg_insert(AssetDetection.__table__)
                .values(
                    [
                        {
                            "id": uuid.uuid4(),
                            "asset_id": asset_id,
                            "detection_id": did,
                        }
                        for did in to_add
                    ]
                )
                .on_conflict_do_nothing(index_elements=["asset_id", "detection_id"])
            )

    return AssetDetectionLinkResult(
        linked=len(to_add),
        unlinked=len(to_remove),
        total=len(desired_set),
    )


# ---- /assets/{id}/data-sources (Collection Management Framework) ---------


class AssetDataSourceOut(BaseModel):
    id: str
    asset_id: str
    name: str
    attack_data_source: Optional[str]
    attack_data_component: Optional[str]
    log_source: Optional[str]
    description: Optional[str]
    storage_connector_id: Optional[str]
    storage_location: Optional[str]
    retention_days: Optional[int]
    device_completeness_q: Optional[int]
    data_field_completeness_q: Optional[int]
    timeliness_q: Optional[int]
    consistency_q: Optional[int]
    retention_q: Optional[int]
    enabled: bool
    notes: Optional[str]
    created_by_email: Optional[str]
    updated_by_email: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class AssetDataSourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    attack_data_source: Optional[str] = Field(default=None, max_length=120)
    attack_data_component: Optional[str] = Field(default=None, max_length=120)
    log_source: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    storage_connector_id: Optional[uuid.UUID] = None
    storage_location: Optional[str] = Field(default=None, max_length=200)
    retention_days: Optional[int] = Field(default=None, ge=0)
    device_completeness_q: Optional[int] = None
    data_field_completeness_q: Optional[int] = None
    timeliness_q: Optional[int] = None
    consistency_q: Optional[int] = None
    retention_q: Optional[int] = None
    enabled: bool = True
    notes: Optional[str] = None


class AssetDataSourcePatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    attack_data_source: Optional[str] = None
    attack_data_component: Optional[str] = None
    log_source: Optional[str] = None
    description: Optional[str] = None
    storage_connector_id: Optional[uuid.UUID] = None
    storage_location: Optional[str] = None
    retention_days: Optional[int] = Field(default=None, ge=0)
    device_completeness_q: Optional[int] = None
    data_field_completeness_q: Optional[int] = None
    timeliness_q: Optional[int] = None
    consistency_q: Optional[int] = None
    retention_q: Optional[int] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None


def _serialise_data_source(d: AssetDataSource) -> AssetDataSourceOut:
    return AssetDataSourceOut(
        id=str(d.id),
        asset_id=str(d.asset_id),
        name=d.name,
        attack_data_source=d.attack_data_source,
        attack_data_component=d.attack_data_component,
        log_source=d.log_source,
        description=d.description,
        storage_connector_id=str(d.storage_connector_id) if d.storage_connector_id else None,
        storage_location=d.storage_location,
        retention_days=d.retention_days,
        device_completeness_q=d.device_completeness_q,
        data_field_completeness_q=d.data_field_completeness_q,
        timeliness_q=d.timeliness_q,
        consistency_q=d.consistency_q,
        retention_q=d.retention_q,
        enabled=d.enabled,
        notes=d.notes,
        created_by_email=d.created_by_email,
        updated_by_email=d.updated_by_email,
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


def _validate_data_source_quality(payload) -> None:
    """Validate the five DeTT&CT quality dimensions on a create/patch body."""
    for field in _QUALITY_FIELDS:
        _validate_quality(getattr(payload, field), field)


async def _assert_asset_exists(session, asset_id: uuid.UUID) -> None:
    exists = (
        await session.execute(select(Asset.id).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(404, "asset not found")


async def _assert_connector_exists(
    session, connector_id: Optional[uuid.UUID]
) -> None:
    if connector_id is None:
        return
    found = (
        await session.execute(
            select(Connector.id).where(Connector.id == connector_id)
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(422, f"unknown storage_connector_id {connector_id}")


@router.get(
    "/assets/{asset_id}/data-sources",
    response_model=list[AssetDataSourceOut],
)
async def list_asset_data_sources(
    asset_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[AssetDataSourceOut]:
    async with tenant_session() as session:
        await _assert_asset_exists(session, asset_id)
        rows = (
            await session.execute(
                select(AssetDataSource)
                .where(AssetDataSource.asset_id == asset_id)
                .order_by(AssetDataSource.name.asc())
            )
        ).scalars().all()
    return [_serialise_data_source(d) for d in rows]


@router.post(
    "/assets/{asset_id}/data-sources",
    response_model=AssetDataSourceOut,
    status_code=201,
)
async def create_asset_data_source(
    asset_id: uuid.UUID,
    payload: AssetDataSourceCreate = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetDataSourceOut:
    _validate_data_source_quality(payload)
    async with tenant_session() as session:
        await _assert_asset_exists(session, asset_id)
        await _assert_connector_exists(session, payload.storage_connector_id)
        ds = AssetDataSource(
            id=uuid.uuid4(),
            asset_id=asset_id,
            name=payload.name.strip(),
            attack_data_source=payload.attack_data_source,
            attack_data_component=payload.attack_data_component,
            log_source=payload.log_source,
            description=payload.description,
            storage_connector_id=payload.storage_connector_id,
            storage_location=payload.storage_location,
            retention_days=payload.retention_days,
            device_completeness_q=payload.device_completeness_q,
            data_field_completeness_q=payload.data_field_completeness_q,
            timeliness_q=payload.timeliness_q,
            consistency_q=payload.consistency_q,
            retention_q=payload.retention_q,
            enabled=payload.enabled,
            notes=payload.notes,
            created_by_email=principal.user.email,
            updated_by_email=principal.user.email,
        )
        session.add(ds)
        try:
            await session.flush()
        except IntegrityError:
            # uq_asset_data_source_name — duplicate label on this asset.
            raise HTTPException(
                409, f"a data source named {payload.name.strip()!r} already exists on this asset"
            )
        return _serialise_data_source(ds)


@router.patch(
    "/assets/{asset_id}/data-sources/{ds_id}",
    response_model=AssetDataSourceOut,
)
async def patch_asset_data_source(
    asset_id: uuid.UUID,
    ds_id: uuid.UUID,
    payload: AssetDataSourcePatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetDataSourceOut:
    _validate_data_source_quality(payload)
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(AssetDataSource).where(
                    AssetDataSource.id == ds_id,
                    AssetDataSource.asset_id == asset_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "data source not found")
        if payload.storage_connector_id is not None:
            await _assert_connector_exists(session, payload.storage_connector_id)
        for field in (
            "name", "attack_data_source", "attack_data_component", "log_source",
            "description", "storage_connector_id", "storage_location",
            "retention_days", "device_completeness_q", "data_field_completeness_q",
            "timeliness_q", "consistency_q", "retention_q", "enabled", "notes",
        ):
            v = getattr(payload, field)
            if v is not None:
                setattr(row, field, v.strip() if field == "name" else v)
        row.updated_by_email = principal.user.email
        try:
            await session.flush()
        except IntegrityError:
            raise HTTPException(
                409, "a data source with that name already exists on this asset"
            )
        await session.refresh(row)
        return _serialise_data_source(row)


@router.delete(
    "/assets/{asset_id}/data-sources/{ds_id}", status_code=204
)
async def delete_asset_data_source(
    asset_id: uuid.UUID,
    ds_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(AssetDataSource).where(
                    AssetDataSource.id == ds_id,
                    AssetDataSource.asset_id == asset_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "data source not found")
        await session.delete(row)
    return Response(status_code=204)


# ---- /assets/import (bulk CMF import) ------------------------------------


_IMPORT_ROW_CAP = 2000


class AssetImportRow(AssetCreate):
    """One asset plus its collection sources. Inherits all asset fields +
    their validation from AssetCreate."""
    data_sources: list[AssetDataSourceCreate] = Field(default_factory=list)


class AssetImportRequest(BaseModel):
    rows: list[AssetImportRow]


class AssetImportResult(BaseModel):
    created: int
    updated: int
    data_sources_added: int
    errors: list[dict]


def _validate_asset_row(row: AssetImportRow) -> list[str]:
    """Validate an import row's asset-level enums and return the canonicalised
    compliance list. Raises HTTPException(422) on the first bad value — the
    caller catches it to record a per-row error. Data-source quality dims are
    validated separately."""
    _validate_enum(row.kind, _ASSET_KINDS, "kind")
    _validate_enum(row.environment, _ENVIRONMENTS, "environment")
    _validate_enum(row.criticality, _CRITICALITIES, "criticality")
    _validate_enum(row.status, _STATUSES, "status")
    _validate_enum(row.cmf_category, _CMF_CATEGORIES, "cmf_category")
    if row.data_classification not in _DATA_CLASSIFICATIONS:
        raise HTTPException(
            422,
            f"data_classification must be one of "
            f"{sorted(v for v in _DATA_CLASSIFICATIONS if v)}",
        )
    return _validate_compliance(row.compliance_scope)


@router.post("/assets/import", response_model=AssetImportResult)
async def import_assets(
    payload: AssetImportRequest = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> AssetImportResult:
    """Bulk-import assets and their collection sources.

    Dedupe is by `external_id`: a row whose external_id matches an existing
    asset *updates* that asset to the imported values (the import file is
    treated as the source of truth); rows without an external_id always
    create a new asset. Data sources are appended by name — an existing
    source with the same name on the asset is left untouched (no clobber).

    Per-row validation errors are collected and reported; valid rows in the
    same request still commit.
    """
    if len(payload.rows) > _IMPORT_ROW_CAP:
        raise HTTPException(
            422, f"too many rows ({len(payload.rows)}); cap is {_IMPORT_ROW_CAP}"
        )

    created = updated = ds_added = 0
    errors: list[dict] = []
    email = principal.user.email

    async with tenant_session() as session:
        # Prefetch existing assets keyed by external_id for dedupe.
        ext_ids = [r.external_id for r in payload.rows if r.external_id]
        existing: dict[str, Asset] = {}
        if ext_ids:
            rows = (
                await session.execute(
                    select(Asset).where(Asset.external_id.in_(ext_ids))
                )
            ).scalars().all()
            existing = {a.external_id: a for a in rows if a.external_id}

        # Prefetch valid connector ids referenced by any data source.
        conn_ids = {
            ds.storage_connector_id
            for r in payload.rows
            for ds in r.data_sources
            if ds.storage_connector_id
        }
        valid_conns: set = set()
        if conn_ids:
            found = (
                await session.execute(
                    select(Connector.id).where(Connector.id.in_(conn_ids))
                )
            ).scalars().all()
            valid_conns = set(found)

        for i, row in enumerate(payload.rows):
            try:
                compliance = _validate_asset_row(row)
                for ds in row.data_sources:
                    _validate_data_source_quality(ds)
                    if ds.storage_connector_id and ds.storage_connector_id not in valid_conns:
                        raise HTTPException(
                            422, f"unknown storage_connector_id {ds.storage_connector_id}"
                        )
            except HTTPException as e:
                errors.append({"row": i, "name": row.name, "error": e.detail})
                continue

            asset = existing.get(row.external_id) if row.external_id else None
            if asset is None:
                asset = Asset(id=uuid.uuid4(), name=row.name.strip(), kind=row.kind)
                session.add(asset)
                created += 1
                # Register in the map so a duplicate external_id later in the
                # same file updates this freshly-created row, not a second one.
                if row.external_id:
                    existing[row.external_id] = asset
            else:
                updated += 1

            asset.name = row.name.strip()
            asset.kind = row.kind
            asset.hostname = row.hostname
            asset.ip_address = row.ip_address
            asset.os = row.os
            asset.environment = row.environment
            asset.location = row.location
            asset.owner = row.owner
            asset.business_function = row.business_function
            asset.cmf_category = row.cmf_category or None
            asset.criticality = row.criticality
            asset.data_classification = row.data_classification or None
            asset.compliance_scope = compliance
            asset.status = row.status
            asset.tags = list(row.tags or [])
            asset.notes = row.notes
            asset.external_id = row.external_id
            asset.updated_by_email = email
            if asset.created_by_email is None:
                asset.created_by_email = email
            await session.flush()

            for ds in row.data_sources:
                result = await session.execute(
                    pg_insert(AssetDataSource.__table__)
                    .values(
                        id=uuid.uuid4(),
                        asset_id=asset.id,
                        name=ds.name.strip(),
                        attack_data_source=ds.attack_data_source,
                        attack_data_component=ds.attack_data_component,
                        log_source=ds.log_source,
                        description=ds.description,
                        storage_connector_id=ds.storage_connector_id,
                        storage_location=ds.storage_location,
                        retention_days=ds.retention_days,
                        device_completeness_q=ds.device_completeness_q,
                        data_field_completeness_q=ds.data_field_completeness_q,
                        timeliness_q=ds.timeliness_q,
                        consistency_q=ds.consistency_q,
                        retention_q=ds.retention_q,
                        enabled=ds.enabled,
                        notes=ds.notes,
                        created_by_email=email,
                        updated_by_email=email,
                    )
                    .on_conflict_do_nothing(index_elements=["asset_id", "name"])
                )
                ds_added += result.rowcount or 0

    return AssetImportResult(
        created=created, updated=updated, data_sources_added=ds_added, errors=errors
    )


# ---- /contacts -----------------------------------------------------------


class ContactOut(BaseModel):
    id: str
    name: str
    role: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    office_address: Optional[str]
    is_primary: bool
    notes: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class ContactCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    role: Optional[str] = Field(default=None, max_length=120)
    email: Optional[str] = Field(default=None, max_length=320)
    phone: Optional[str] = Field(default=None, max_length=60)
    office_address: Optional[str] = None
    is_primary: bool = False
    notes: Optional[str] = None


class ContactPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    office_address: Optional[str] = None
    is_primary: Optional[bool] = None
    notes: Optional[str] = None


def _serialise_contact(c: CustomerContact) -> ContactOut:
    return ContactOut(
        id=str(c.id),
        name=c.name,
        role=c.role,
        email=c.email,
        phone=c.phone,
        office_address=c.office_address,
        is_primary=c.is_primary,
        notes=c.notes,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


@router.get("/contacts", response_model=list[ContactOut])
async def list_contacts(
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[ContactOut]:
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(CustomerContact).order_by(
                    CustomerContact.is_primary.desc(),
                    CustomerContact.name.asc(),
                )
            )
        ).scalars().all()
    return [_serialise_contact(c) for c in rows]


@router.post("/contacts", response_model=ContactOut, status_code=201)
async def create_contact(
    payload: ContactCreate = Body(...),
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> ContactOut:
    async with tenant_session() as session:
        c = CustomerContact(
            id=uuid.uuid4(),
            name=payload.name.strip(),
            role=payload.role,
            email=payload.email,
            phone=payload.phone,
            office_address=payload.office_address,
            is_primary=payload.is_primary,
            notes=payload.notes,
        )
        session.add(c)
        await session.flush()
        return _serialise_contact(c)


@router.patch("/contacts/{contact_id}", response_model=ContactOut)
async def patch_contact(
    contact_id: uuid.UUID,
    payload: ContactPatch = Body(...),
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> ContactOut:
    async with tenant_session() as session:
        c = (
            await session.execute(
                select(CustomerContact).where(CustomerContact.id == contact_id)
            )
        ).scalar_one_or_none()
        if c is None:
            raise HTTPException(404, "contact not found")
        for field in ("name", "role", "email", "phone", "office_address", "is_primary", "notes"):
            v = getattr(payload, field)
            if v is not None:
                if field == "name":
                    setattr(c, field, v.strip())
                else:
                    setattr(c, field, v)
        await session.flush()
        await session.refresh(c)  # see _serialise_asset comment re: onupdate
        return _serialise_contact(c)


@router.delete("/contacts/{contact_id}", status_code=204)
async def delete_contact(
    contact_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        c = (
            await session.execute(
                select(CustomerContact).where(CustomerContact.id == contact_id)
            )
        ).scalar_one_or_none()
        if c is None:
            raise HTTPException(404, "contact not found")
        await session.delete(c)
    return Response(status_code=204)


__all__ = ["router"]
