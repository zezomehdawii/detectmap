"""Collection Management Framework — lifecycle endpoints.

The *manage* half of the CMF workspace: collection requirements (the why) and
the collection plan / implementation tracker (the what + status). Tenant-
scoped, ASSET_READ for GETs and ASSET_WRITE for mutations — same as assets.

`POST /cmf/plan/seed-from-gaps` is the "inherited from gap analysis" step: it
turns the current visibility recommendations into proposed plan items.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import Asset, AssetDataSource, CollectionPlanItem, CollectionRequirement
from app.services.cmf_visibility import DenominatorKind, compute_recommendations
from app.services.cmf_sources import normalize_source_fields

router = APIRouter(prefix="/cmf", tags=["cmf"])


# ---- validation vocab (string-validated, not DB enums) --------------------

_DRIVERS = {
    "ttx", "risk_management", "threat_modeling", "threat_intel",
    "incident", "compliance", "other",
}
_PRIORITIES = {"low", "medium", "high", "critical"}
_REQ_STATUSES = {"proposed", "active", "satisfied", "archived"}
_PLAN_STATUSES = {
    "proposed", "approved", "in_progress", "collected", "validated", "deferred",
}


def _validate(value: str, allowed: set, field: str) -> str:
    if value not in allowed:
        raise HTTPException(422, f"{field} must be one of {sorted(allowed)}")
    return value


def _reject_nulls(payload, required: tuple[str, ...]) -> None:
    for field in required:
        if field in payload.model_fields_set and getattr(payload, field) is None:
            raise HTTPException(422, f"{field} cannot be null")


async def _validate_plan_links(
    session, *, requirement_id, target_asset_id, asset_data_source_id,
    status: str, notes: Optional[str], data_source: str,
) -> None:
    for model, value, label in (
        (CollectionRequirement, requirement_id, "requirement_id"),
        (Asset, target_asset_id, "target_asset_id"),
    ):
        if value is not None:
            found = (await session.execute(select(model.id).where(model.id == value))).scalar_one_or_none()
            if found is None:
                raise HTTPException(422, f"unknown {label}")
    source = None
    if asset_data_source_id is not None:
        source = (await session.execute(
            select(AssetDataSource).where(AssetDataSource.id == asset_data_source_id).with_for_update()
        )).scalar_one_or_none()
        if source is None:
            raise HTTPException(422, "unknown asset_data_source_id")
        if target_asset_id is None or source.asset_id != target_asset_id:
            raise HTTPException(422, "collection source must belong to the target asset")
        mapping = normalize_source_fields({
            "attack_data_source": source.attack_data_source,
            "attack_data_component": source.attack_data_component,
        })
        actual = mapping["attack_data_source"]
        if actual and mapping["attack_data_component"]:
            actual = f"{actual}: {mapping['attack_data_component']}"
        # Unmapped collection labels can match their explicit source name.
        actual = actual or source.name
        if actual.strip().casefold() != data_source.strip().casefold():
            raise HTTPException(422, "linked collection source does not match the plan data_source")
    if status in {"collected", "validated"}:
        if source is None or not source.enabled:
            raise HTTPException(422, "collected/validated plan items require an enabled collection source on the target asset")
    if status == "validated" and not (notes or "").strip():
        raise HTTPException(422, "validated plan items require test evidence in notes")


def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid denominator kind: {s!r}") from e


# ---- requirements ---------------------------------------------------------

class RequirementOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    driver: str
    priority: str
    status: str
    attack_technique_ids: list[str]
    apt_group_id: Optional[str]
    plan_item_count: int
    author_email: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class RequirementCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    driver: str = "other"
    priority: str = "medium"
    status: str = "proposed"
    attack_technique_ids: list[str] = Field(default_factory=list)
    apt_group_id: Optional[str] = Field(default=None, max_length=20)

    @field_validator("title")
    @classmethod
    def nonblank_title(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("title cannot be blank")
        return value


class RequirementPatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    driver: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    attack_technique_ids: Optional[list[str]] = None
    apt_group_id: Optional[str] = Field(default=None, max_length=20)

    @field_validator("title")
    @classmethod
    def nonblank_title(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("title cannot be blank")
        return value


def _req_out(r: CollectionRequirement, plan_count: int) -> RequirementOut:
    return RequirementOut(
        id=str(r.id),
        title=r.title,
        description=r.description,
        driver=r.driver,
        priority=r.priority,
        status=r.status,
        attack_technique_ids=list(r.attack_technique_ids or []),
        apt_group_id=r.apt_group_id,
        plan_item_count=plan_count,
        author_email=r.author_email,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.get("/requirements", response_model=list[RequirementOut])
async def list_requirements(
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[RequirementOut]:
    async with tenant_session() as session:
        reqs = (
            await session.execute(
                select(CollectionRequirement).order_by(
                    CollectionRequirement.created_at.desc()
                )
            )
        ).scalars().all()
        counts = dict(
            (
                await session.execute(
                    select(
                        CollectionPlanItem.requirement_id, func.count()
                    ).group_by(CollectionPlanItem.requirement_id)
                )
            ).all()
        )
        return [_req_out(r, int(counts.get(r.id, 0))) for r in reqs]


@router.post("/requirements", response_model=RequirementOut, status_code=201)
async def create_requirement(
    payload: RequirementCreate,
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> RequirementOut:
    _validate(payload.driver, _DRIVERS, "driver")
    _validate(payload.priority, _PRIORITIES, "priority")
    _validate(payload.status, _REQ_STATUSES, "status")
    async with tenant_session() as session:
        r = CollectionRequirement(
            id=uuid.uuid4(),
            title=payload.title.strip(),
            description=payload.description,
            driver=payload.driver,
            priority=payload.priority,
            status=payload.status,
            attack_technique_ids=payload.attack_technique_ids,
            apt_group_id=payload.apt_group_id,
            author_email=principal.user.email,
        )
        session.add(r)
        await session.flush()
        await session.refresh(r)
        return _req_out(r, 0)


@router.patch("/requirements/{requirement_id}", response_model=RequirementOut)
async def update_requirement(
    requirement_id: uuid.UUID,
    payload: RequirementPatch,
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> RequirementOut:
    _reject_nulls(payload, ("title", "driver", "priority", "status", "attack_technique_ids"))
    if payload.driver is not None:
        _validate(payload.driver, _DRIVERS, "driver")
    if payload.priority is not None:
        _validate(payload.priority, _PRIORITIES, "priority")
    if payload.status is not None:
        _validate(payload.status, _REQ_STATUSES, "status")
    async with tenant_session() as session:
        r = (
            await session.execute(
                select(CollectionRequirement).where(
                    CollectionRequirement.id == requirement_id
                )
            )
        ).scalar_one_or_none()
        if r is None:
            raise HTTPException(404, "requirement not found")
        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(r, field, value.strip() if field == "title" and value else value)
        await session.flush()
        count = (
            await session.execute(
                select(func.count()).select_from(CollectionPlanItem).where(
                    CollectionPlanItem.requirement_id == requirement_id
                )
            )
        ).scalar_one()
        await session.refresh(r)
        return _req_out(r, int(count))


@router.delete("/requirements/{requirement_id}", status_code=204)
async def delete_requirement(
    requirement_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        res = await session.execute(
            delete(CollectionRequirement).where(
                CollectionRequirement.id == requirement_id
            )
        )
        if res.rowcount == 0:
            raise HTTPException(404, "requirement not found")
    return Response(status_code=204)


# ---- plan items / implementation tracker ----------------------------------

class PlanItemOut(BaseModel):
    id: str
    data_source: str
    title: Optional[str]
    rationale: Optional[str]
    requirement_id: Optional[str]
    requirement_title: Optional[str]
    target_asset_id: Optional[str]
    target_asset_name: Optional[str]
    asset_data_source_id: Optional[str]
    priority: str
    status: str
    assigned_to: Optional[str]
    due_date: Optional[date]
    technique_count: int
    source_kind: str
    notes: Optional[str]
    author_email: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class PlanItemCreate(BaseModel):
    data_source: str = Field(..., min_length=1, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    rationale: Optional[str] = None
    requirement_id: Optional[uuid.UUID] = None
    target_asset_id: Optional[uuid.UUID] = None
    asset_data_source_id: Optional[uuid.UUID] = None
    priority: str = "medium"
    status: str = "proposed"
    assigned_to: Optional[str] = Field(default=None, max_length=200)
    due_date: Optional[date] = None
    notes: Optional[str] = None

    @field_validator("data_source")
    @classmethod
    def nonblank_data_source(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("data_source cannot be blank")
        return value


class PlanItemPatch(BaseModel):
    data_source: Optional[str] = Field(default=None, min_length=1, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    rationale: Optional[str] = None
    requirement_id: Optional[uuid.UUID] = None
    target_asset_id: Optional[uuid.UUID] = None
    asset_data_source_id: Optional[uuid.UUID] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = Field(default=None, max_length=200)
    due_date: Optional[date] = None
    notes: Optional[str] = None

    @field_validator("data_source")
    @classmethod
    def nonblank_data_source(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("data_source cannot be blank")
        return value


class SeedFromGapsRequest(BaseModel):
    domain: str = "enterprise"
    denominator: str = "full"
    ref: Optional[str] = None
    limit: int = Field(default=15, ge=1, le=100)


class SeedFromGapsResult(BaseModel):
    created: int
    skipped: int
    items: list[PlanItemOut]


def _plan_out(
    item: CollectionPlanItem,
    req_title: Optional[str],
    asset_name: Optional[str],
) -> PlanItemOut:
    return PlanItemOut(
        id=str(item.id),
        data_source=item.data_source,
        title=item.title,
        rationale=item.rationale,
        requirement_id=str(item.requirement_id) if item.requirement_id else None,
        requirement_title=req_title,
        target_asset_id=str(item.target_asset_id) if item.target_asset_id else None,
        target_asset_name=asset_name,
        asset_data_source_id=str(item.asset_data_source_id) if item.asset_data_source_id else None,
        priority=item.priority,
        status=item.status,
        assigned_to=item.assigned_to,
        due_date=item.due_date,
        technique_count=item.technique_count,
        source_kind=item.source_kind,
        notes=item.notes,
        author_email=item.author_email,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


# Rank order for stable, meaningful plan sorting.
_STATUS_ORDER = {
    "in_progress": 0, "approved": 1, "proposed": 2,
    "collected": 3, "validated": 4, "deferred": 5,
}
_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


async def _load_plan(session, *, status: Optional[str] = None) -> list[PlanItemOut]:
    stmt = (
        select(
            CollectionPlanItem,
            CollectionRequirement.title,
            Asset.name,
        )
        .outerjoin(
            CollectionRequirement,
            CollectionPlanItem.requirement_id == CollectionRequirement.id,
        )
        .outerjoin(Asset, CollectionPlanItem.target_asset_id == Asset.id)
    )
    if status:
        stmt = stmt.where(CollectionPlanItem.status == status)
    rows = (await session.execute(stmt)).all()
    out = [_plan_out(item, req_title, asset_name) for item, req_title, asset_name in rows]
    out.sort(
        key=lambda p: (
            _STATUS_ORDER.get(p.status, 9),
            _PRIORITY_ORDER.get(p.priority, 9),
            -p.technique_count,
        )
    )
    return out


@router.get("/plan", response_model=list[PlanItemOut])
async def list_plan_items(
    status: Optional[str] = Query(None),
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[PlanItemOut]:
    if status is not None:
        _validate(status, _PLAN_STATUSES, "status")
    async with tenant_session() as session:
        return await _load_plan(session, status=status)


@router.post("/plan", response_model=PlanItemOut, status_code=201)
async def create_plan_item(
    payload: PlanItemCreate,
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> PlanItemOut:
    _validate(payload.priority, _PRIORITIES, "priority")
    _validate(payload.status, _PLAN_STATUSES, "status")
    async with tenant_session() as session:
        await _validate_plan_links(
            session, requirement_id=payload.requirement_id,
            target_asset_id=payload.target_asset_id,
            asset_data_source_id=payload.asset_data_source_id,
            status=payload.status, notes=payload.notes, data_source=payload.data_source,
        )
        item = CollectionPlanItem(
            id=uuid.uuid4(),
            data_source=payload.data_source.strip(),
            title=payload.title,
            rationale=payload.rationale,
            requirement_id=payload.requirement_id,
            target_asset_id=payload.target_asset_id,
            asset_data_source_id=payload.asset_data_source_id,
            priority=payload.priority,
            status=payload.status,
            assigned_to=payload.assigned_to,
            due_date=payload.due_date,
            source_kind="manual",
            notes=payload.notes,
            author_email=principal.user.email,
        )
        session.add(item)
        await session.flush()
        await session.refresh(item)
        # Re-serialise with joined titles.
        items = await _load_plan(session)
        return next(p for p in items if p.id == str(item.id))


@router.patch("/plan/{item_id}", response_model=PlanItemOut)
async def update_plan_item(
    item_id: uuid.UUID,
    payload: PlanItemPatch,
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> PlanItemOut:
    _reject_nulls(payload, ("data_source", "priority", "status"))
    if payload.priority is not None:
        _validate(payload.priority, _PRIORITIES, "priority")
    if payload.status is not None:
        _validate(payload.status, _PLAN_STATUSES, "status")
    async with tenant_session() as session:
        item = (
            await session.execute(
                select(CollectionPlanItem).where(CollectionPlanItem.id == item_id)
            )
        ).scalar_one_or_none()
        if item is None:
            raise HTTPException(404, "plan item not found")
        changes = payload.model_dump(exclude_unset=True)
        await _validate_plan_links(
            session,
            requirement_id=changes.get("requirement_id", item.requirement_id),
            target_asset_id=changes.get("target_asset_id", item.target_asset_id),
            asset_data_source_id=changes.get("asset_data_source_id", item.asset_data_source_id),
            status=changes.get("status", item.status),
            notes=changes.get("notes", item.notes),
            data_source=changes.get("data_source", item.data_source),
        )
        for field, value in changes.items():
            setattr(item, field, value)
        await session.flush()
        items = await _load_plan(session)
        return next(p for p in items if p.id == str(item.id))


@router.delete("/plan/{item_id}", status_code=204)
async def delete_plan_item(
    item_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        res = await session.execute(
            delete(CollectionPlanItem).where(CollectionPlanItem.id == item_id)
        )
        if res.rowcount == 0:
            raise HTTPException(404, "plan item not found")
    return Response(status_code=204)


def _seed_priority(touches: int) -> str:
    if touches >= 40:
        return "high"
    if touches >= 10:
        return "medium"
    return "low"


@router.post("/plan/seed-from-gaps", response_model=SeedFromGapsResult)
async def seed_plan_from_gaps(
    payload: SeedFromGapsRequest,
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SeedFromGapsResult:
    """Turn the current visibility recommendations into proposed plan items.
    Idempotent on `data_source` — sources already in the plan are skipped."""
    kind = _parse_kind(payload.denominator)
    recs = await compute_recommendations(
        payload.domain, kind, payload.ref, limit=payload.limit
    )
    created = 0
    skipped = 0
    async with tenant_session() as session:
        existing = set(
            (
                await session.execute(select(CollectionPlanItem.data_source))
            ).scalars().all()
        )
        for r in recs:
            if r.raw in existing:
                skipped += 1
                continue
            session.add(
                CollectionPlanItem(
                    id=uuid.uuid4(),
                    data_source=r.raw,
                    title=r.raw,
                    rationale=(
                        f"Seeded from gap analysis — illuminates {r.touches} "
                        f"in-scope technique(s); {r.unlocks} would become fully "
                        f"visible. Examples: {', '.join(r.sample_technique_ids)}."
                    ),
                    priority=_seed_priority(r.touches),
                    status="proposed",
                    technique_count=r.touches,
                    source_kind="gap_seed",
                    author_email=principal.user.email,
                )
            )
            existing.add(r.raw)
            created += 1
        await session.flush()
        items = await _load_plan(session)
    return SeedFromGapsResult(created=created, skipped=skipped, items=items)
