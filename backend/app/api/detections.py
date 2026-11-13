"""Detection (Sigma rule) endpoints — tenant-scoped."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select

from app.api.deps import (
    TenantPrincipal,
    require_active_customer,
    require_feature,
    require_perm,
)
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import (
    Detection,
    DetectionReviewEvent,
    DetectionSource,
    DetectionStatus,
    DetectionTechnique,
    DetectionVersion,
    SigmaLevel,
)
from app.models.public import Role
from app.services.detection_review import (
    DEPLOYMENT_APPROVAL_REQUIRED,
    DEPLOYMENT_EDIT_REVIEW_REQUIRED,
    GLOBAL_RULE_REVIEW_REFUSED,
    GLOBAL_RULE_REVIEW_REQUIRED,
    ReviewTransitionError,
    apply_review_action,
    deployment_block_reason,
    invalidate_review,
    parse_review_action,
    parse_review_status,
    review_status_value,
)
from app.services.detection_versions import (
    REVIEW_NEUTRAL_FIELDS,
    append_version,
    field_changes,
    history_for,
    initial_version,
    snapshot,
)
from app.services.sigma_validate import (
    SigmaValidationError,
    parse_sigma_yaml,
    techniques_from_tags,
)

router = APIRouter(prefix="/detections", tags=["detections"])


class DetectionTechniqueOut(BaseModel):
    technique_id: str
    domain: str


class DetectionListItem(BaseModel):
    id: str
    sigma_id: str
    title: str
    description: Optional[str]
    detection_status: str
    source: str
    level: Optional[str]
    score_breadth: int
    score_depth: int
    upstream_global_id: Optional[str]
    tags: list[str]
    techniques: list[str]
    owner: Optional[str]
    review_status: str
    version: int
    last_changed_at: datetime


class DetectionReviewEventOut(BaseModel):
    id: str
    action: str
    from_status: str
    to_status: str
    note: Optional[str]
    actor_email: Optional[str]
    created_at: datetime


class DetectionVersionOut(BaseModel):
    version: int
    changed_at: datetime
    changed_by_user_id: Optional[uuid.UUID]
    changed_by_email: Optional[str]
    changed_by_name: Optional[str]
    change_reason: str
    source: str
    changes: dict[str, dict[str, Any]]


class DetectionDetail(DetectionListItem):
    sigma_status: Optional[str]
    author: Optional[str]
    sigma_references: list[str]
    logsource: dict
    detection: dict
    falsepositives: list[str]
    raw_yaml: Optional[str]
    reviewer_email: Optional[str]
    review_requested_at: Optional[datetime]
    reviewed_at: Optional[datetime]
    review_due_at: Optional[datetime]
    review_note: Optional[str]
    review_events: list[DetectionReviewEventOut]


class PaginatedDetections(BaseModel):
    items: list[DetectionListItem]
    total: int
    page: int
    page_size: int


class DetectionCreate(BaseModel):
    raw_yaml: str
    detection_status: Optional[str] = None
    score_breadth: int = 0
    score_depth: int = 0
    owner: Optional[str] = None


class DetectionPatch(BaseModel):
    raw_yaml: Optional[str] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=500)
    description: Optional[str] = None
    detection_status: Optional[str] = None
    level: Optional[str] = None
    score_breadth: Optional[int] = None
    score_depth: Optional[int] = None
    tags: Optional[list[str]] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    change_reason: Optional[str] = Field(default=None, max_length=2000)
    expected_version: Optional[int] = Field(default=None, ge=1)


class ReviewActionIn(BaseModel):
    action: str
    note: Optional[str] = None
    reviewer_email: Optional[str] = None
    review_due_at: Optional[datetime] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


def _validate_status(s: Optional[str]) -> Optional[DetectionStatus]:
    if s is None:
        return None
    try:
        return DetectionStatus(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid detection_status: {s!r}") from e


def _validate_level(s: Optional[str]) -> Optional[SigmaLevel]:
    if s is None:
        return None
    try:
        return SigmaLevel(s)
    except ValueError as e:
        raise HTTPException(422, f"invalid level: {s!r}") from e


def _validate_review_status(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    try:
        return parse_review_status(s).value
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


def _validate_review_action(s: str):
    try:
        return parse_review_action(s)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


def _serialize_list_item(d: Detection, technique_ids: list[str]) -> DetectionListItem:
    return DetectionListItem(
        id=str(d.id),
        sigma_id=d.sigma_id,
        title=d.title,
        description=d.description,
        detection_status=d.detection_status.value,
        source=d.source.value,
        level=d.level.value if d.level else None,
        score_breadth=d.score_breadth,
        score_depth=d.score_depth,
        upstream_global_id=d.upstream_global_id,
        tags=list(d.tags or []),
        techniques=technique_ids,
        owner=d.owner,
        review_status=review_status_value(d.review_status),
        version=d.version,
        last_changed_at=d.last_changed_at,
    )


def _serialize_version(event: DetectionVersion) -> DetectionVersionOut:
    return DetectionVersionOut.model_validate(event, from_attributes=True)


def _serialize_review_event(event: DetectionReviewEvent) -> DetectionReviewEventOut:
    return DetectionReviewEventOut(
        id=str(event.id),
        action=event.action,
        from_status=event.from_status,
        to_status=event.to_status,
        note=event.note,
        actor_email=event.actor_email,
        created_at=event.created_at,
    )


def _serialize_detail(
    d: Detection,
    technique_ids: list[str],
    review_events: Optional[list[DetectionReviewEvent]] = None,
) -> DetectionDetail:
    base = _serialize_list_item(d, technique_ids)
    return DetectionDetail(
        **base.model_dump(),
        sigma_status=d.sigma_status,
        author=d.author,
        sigma_references=list(d.sigma_references or []),
        logsource=dict(d.logsource or {}),
        detection=dict(d.detection or {}),
        falsepositives=list(d.falsepositives or []),
        raw_yaml=d.raw_yaml,
        reviewer_email=d.reviewer_email,
        review_requested_at=d.review_requested_at,
        reviewed_at=d.reviewed_at,
        review_due_at=d.review_due_at,
        review_note=d.review_note,
        review_events=[_serialize_review_event(e) for e in (review_events or [])],
    )


async def _review_events_for(
    session, detection_id: uuid.UUID, limit: int = 50
) -> list[DetectionReviewEvent]:
    rows = (
        await session.execute(
            select(DetectionReviewEvent)
            .where(DetectionReviewEvent.detection_id == detection_id)
            .order_by(DetectionReviewEvent.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


async def _techniques_for(session, detection_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    if not detection_ids:
        return {}
    rows = (
        await session.execute(
            select(DetectionTechnique).where(
                DetectionTechnique.detection_id.in_(detection_ids)
            )
        )
    ).scalars().all()
    out: dict[uuid.UUID, list[str]] = {did: [] for did in detection_ids}
    for r in rows:
        out.setdefault(r.detection_id, []).append(r.technique_id)
    for did in out:
        out[did].sort()
    return out


async def _replace_technique_mappings(
    session, detection_id: uuid.UUID, tags: list[str]
) -> None:
    await session.execute(
        delete(DetectionTechnique).where(DetectionTechnique.detection_id == detection_id)
    )
    tids = dict.fromkeys(techniques_from_tags(tags))
    if not tids:
        return
    for tid in tids:
        session.add(
            DetectionTechnique(
                id=uuid.uuid4(),
                detection_id=detection_id,
                technique_id=tid,
                domain="enterprise",
            )
        )
    # The AsyncSessionLocal is autoflush=False, so explicit flush so subsequent
    # SELECTs in the same transaction see these rows.
    await session.flush()


@router.get("", response_model=PaginatedDetections)
async def list_detections(
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="ILIKE on title"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> PaginatedDetections:
    clauses = []
    if status:
        clauses.append(Detection.detection_status == _validate_status(status))
    if source:
        try:
            clauses.append(Detection.source == DetectionSource(source))
        except ValueError as e:
            raise HTTPException(422, f"invalid source: {source!r}") from e
    if level:
        clauses.append(Detection.level == _validate_level(level))
    if review_status:
        clauses.append(Detection.review_status == _validate_review_status(review_status))
    if q:
        clauses.append(Detection.title.ilike(f"%{q}%"))

    where = and_(*clauses) if clauses else None
    base = select(Detection)
    count_stmt = select(func.count()).select_from(Detection)

    if technique_id:
        # filter by detection_techniques.technique_id; join then dedup
        base = base.join(
            DetectionTechnique,
            DetectionTechnique.detection_id == Detection.id,
        ).where(DetectionTechnique.technique_id == technique_id)
        count_stmt = (
            select(func.count(func.distinct(Detection.id)))
            .select_from(Detection)
            .join(
                DetectionTechnique,
                DetectionTechnique.detection_id == Detection.id,
            )
            .where(DetectionTechnique.technique_id == technique_id)
        )

    if where is not None:
        base = base.where(where)
        count_stmt = count_stmt.where(where)
    base = base.order_by(Detection.title).distinct()

    async with tenant_session() as session:
        total = (await session.execute(count_stmt)).scalar_one()
        rows = (
            await session.execute(
                base.offset((page - 1) * page_size).limit(page_size)
            )
        ).scalars().all()
        tech_map = await _techniques_for(session, [r.id for r in rows])

    return PaginatedDetections(
        items=[_serialize_list_item(r, tech_map.get(r.id, [])) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/{detection_id:uuid}", response_model=DetectionDetail)
async def get_detection(
    detection_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> DetectionDetail:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Detection).where(Detection.id == detection_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "detection not found")
        tech_map = await _techniques_for(session, [row.id])
        events = await _review_events_for(session, row.id)
    return _serialize_detail(row, tech_map.get(row.id, []), events)


@router.get("/{detection_id:uuid}/history", response_model=list[DetectionVersionOut])
async def get_detection_history(
    detection_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[DetectionVersionOut]:
    async with tenant_session() as session:
        row = await session.get(Detection, detection_id)
        if row is None:
            raise HTTPException(404, "detection not found")
        return [_serialize_version(event) for event in await history_for(session, row)]


@router.post("", response_model=DetectionDetail, status_code=201)
async def create_detection(
    payload: DetectionCreate,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> DetectionDetail:
    try:
        parsed = parse_sigma_yaml(payload.raw_yaml)
    except SigmaValidationError as e:
        raise HTTPException(422, str(e)) from e
    status = _validate_status(payload.detection_status) or DetectionStatus.IDEA
    if status == DetectionStatus.DEPLOYED:
        raise HTTPException(409, DEPLOYMENT_APPROVAL_REQUIRED)
    level = SigmaLevel(parsed["level"]) if parsed.get("level") in SigmaLevel._value2member_map_ else None

    async with tenant_session() as session:
        existing = (
            await session.execute(
                select(Detection).where(Detection.sigma_id == parsed["sigma_id"])
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                409,
                f"detection with sigma_id={parsed['sigma_id']} already exists",
            )
        det = Detection(
            id=uuid.uuid4(),
            sigma_id=parsed["sigma_id"],
            title=parsed["title"],
            description=parsed["description"],
            sigma_status=parsed["sigma_status"],
            level=level,
            author=parsed["author"],
            sigma_references=parsed["sigma_references"],
            tags=parsed["tags"],
            logsource=parsed["logsource"],
            detection=parsed["detection"],
            falsepositives=parsed["falsepositives"],
            raw_yaml=parsed["raw_yaml"],
            detection_status=status,
            source=DetectionSource.CUSTOM,
            score_breadth=payload.score_breadth,
            score_depth=payload.score_depth,
            owner=payload.owner or None,
            review_status="draft",
        )
        session.add(det)
        await session.flush()
        session.add(initial_version(
            det, actor=_principal.user, reason="Created use case.", source="created"
        ))
        await _replace_technique_mappings(session, det.id, parsed["tags"])
        tech_map = await _techniques_for(session, [det.id])
    return _serialize_detail(det, tech_map.get(det.id, []))


def _required_change_reason(reason: str | None) -> str:
    purpose = (reason or "").strip()
    if not purpose:
        raise HTTPException(422, "Enter the purpose of the change.")
    return purpose


def _require_current_version(row: Detection, expected: int | None) -> None:
    if expected is not None and expected != row.version:
        raise HTTPException(409, "This use case changed since you opened it. Reload it and try again.")


def _patch_fields(row: Detection, payload: DetectionPatch) -> dict[str, Any]:
    updates = payload.model_dump(
        include={"title", "description", "tags", "score_breadth", "score_depth", "owner"},
        exclude_none=True,
    )
    if "owner" in updates:
        updates["owner"] = updates["owner"] or None
    if payload.detection_status is not None:
        updates["detection_status"] = _validate_status(payload.detection_status)

    if payload.raw_yaml is not None and payload.raw_yaml != row.raw_yaml:
        try:
            parsed = parse_sigma_yaml(payload.raw_yaml)
        except SigmaValidationError as exc:
            raise HTTPException(422, str(exc)) from exc

        # Imported copies can have a tenant-local identifier distinct from
        # the identifier of the original rule stored in their YAML.
        old_sigma_id = row.sigma_id
        if row.raw_yaml:
            try:
                old_sigma_id = parse_sigma_yaml(row.raw_yaml)["sigma_id"]
            except SigmaValidationError:
                pass
        if parsed["sigma_id"] != old_sigma_id:
            raise HTTPException(422, "Keep the existing Sigma rule ID when editing its YAML.")
        updates.update({
            field: parsed[field] for field in (
                "title", "description", "tags", "sigma_status", "author",
                "sigma_references", "logsource", "detection", "falsepositives", "raw_yaml",
            )
        })
        updates["level"] = _validate_level(parsed["level"])
    if payload.level is not None:
        updates["level"] = _validate_level(payload.level)
    return updates


@router.patch("/{detection_id:uuid}", response_model=DetectionDetail)
async def patch_detection(
    detection_id: uuid.UUID,
    payload: DetectionPatch,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> DetectionDetail:
    """Update a use case and record a version in the same transaction."""
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(Detection).where(Detection.id == detection_id).with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "detection not found")
        _require_current_version(row, payload.expected_version)

        before = snapshot(row)
        updates = _patch_fields(row, payload)
        changes = field_changes(before, updates)
        if not changes:
            tech_map = await _techniques_for(session, [row.id])
            events = await _review_events_for(session, row.id)
            return _serialize_detail(row, tech_map.get(row.id, []), events)

        substantive = bool(changes.keys() - REVIEW_NEUTRAL_FIELDS)
        is_global = row.source == DetectionSource.GLOBAL
        new_status = updates.get("detection_status")
        if new_status == DetectionStatus.DEPLOYED:
            if is_global:
                raise HTTPException(409, GLOBAL_RULE_REVIEW_REQUIRED)
            if row.detection_status != DetectionStatus.DEPLOYED:
                if substantive:
                    raise HTTPException(409, DEPLOYMENT_EDIT_REVIEW_REQUIRED)
                blocked = deployment_block_reason(row)
                if blocked:
                    raise HTTPException(409, blocked)

        purpose = _required_change_reason(payload.change_reason)
        if is_global:
            target = Detection(
                id=uuid.uuid4(),
                sigma_id=row.sigma_id,
                source=DetectionSource.CUSTOMIZED,
                upstream_global_id=row.upstream_global_id or row.sigma_id,
                review_status="draft",
                **(before | updates),
            )
            session.add(target)
            await session.flush()
        else:
            target = row
            for field in changes:
                setattr(target, field, updates[field])
            if substantive:
                event = invalidate_review(
                    target,
                    actor_email=_principal.user.email,
                    reason="Detection content changed; review must be repeated.",
                )
                if event is not None:
                    session.add(event)

        await append_version(
            session, target, before=before, changes=changes, actor=_principal.user, reason=purpose
        )
        if is_global or "tags" in changes:
            await _replace_technique_mappings(session, target.id, list(target.tags or []))
        await session.flush()
        tech_map = await _techniques_for(session, [target.id])
        events = await _review_events_for(session, target.id)
    return _serialize_detail(target, tech_map.get(target.id, []), events)


@router.post("/{detection_id:uuid}/review", response_model=DetectionDetail)
async def review_detection(
    detection_id: uuid.UUID,
    payload: ReviewActionIn,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> DetectionDetail:
    """Move a detection through its review lifecycle.

    Approval is recorded separately from `detection_status`; the caller still
    has to patch the status to `deployed` (or approve first, then deploy).
    """
    action = _validate_review_action(payload.action)
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(Detection).where(Detection.id == detection_id).with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "detection not found")
        if row.source == DetectionSource.GLOBAL:
            raise HTTPException(409, GLOBAL_RULE_REVIEW_REFUSED)
        _require_current_version(row, payload.expected_version)

        try:
            event = apply_review_action(
                row,
                action,
                actor_email=_principal.user.email,
                note=payload.note,
                reviewer_email=payload.reviewer_email,
                due_at=payload.review_due_at,
            )
        except ReviewTransitionError as e:
            raise HTTPException(409, str(e)) from e
        session.add(event)
        await session.flush()
        tech_map = await _techniques_for(session, [row.id])
        events = await _review_events_for(session, row.id)
    return _serialize_detail(row, tech_map.get(row.id, []), events)


@router.delete("/{detection_id:uuid}", status_code=204)
async def delete_detection(
    detection_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_DELETE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Detection).where(Detection.id == detection_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "detection not found")
        if row.source == DetectionSource.GLOBAL:
            raise HTTPException(
                409,
                "cannot delete a global rule — edit to customize, or filter from the UI",
            )
        await session.delete(row)
    return Response(status_code=204)


class BulkStatusIn(BaseModel):
    ids: list[uuid.UUID]
    detection_status: str
    change_reason: Optional[str] = Field(default=None, max_length=2000)


class BulkResultOut(BaseModel):
    updated: int
    skipped: int
    blocked: int = 0


@router.post("/bulk-status", response_model=BulkResultOut)
async def bulk_status(
    payload: BulkStatusIn,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> BulkResultOut:
    """Set detection_status on many rows. Global rules are skipped (editing a
    global flips it to customized — not appropriate for a bulk status nudge)."""
    new_status = _validate_status(payload.detection_status)
    if new_status is None:
        raise HTTPException(422, "invalid detection_status")
    if not payload.ids:
        return BulkResultOut(updated=0, skipped=0)
    updated = skipped = blocked = 0
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(Detection)
                .where(Detection.id.in_(payload.ids))
                .order_by(Detection.id)
                .with_for_update()
            )
        ).scalars().all()
        for row in rows:
            if row.source == DetectionSource.GLOBAL or row.detection_status == new_status:
                skipped += 1
                continue
            if new_status == DetectionStatus.DEPLOYED and deployment_block_reason(row):
                blocked += 1
                continue
            purpose = _required_change_reason(payload.change_reason)
            before = snapshot(row)
            changes = field_changes(before, {"detection_status": new_status})
            row.detection_status = new_status
            await append_version(
                session, row, before=before, changes=changes, actor=_principal.user,
                reason=purpose, source="bulk",
            )
            updated += 1
    return BulkResultOut(updated=updated, skipped=skipped, blocked=blocked)


class BulkDeleteIn(BaseModel):
    ids: list[uuid.UUID]


@router.post("/bulk-delete", response_model=BulkResultOut)
async def bulk_delete(
    payload: BulkDeleteIn,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_DELETE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_editing")),
) -> BulkResultOut:
    """Delete many rows. Global rules are skipped (can't be deleted)."""
    if not payload.ids:
        return BulkResultOut(updated=0, skipped=0)
    deleted = skipped = 0
    async with tenant_session() as session:
        rows = (
            await session.execute(select(Detection).where(Detection.id.in_(payload.ids)))
        ).scalars().all()
        for row in rows:
            if row.source == DetectionSource.GLOBAL:
                skipped += 1
                continue
            await session.delete(row)
            deleted += 1
    return BulkResultOut(updated=deleted, skipped=skipped)


@router.get("/{detection_id:uuid}/export", response_class=Response)
async def export_detection(
    detection_id: uuid.UUID,
    _principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Detection).where(Detection.id == detection_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "detection not found")
    return Response(
        content=row.raw_yaml or "",
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": f'attachment; filename="{row.sigma_id}.yml"',
        },
    )


# ---- detection effectiveness (outcomes) ----------------------------------

class OutcomeRowOut(BaseModel):
    id: str
    detection_id: str
    kind: str
    summary: Optional[str]
    reference_url: Optional[str]
    author_email: Optional[str]
    observed_at: str


class OutcomeSummaryOut(BaseModel):
    total: int
    tp: int
    fp: int
    unsure: int
    precision: float


class OutcomeIn(BaseModel):
    kind: str  # tp|fp|unsure
    summary: Optional[str] = None
    reference_url: Optional[str] = None


@router.get(
    "/{detection_id}/outcomes",
    response_model=list[OutcomeRowOut],
)
async def list_outcomes_endpoint(
    detection_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[OutcomeRowOut]:
    from app.services.detection_outcomes import list_outcomes

    rows = await list_outcomes(detection_id)
    return [OutcomeRowOut(**r.__dict__) for r in rows]


@router.post(
    "/{detection_id}/outcomes",
    response_model=OutcomeRowOut,
    status_code=201,
)
async def create_outcome_endpoint(
    detection_id: str,
    payload: OutcomeIn,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> OutcomeRowOut:
    from app.services.detection_outcomes import create_outcome

    try:
        out = await create_outcome(
            detection_id,
            kind=payload.kind,
            summary=payload.summary,
            reference_url=payload.reference_url,
            author_email=principal.user.email,
        )
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    if out is None:
        raise HTTPException(422, "invalid detection id")
    return OutcomeRowOut(**out.__dict__)


@router.delete("/outcomes/{outcome_id}")
async def delete_outcome_endpoint(
    outcome_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    from app.services.detection_outcomes import delete_outcome

    if not await delete_outcome(outcome_id):
        raise HTTPException(404, "outcome not found")
    return Response(status_code=204)


@router.get(
    "/{detection_id}/effectiveness",
    response_model=OutcomeSummaryOut,
)
async def effectiveness(
    detection_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> OutcomeSummaryOut:
    from app.services.detection_outcomes import detection_summary

    s = await detection_summary(detection_id)
    return OutcomeSummaryOut(**s.__dict__)


# ---- detection unit tests (event samples) --------------------------------

class SampleOutAPI(BaseModel):
    id: str
    detection_id: str
    label: str
    kind: str
    event: dict
    expected_match: bool
    last_run_at: Optional[str]
    last_run_pass: Optional[bool]
    last_run_message: Optional[str]
    author_email: Optional[str]


class SampleIn(BaseModel):
    label: str
    kind: str  # positive|negative
    event: dict
    expected_match: Optional[bool] = None


class SampleRunOut(BaseModel):
    sample_id: str
    matched: Optional[bool]
    passed: Optional[bool]
    message: str


@router.get(
    "/{detection_id}/samples", response_model=list[SampleOutAPI]
)
async def list_samples_endpoint(
    detection_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[SampleOutAPI]:
    from app.services.detection_samples import list_samples

    rows = await list_samples(detection_id)
    return [SampleOutAPI(**r.__dict__) for r in rows]


@router.post(
    "/{detection_id}/samples",
    response_model=SampleOutAPI,
    status_code=201,
)
async def upsert_sample_endpoint(
    detection_id: str,
    payload: SampleIn,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> SampleOutAPI:
    from app.services.detection_samples import upsert_sample

    try:
        out = await upsert_sample(
            detection_id=detection_id,
            label=payload.label.strip(),
            kind=payload.kind,
            event=payload.event,
            expected_match=payload.expected_match,
            author_email=principal.user.email,
        )
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    return SampleOutAPI(**out.__dict__)


@router.delete("/samples/{sample_id}")
async def delete_sample_endpoint(
    sample_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    from app.services.detection_samples import delete_sample

    if not await delete_sample(sample_id):
        raise HTTPException(404, "sample not found")
    return Response(status_code=204)


@router.post(
    "/{detection_id}/samples/run", response_model=list[SampleRunOut]
)
async def run_samples_endpoint(
    detection_id: str,
    _: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[SampleRunOut]:
    from app.services.detection_samples import run_samples_for_detection

    results = await run_samples_for_detection(detection_id)
    return [SampleRunOut(**r.__dict__) for r in results]


# ---- cross-customer rule promotion ---------------------------------------

class PromotionOut(BaseModel):
    detection_id: str
    sigma_id: str
    title: str
    detection_status: str
    source: str
    source_customer_codename: str
    source_customer_name: str
    same_sector: bool
    techniques: list[str]


@router.get("/suggestions", response_model=list[PromotionOut])
async def suggestions(
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_promotion")),
) -> list[PromotionOut]:
    """Suggested rules from sibling tenants in the same MSSP org.

    Same-sector deployed rules surface first. Read-only — POST to
    `/detections/promote` to actually copy the rule into the active tenant.
    """
    from app.services.cross_promotion import find_suggestions

    if (
        principal.user.role == Role.CUSTOMER_USER
        or principal.user.mssp_org_id is None
        or principal.customer is None
    ):
        return []
    out = await find_suggestions(
        mssp_org_id=str(principal.user.mssp_org_id),
        active_codename=principal.customer.codename,
        active_sector=principal.customer.sector,
        scope=principal.deployment,
        sample_workspace=principal.customer.sample_dataset is not None,
    )
    return [PromotionOut(**s.__dict__) for s in out]


class PromoteIn(BaseModel):
    source_codename: str
    source_detection_id: str


class PromoteOut(BaseModel):
    id: str
    sigma_id: str
    title: str
    source_customer_codename: str
    technique_count: int


# ---- AI-assisted Sigma drafting -----------------------------------------

class AIDraftIn(BaseModel):
    intent: str = ""
    techniques: list[str] = []
    log_source_product: Optional[str] = None
    log_source_category: Optional[str] = None
    log_source_service: Optional[str] = None
    severity: str = "medium"
    fp_notes: str = ""
    reference_urls: list[str] = []


class AIDraftOut(BaseModel):
    yaml: str
    parsed: dict
    attempts: int
    warnings: list[str]


@router.post("/ai-draft", response_model=AIDraftOut)
async def ai_draft(
    payload: AIDraftIn,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("ai_authoring")),
) -> AIDraftOut:
    """Generate a Sigma rule draft from a structured brief.

    Requires an MSSP that has configured AI authoring credentials. The
    draft is validated against pySigma before returning; the UI can then
    let the user save it as a new `custom` detection. We do NOT persist
    the draft here — that's the user's call.
    """
    from app.services.ai_sigma import AISigmaError, draft as ai_draft_fn
    from app.services.ai_sigma_prompt import SigmaBrief
    from app.services.ai_sigma_validate import AISigmaValidationError

    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "AI drafting requires an MSSP user")

    brief = SigmaBrief(
        intent=payload.intent,
        techniques=payload.techniques,
        log_source_product=payload.log_source_product,
        log_source_category=payload.log_source_category,
        log_source_service=payload.log_source_service,
        severity=payload.severity,
        fp_notes=payload.fp_notes,
        reference_urls=payload.reference_urls,
        tenant_codename=principal.customer.codename if principal.customer else None,
    )

    try:
        result = await ai_draft_fn(brief, org_id=principal.user.mssp_org_id)
    except AISigmaValidationError as e:
        raise HTTPException(
            422,
            {
                "detail": "AI failed to produce a valid Sigma rule after retries",
                "errors": e.errors,
            },
        )
    except AISigmaError as e:
        raise HTTPException(400, str(e))

    return AIDraftOut(
        yaml=result.yaml_text,
        parsed=result.parsed_fields,
        attempts=result.attempts,
        warnings=result.warnings,
    )


@router.post("/promote", response_model=PromoteOut, status_code=201)
async def promote_suggestion(
    payload: PromoteIn,
    principal: TenantPrincipal = Depends(require_perm(Permission.DETECTION_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("detection_promotion")),
) -> PromoteOut:
    """Copy a sibling tenant's custom rule into the active tenant.

    Only MSSP users may promote — the boundary is the MSSP org. Customer
    users can't reach other customers anyway because tenant isolation
    pins them to their own schema.
    """
    from app.services.cross_promotion import promote_to_active

    if principal.user.role == Role.CUSTOMER_USER or principal.user.mssp_org_id is None or principal.customer is None:
        raise HTTPException(403, "promotion requires an active MSSP tenant context")
    try:
        out = await promote_to_active(
            mssp_org_id=str(principal.user.mssp_org_id),
            source_codename=payload.source_codename,
            source_detection_id=payload.source_detection_id,
            target_codename=principal.customer.codename,
            scope=principal.deployment,
            actor=principal.user,
        )
    except ValueError as e:
        msg = str(e)
        if "already promoted" in msg:
            raise HTTPException(409, msg) from e
        raise HTTPException(422, msg) from e
    return PromoteOut(**out)


