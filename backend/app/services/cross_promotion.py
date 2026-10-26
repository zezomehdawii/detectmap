"""Cross-customer rule promotion.

When an MSSP analyst writes a `custom` detection for one customer, the
same rule is likely useful for sibling customers in the portfolio —
especially same-sector ones. This service surfaces those candidates to
the currently active tenant.

The active tenant only sees the rule's title, source customer codename,
status, and the techniques it covers. Full Sigma YAML is not exposed
through this endpoint — the analyst has to "Import" it (a UI action
that re-fetches the YAML via the existing detection endpoint while
swapped into the source tenant). This keeps the cross-tenant boundary
intentional: read-only metadata only.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.models.customer import Detection, DetectionSource, DetectionStatus, DetectionTechnique
from app.models.public import Customer


@dataclass
class PromotionSuggestion:
    detection_id: str
    sigma_id: str
    title: str
    detection_status: str
    source: str
    source_customer_codename: str
    source_customer_name: str
    same_sector: bool
    techniques: list[str]


async def find_suggestions(
    *,
    mssp_org_id: str,
    active_codename: str,
    active_sector: Optional[str],
    limit: int = 20,
) -> list[PromotionSuggestion]:
    try:
        org_uuid = uuid.UUID(mssp_org_id)
    except ValueError:
        return []

    async with AsyncSessionLocal() as session:
        siblings = (
            await session.execute(
                select(Customer).where(
                    Customer.mssp_org_id == org_uuid,
                    Customer.codename != active_codename,
                )
            )
        ).scalars().all()

    # Snapshot the active tenant's existing sigma_ids so we don't surface rules
    # the analyst already has.
    set_tenant(active_codename)
    try:
        async with tenant_session() as session:
            existing_sigma_ids = set(
                (
                    await session.execute(select(Detection.sigma_id))
                ).scalars().all()
            )
    finally:
        set_tenant(None)

    suggestions: list[PromotionSuggestion] = []
    for cust in siblings:
        set_tenant(cust.codename)
        try:
            async with tenant_session() as session:
                rows = (
                    await session.execute(
                        select(Detection).where(
                            Detection.source.in_(
                                [DetectionSource.CUSTOM, DetectionSource.CUSTOMIZED]
                            ),
                            Detection.detection_status.in_(
                                [
                                    DetectionStatus.DEPLOYED,
                                    DetectionStatus.TUNING,
                                    DetectionStatus.IN_DEVELOPMENT,
                                ]
                            ),
                        )
                    )
                ).scalars().all()
                if not rows:
                    continue
                # batch-fetch technique mappings for these detections
                det_ids = [r.id for r in rows]
                tech_rows = (
                    await session.execute(
                        select(
                            DetectionTechnique.detection_id,
                            DetectionTechnique.technique_id,
                        ).where(DetectionTechnique.detection_id.in_(det_ids))
                    )
                ).all()
                techs_by_id: dict[uuid.UUID, list[str]] = {}
                for did, tid in tech_rows:
                    techs_by_id.setdefault(did, []).append(tid)

                for r in rows:
                    if r.sigma_id in existing_sigma_ids:
                        continue
                    suggestions.append(
                        PromotionSuggestion(
                            detection_id=str(r.id),
                            sigma_id=r.sigma_id,
                            title=r.title,
                            detection_status=r.detection_status.value,
                            source=r.source.value,
                            source_customer_codename=cust.codename,
                            source_customer_name=cust.name,
                            same_sector=bool(
                                active_sector
                                and cust.sector
                                and active_sector == cust.sector
                            ),
                            techniques=techs_by_id.get(r.id, []),
                        )
                    )
        finally:
            set_tenant(None)

    # Prefer same-sector, then deployed, then most techniques covered.
    suggestions.sort(
        key=lambda s: (
            not s.same_sector,
            s.detection_status != "deployed",
            -len(s.techniques),
        )
    )
    return suggestions[:limit]


async def promote_to_active(
    *,
    mssp_org_id: str,
    source_codename: str,
    source_detection_id: str,
    target_codename: str,
) -> dict:
    """Copy a detection from one sibling tenant to another within the same MSSP.

    The destination row is created as `source=custom` (or `customized` if
    the source was customized). It gets a fresh UUID PK, a new sigma_id
    suffixed with `-from-<src_codename>` so it can never collide with
    upstream global rules, and preserves YAML + tags + technique mappings.
    Existing target rows with the same sigma_id (i.e. already promoted)
    are rejected with a 409 — the user can edit afterward instead.
    """
    try:
        org_uuid = uuid.UUID(mssp_org_id)
        src_uuid = uuid.UUID(source_detection_id)
    except ValueError as e:
        raise ValueError("invalid id") from e

    async with AsyncSessionLocal() as session:
        cust_rows = (
            await session.execute(
                select(Customer).where(
                    Customer.mssp_org_id == org_uuid,
                    Customer.codename.in_([source_codename, target_codename]),
                )
            )
        ).scalars().all()
    by_code = {c.codename: c for c in cust_rows}
    if source_codename not in by_code or target_codename not in by_code:
        raise ValueError("one or both customers not in your MSSP org")
    if source_codename == target_codename:
        raise ValueError("source and target customers must differ")

    # Read source rule and its technique mappings.
    set_tenant(source_codename)
    try:
        async with tenant_session() as session:
            src = (
                await session.execute(
                    select(Detection).where(Detection.id == src_uuid)
                )
            ).scalar_one_or_none()
            if src is None:
                raise ValueError("source detection not found")
            tech_rows = (
                await session.execute(
                    select(DetectionTechnique.technique_id).where(
                        DetectionTechnique.detection_id == src_uuid
                    )
                )
            ).scalars().all()
            src_snap = {
                "sigma_id": src.sigma_id,
                "title": src.title,
                "description": src.description,
                "sigma_status": src.sigma_status,
                "level": src.level,
                "author": src.author,
                "sigma_references": list(src.sigma_references or []),
                "tags": list(src.tags or []),
                "logsource": dict(src.logsource or {}),
                "detection": dict(src.detection or {}),
                "falsepositives": list(src.falsepositives or []),
                "raw_yaml": src.raw_yaml,
                "score_breadth": src.score_breadth,
                "score_depth": src.score_depth,
                "source": src.source.value,
                "techniques": list(tech_rows),
            }
    finally:
        set_tenant(None)

    # Write into target tenant.
    new_sigma_id = f"{src_snap['sigma_id']}-from-{source_codename}"
    set_tenant(target_codename)
    try:
        async with tenant_session() as session:
            existing = (
                await session.execute(
                    select(Detection).where(Detection.sigma_id == new_sigma_id)
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise ValueError(
                    f"detection already promoted from {source_codename!r}",
                )
            new_det = Detection(
                id=uuid.uuid4(),
                sigma_id=new_sigma_id,
                title=f"[{source_codename}] {src_snap['title']}",
                description=src_snap["description"],
                sigma_status=src_snap["sigma_status"],
                level=src_snap["level"],
                author=src_snap["author"],
                sigma_references=src_snap["sigma_references"],
                tags=src_snap["tags"],
                logsource=src_snap["logsource"],
                detection=src_snap["detection"],
                falsepositives=src_snap["falsepositives"],
                raw_yaml=src_snap["raw_yaml"],
                detection_status=DetectionStatus.IDEA,
                source=DetectionSource.CUSTOM,
                score_breadth=src_snap["score_breadth"],
                score_depth=0,  # reset depth — needs tuning in the new tenant
                upstream_global_id=None,
            )
            session.add(new_det)
            await session.flush()
            for tid in src_snap["techniques"]:
                session.add(
                    DetectionTechnique(
                        id=uuid.uuid4(),
                        detection_id=new_det.id,
                        technique_id=tid,
                        domain="enterprise",
                    )
                )
            await session.flush()
            return {
                "id": str(new_det.id),
                "sigma_id": new_det.sigma_id,
                "title": new_det.title,
                "source_customer_codename": source_codename,
                "technique_count": len(src_snap["techniques"]),
            }
    finally:
        set_tenant(None)


__all__ = ["PromotionSuggestion", "find_suggestions", "promote_to_active"]
