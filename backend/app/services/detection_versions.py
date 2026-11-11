"""Field snapshots and append-only revisions for detection use cases."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.customer import Detection, DetectionVersion
from app.models.public import User

TRACKED_FIELDS = (
    "title", "description", "sigma_status", "level", "author", "sigma_references",
    "tags", "logsource", "detection", "falsepositives", "raw_yaml",
    "detection_status", "score_breadth", "score_depth", "owner",
)
REVIEW_NEUTRAL_FIELDS = frozenset({"detection_status", "owner"})


def snapshot(row: Detection) -> dict[str, Any]:
    return {field: getattr(row, field) for field in TRACKED_FIELDS}


def field_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    changes = {}
    for field, value in after.items():
        previous = before.get(field)
        if previous != value:
            changes[field] = {
                "before": previous.value if isinstance(previous, Enum) else previous,
                "after": value.value if isinstance(value, Enum) else value,
            }
    return changes


def initial_version(
    row: Detection,
    *,
    fields: dict[str, Any] | None = None,
    actor: User | None = None,
    reason: str = "Baseline recorded when version tracking began for this use case.",
    source: str = "baseline",
) -> DetectionVersion:
    return DetectionVersion(
        detection_id=row.id,
        version=1,
        changed_at=row.last_changed_at,
        changed_by_user_id=actor.id if actor else None,
        changed_by_email=actor.email if actor else None,
        changed_by_name=actor.full_name if actor else None,
        change_reason=reason,
        source=source,
        changes=field_changes({}, snapshot(row) if fields is None else fields),
    )


async def append_version(
    session: AsyncSession,
    row: Detection,
    *,
    before: dict[str, Any],
    changes: dict[str, dict[str, Any]],
    actor: User,
    reason: str,
    source: str = "manual",
) -> None:
    # The caller holds a lock on the detection row (or just inserted the row).
    # Legacy records and catalog templates do not need materialized history
    # until they are edited. Save the original state before incrementing.
    if row.version == 1 and await session.get(DetectionVersion, (row.id, 1)) is None:
        session.add(initial_version(row, fields=before))

    row.version += 1
    row.last_changed_at = datetime.now(timezone.utc)
    session.add(
        DetectionVersion(
            detection_id=row.id,
            version=row.version,
            changed_at=row.last_changed_at,
            changed_by_user_id=actor.id,
            changed_by_email=actor.email,
            changed_by_name=actor.full_name,
            change_reason=reason,
            source=source,
            changes=changes,
        )
    )


async def history_for(session: AsyncSession, row: Detection) -> list[DetectionVersion]:
    history = (
        await session.execute(
            select(DetectionVersion)
            .where(
                DetectionVersion.detection_id == row.id,
                DetectionVersion.version <= row.version,
            )
            .order_by(DetectionVersion.version.desc())
        )
    ).scalars().all()
    return list(history) if history else [initial_version(row)]
