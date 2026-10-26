"""Detection effectiveness loop.

Analysts log per-detection event outcomes (true positive / false positive
/ inconclusive). The aggregate ratio answers "is this rule actually
working?" without us doing rule-firing telemetry — analyst eyeballs are
the source of truth for the MVP.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func, select

from app.db.tenant import tenant_session
from app.models.customer import DetectionOutcome


@dataclass
class OutcomeOut:
    id: str
    detection_id: str
    kind: str
    summary: Optional[str]
    reference_url: Optional[str]
    author_email: Optional[str]
    observed_at: str


@dataclass
class OutcomeSummary:
    total: int
    tp: int
    fp: int
    unsure: int
    precision: float  # tp / (tp + fp), 0 when no decided outcomes


def _to_out(r: DetectionOutcome) -> OutcomeOut:
    return OutcomeOut(
        id=str(r.id),
        detection_id=str(r.detection_id),
        kind=r.kind,
        summary=r.summary,
        reference_url=r.reference_url,
        author_email=r.author_email,
        observed_at=r.observed_at.isoformat() if r.observed_at else "",
    )


async def list_outcomes(detection_id: str) -> list[OutcomeOut]:
    try:
        did = uuid.UUID(detection_id)
    except ValueError:
        return []
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(DetectionOutcome)
                .where(DetectionOutcome.detection_id == did)
                .order_by(DetectionOutcome.observed_at.desc())
            )
        ).scalars().all()
        return [_to_out(r) for r in rows]


async def create_outcome(
    detection_id: str,
    *,
    kind: str,
    summary: Optional[str] = None,
    reference_url: Optional[str] = None,
    author_email: Optional[str] = None,
) -> Optional[OutcomeOut]:
    if kind not in {"tp", "fp", "unsure"}:
        raise ValueError(f"invalid outcome kind: {kind!r}")
    try:
        did = uuid.UUID(detection_id)
    except ValueError:
        return None
    async with tenant_session() as session:
        row = DetectionOutcome(
            id=uuid.uuid4(),
            detection_id=did,
            kind=kind,
            summary=summary,
            reference_url=reference_url,
            author_email=author_email,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _to_out(row)


async def delete_outcome(outcome_id: str) -> bool:
    try:
        oid = uuid.UUID(outcome_id)
    except ValueError:
        return False
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(DetectionOutcome).where(DetectionOutcome.id == oid)
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        return True


async def detection_summary(detection_id: str) -> OutcomeSummary:
    try:
        did = uuid.UUID(detection_id)
    except ValueError:
        return OutcomeSummary(0, 0, 0, 0, 0.0)
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(
                    DetectionOutcome.kind, func.count(DetectionOutcome.id)
                )
                .where(DetectionOutcome.detection_id == did)
                .group_by(DetectionOutcome.kind)
            )
        ).all()
    counts = {k: int(c) for k, c in rows}
    tp = counts.get("tp", 0)
    fp = counts.get("fp", 0)
    unsure = counts.get("unsure", 0)
    decided = tp + fp
    return OutcomeSummary(
        total=tp + fp + unsure,
        tp=tp,
        fp=fp,
        unsure=unsure,
        precision=(tp / decided) if decided else 0.0,
    )


__all__ = [
    "OutcomeOut",
    "OutcomeSummary",
    "create_outcome",
    "delete_outcome",
    "detection_summary",
    "list_outcomes",
]
