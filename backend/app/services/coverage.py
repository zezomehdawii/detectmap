"""Coverage matrix + DeTT&CT-style scoring service.

Three concerns:

1. **Denominator** — which ATT&CK techniques are "in scope" for a customer:
     - full:   all techniques in the domain (excluding deprecated/revoked).
     - sector: curated techniques from public.sector_profiles[customer.sector].
     - apt:    a named group's direct TTPs ∪ TTPs of software the group uses.

2. **Matrix** — for each in-scope technique, what's the coverage state derived
   from the tenant's detections + their technique mappings:
     - not_applicable: detection_status=not_applicable on any covering detection.
     - deployed:       at least one detection in 'deployed' status covers it.
     - in_progress:    in_development or tuning covers it (no deployed).
     - idea:           only 'idea' detections cover it.
     - gap:            in scope, no detection at all.

3. **Score** — DeTT&CT-flavoured posture grade:
     - breadth_pct = covered_techniques / |denominator|  → letter A..D
     - depth_avg   = mean(max(score_depth) per covered technique) → letter A..D
     - posture     = combine via a 2D matrix → letter A..D

All "covered" buckets count toward breadth — a tuning or idea detection means
the analyst is at least aware of the technique. The grade rewards depth on top.
"""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import (
    CoverageSnapshot,
    Detection,
    DetectionStatus,
    DetectionTechnique,
)
from app.models.public import (
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackSoftwareTechnique,
    AttackTechnique,
    SectorProfile,
)

log = logging.getLogger(__name__)


class DenominatorKind(str, Enum):
    FULL = "full"
    SECTOR = "sector"
    APT = "apt"


class CoverageState(str, Enum):
    DEPLOYED = "deployed"
    IN_PROGRESS = "in_progress"
    IDEA = "idea"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"
    OUT_OF_SCOPE = "out_of_scope"


# Standard ATT&CK tactic ordering for the matrix column layout.
TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


@dataclass
class TechniqueCell:
    technique_id: str
    name: str
    parent_technique_id: Optional[str]
    is_subtechnique: bool
    tactics: list[str]
    state: CoverageState
    detection_count: int
    max_depth: int  # 0-5
    deployed_count: int


@dataclass
class CoverageMatrix:
    domain: str
    denominator_kind: DenominatorKind
    denominator_ref: Optional[str]
    technique_count: int
    tactics: list[str]
    by_tactic: dict[str, list[TechniqueCell]] = field(default_factory=dict)


@dataclass
class CoverageScore:
    domain: str
    denominator_kind: DenominatorKind
    denominator_ref: Optional[str]
    denominator_size: int
    covered_count: int
    deployed_count: int
    breadth_pct: float          # 0..1
    depth_avg: float            # 0..5
    breadth_grade: str          # A..D
    depth_grade: str            # A..D
    posture_grade: str          # A..D
    state_counts: dict[str, int]


# ---- denominator ----------------------------------------------------------

async def compute_denominator(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
) -> set[str]:
    """Return the set of in-scope technique IDs for (domain, kind, ref)."""
    if kind == DenominatorKind.FULL:
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(AttackTechnique.technique_id).where(
                        AttackTechnique.domain == domain,
                        AttackTechnique.deprecated.is_(False),
                        AttackTechnique.revoked.is_(False),
                    )
                )
            ).scalars().all()
            return set(rows)

    if kind == DenominatorKind.SECTOR:
        if not ref:
            raise ValueError("sector denominator requires a sector ref")
        async with AsyncSessionLocal() as session:
            profile = (
                await session.execute(
                    select(SectorProfile).where(SectorProfile.sector == ref)
                )
            ).scalar_one_or_none()
            if profile is None:
                return set()
            return {t for t in (profile.technique_ids or [])}

    if kind == DenominatorKind.APT:
        if not ref:
            raise ValueError("apt denominator requires a group ref")
        async with AsyncSessionLocal() as session:
            # Direct TTPs of the group...
            direct = set(
                (
                    await session.execute(
                        select(AttackGroupTechnique.technique_id).where(
                            AttackGroupTechnique.domain == domain,
                            AttackGroupTechnique.group_id == ref,
                        )
                    )
                ).scalars().all()
            )
            # ...union TTPs of software the group uses.
            software_ids = (
                await session.execute(
                    select(AttackGroupSoftware.software_id).where(
                        AttackGroupSoftware.domain == domain,
                        AttackGroupSoftware.group_id == ref,
                    )
                )
            ).scalars().all()
            if software_ids:
                indirect = set(
                    (
                        await session.execute(
                            select(AttackSoftwareTechnique.technique_id).where(
                                AttackSoftwareTechnique.domain == domain,
                                AttackSoftwareTechnique.software_id.in_(software_ids),
                            )
                        )
                    ).scalars().all()
                )
                direct |= indirect
            return direct

    raise ValueError(f"unknown denominator kind: {kind!r}")


# ---- matrix ---------------------------------------------------------------

def _cell_state(
    *,
    in_scope: bool,
    statuses: list[DetectionStatus],
) -> CoverageState:
    if not in_scope:
        return CoverageState.OUT_OF_SCOPE
    if not statuses:
        return CoverageState.GAP
    if DetectionStatus.NOT_APPLICABLE in statuses:
        return CoverageState.NOT_APPLICABLE
    if DetectionStatus.DEPLOYED in statuses:
        return CoverageState.DEPLOYED
    if any(s in statuses for s in (DetectionStatus.IN_DEVELOPMENT, DetectionStatus.TUNING)):
        return CoverageState.IN_PROGRESS
    if DetectionStatus.IDEA in statuses:
        return CoverageState.IDEA
    # statuses = [GAP] only — treat as gap.
    return CoverageState.GAP


async def _fetch_techniques(domain: str) -> dict[str, dict]:
    """Pull the technique catalog metadata for a domain into a {tid: row} map."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(
                    AttackTechnique.technique_id,
                    AttackTechnique.name,
                    AttackTechnique.parent_technique_id,
                    AttackTechnique.is_subtechnique,
                    AttackTechnique.tactics,
                    AttackTechnique.deprecated,
                    AttackTechnique.revoked,
                ).where(
                    AttackTechnique.domain == domain,
                    AttackTechnique.deprecated.is_(False),
                    AttackTechnique.revoked.is_(False),
                )
            )
        ).all()
    return {
        r.technique_id: {
            "name": r.name,
            "parent_technique_id": r.parent_technique_id,
            "is_subtechnique": bool(r.is_subtechnique),
            "tactics": list(r.tactics or []),
        }
        for r in rows
    }


async def _fetch_tenant_coverage(
    session: AsyncSession, technique_ids: Iterable[str]
) -> dict[str, dict]:
    """Aggregate {tid → {statuses, max_depth, detection_count, deployed_count}}."""
    tids = list(technique_ids)
    if not tids:
        return {}
    rows = (
        await session.execute(
            select(
                DetectionTechnique.technique_id,
                Detection.detection_status,
                Detection.score_depth,
            )
            .join(Detection, Detection.id == DetectionTechnique.detection_id)
            .where(DetectionTechnique.technique_id.in_(tids))
        )
    ).all()
    agg: dict[str, dict] = defaultdict(
        lambda: {
            "statuses": [],
            "max_depth": 0,
            "detection_count": 0,
            "deployed_count": 0,
        }
    )
    for r in rows:
        a = agg[r.technique_id]
        a["statuses"].append(r.detection_status)
        a["max_depth"] = max(a["max_depth"], int(r.score_depth or 0))
        a["detection_count"] += 1
        if r.detection_status == DetectionStatus.DEPLOYED:
            a["deployed_count"] += 1
    return dict(agg)


async def compute_matrix(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    precomputed_denominator: Optional[set[str]] = None,
) -> CoverageMatrix:
    """Build the tactic-column / technique-cell matrix for the active tenant.

    Callers can pass `precomputed_denominator` to skip the canonical
    full/sector/apt resolution — used by the custom-denominator endpoint
    which composes a denominator from multiple sources.
    """
    techniques = await _fetch_techniques(domain)
    denom = (
        precomputed_denominator
        if precomputed_denominator is not None
        else await compute_denominator(domain, kind, ref)
    )

    async with tenant_session() as session:
        coverage = await _fetch_tenant_coverage(session, denom)

    by_tactic: dict[str, list[TechniqueCell]] = {t: [] for t in TACTIC_ORDER}

    for tid in sorted(denom):
        meta = techniques.get(tid)
        if meta is None:
            # In scope (by sector/apt list) but missing from the live catalog —
            # surface as a gap cell on a synthetic "uncategorised" bucket.
            by_tactic.setdefault("uncategorised", []).append(
                TechniqueCell(
                    technique_id=tid,
                    name=tid,
                    parent_technique_id=None,
                    is_subtechnique=False,
                    tactics=[],
                    state=CoverageState.GAP if tid not in coverage else CoverageState.IDEA,
                    detection_count=coverage.get(tid, {}).get("detection_count", 0),
                    max_depth=coverage.get(tid, {}).get("max_depth", 0),
                    deployed_count=coverage.get(tid, {}).get("deployed_count", 0),
                )
            )
            continue

        c = coverage.get(tid, {})
        cell = TechniqueCell(
            technique_id=tid,
            name=meta["name"],
            parent_technique_id=meta["parent_technique_id"],
            is_subtechnique=meta["is_subtechnique"],
            tactics=meta["tactics"],
            state=_cell_state(in_scope=True, statuses=c.get("statuses", [])),
            detection_count=c.get("detection_count", 0),
            max_depth=c.get("max_depth", 0),
            deployed_count=c.get("deployed_count", 0),
        )
        if meta["tactics"]:
            for tac in meta["tactics"]:
                by_tactic.setdefault(tac, []).append(cell)
        else:
            by_tactic.setdefault("uncategorised", []).append(cell)

    # Stable order: by parent then technique_id (sub-techniques cluster).
    for tac in by_tactic:
        by_tactic[tac].sort(
            key=lambda c: (c.parent_technique_id or c.technique_id, c.technique_id)
        )

    # Only return tactics that actually have cells.
    tactics_used = [t for t in by_tactic if by_tactic[t]]
    # Stable column order: standard ordering first, then any extras alphabetically.
    extras = sorted(t for t in tactics_used if t not in TACTIC_ORDER)
    ordered = [t for t in TACTIC_ORDER if t in tactics_used] + extras
    return CoverageMatrix(
        domain=domain,
        denominator_kind=kind,
        denominator_ref=ref,
        technique_count=len(denom),
        tactics=ordered,
        by_tactic={t: by_tactic[t] for t in ordered},
    )


# ---- score ----------------------------------------------------------------

def _breadth_grade(pct: float) -> str:
    if pct >= 0.75:
        return "A"
    if pct >= 0.50:
        return "B"
    if pct >= 0.25:
        return "C"
    return "D"


def _depth_grade(avg: float) -> str:
    if avg >= 4.0:
        return "A"
    if avg >= 3.0:
        return "B"
    if avg >= 2.0:
        return "C"
    return "D"


# 2D posture matrix — rows = breadth grade, cols = depth grade. A is the cap.
_POSTURE_MATRIX: dict[tuple[str, str], str] = {
    ("A", "A"): "A", ("A", "B"): "A", ("A", "C"): "B", ("A", "D"): "B",
    ("B", "A"): "A", ("B", "B"): "B", ("B", "C"): "B", ("B", "D"): "C",
    ("C", "A"): "B", ("C", "B"): "C", ("C", "C"): "C", ("C", "D"): "D",
    ("D", "A"): "C", ("D", "B"): "C", ("D", "C"): "D", ("D", "D"): "D",
}


async def compute_score(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    precomputed_denominator: Optional[set[str]] = None,
) -> CoverageScore:
    denom = (
        precomputed_denominator
        if precomputed_denominator is not None
        else await compute_denominator(domain, kind, ref)
    )
    if not denom:
        # Nothing to score — short-circuit before touching the tenant schema.
        return CoverageScore(
            domain=domain,
            denominator_kind=kind,
            denominator_ref=ref,
            denominator_size=0,
            covered_count=0,
            deployed_count=0,
            breadth_pct=0.0,
            depth_avg=0.0,
            breadth_grade="D",
            depth_grade="D",
            posture_grade="D",
            state_counts={s.value: 0 for s in CoverageState},
        )
    async with tenant_session() as session:
        coverage = await _fetch_tenant_coverage(session, denom)

    state_counts: dict[str, int] = defaultdict(int)
    covered = 0
    deployed = 0
    depth_total = 0
    depth_n = 0
    for tid in denom:
        c = coverage.get(tid, {})
        state = _cell_state(in_scope=True, statuses=c.get("statuses", []))
        state_counts[state.value] += 1
        if state in (
            CoverageState.DEPLOYED,
            CoverageState.IN_PROGRESS,
            CoverageState.IDEA,
        ):
            covered += 1
        if state == CoverageState.DEPLOYED:
            deployed += 1
        if c.get("detection_count"):
            depth_total += c.get("max_depth", 0)
            depth_n += 1

    breadth = covered / len(denom)
    depth_avg = (depth_total / depth_n) if depth_n else 0.0
    bg = _breadth_grade(breadth)
    dg = _depth_grade(depth_avg)
    posture = _POSTURE_MATRIX.get((bg, dg), "D")

    return CoverageScore(
        domain=domain,
        denominator_kind=kind,
        denominator_ref=ref,
        denominator_size=len(denom),
        covered_count=covered,
        deployed_count=deployed,
        breadth_pct=breadth,
        depth_avg=depth_avg,
        breadth_grade=bg,
        depth_grade=dg,
        posture_grade=posture,
        state_counts={s.value: state_counts.get(s.value, 0) for s in CoverageState},
    )


# ---- snapshots ------------------------------------------------------------

async def save_snapshot(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    notes: Optional[str] = None,
) -> CoverageSnapshot:
    """Persist a point-in-time roll-up of (matrix + score) for audit history."""
    score = await compute_score(domain, kind, ref)
    matrix = await compute_matrix(domain, kind, ref)
    # Flatten matrix cells to one (technique_id -> state) map so a later
    # snapshot can diff against this one cell-by-cell. Each technique
    # appears once per tactic in by_tactic; collapse to a single entry.
    technique_states: dict[str, str] = {}
    technique_depth: dict[str, int] = {}
    for cells in matrix.by_tactic.values():
        for c in cells:
            technique_states[c.technique_id] = c.state.value
            technique_depth[c.technique_id] = c.max_depth
    payload = {
        "domain": domain,
        "denominator_size": score.denominator_size,
        "breadth_pct": score.breadth_pct,
        "depth_avg": score.depth_avg,
        "covered_count": score.covered_count,
        "deployed_count": score.deployed_count,
        "state_counts": score.state_counts,
        "tactic_counts": {
            tac: len(matrix.by_tactic.get(tac, [])) for tac in matrix.tactics
        },
        # Newer payloads (>= migration 0003) carry per-technique state for
        # the matrix-delta endpoint. Older snapshots lack this key — delta
        # rendering must treat their absence as "no comparison available".
        "technique_states": technique_states,
        "technique_depth": technique_depth,
    }
    async with tenant_session() as session:
        snap = CoverageSnapshot(
            id=uuid.uuid4(),
            denominator_kind=kind.value,
            denominator_ref=ref,
            breadth_score=score.breadth_grade,
            depth_score=score.depth_grade,
            posture_grade=score.posture_grade,
            payload=payload,
            notes=notes,
        )
        session.add(snap)
        await session.flush()
        # Re-load to capture server defaults (taken_at).
        await session.refresh(snap)
        # Detach so callers can read attributes after the session closes.
        session.expunge(snap)
    return snap


async def list_snapshots(*, limit: int = 50) -> list[CoverageSnapshot]:
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(CoverageSnapshot)
                .order_by(CoverageSnapshot.taken_at.desc())
                .limit(limit)
            )
        ).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)


async def delete_snapshot(snapshot_id: uuid.UUID) -> bool:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CoverageSnapshot).where(CoverageSnapshot.id == snapshot_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        return True


async def update_snapshot_notes(
    snapshot_id: uuid.UUID, notes: Optional[str]
) -> Optional[CoverageSnapshot]:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(CoverageSnapshot).where(CoverageSnapshot.id == snapshot_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        row.notes = notes
        await session.flush()
        await session.refresh(row)
        session.expunge(row)
        return row


__all__ = [
    "CoverageMatrix",
    "CoverageScore",
    "CoverageState",
    "DenominatorKind",
    "TACTIC_ORDER",
    "TechniqueCell",
    "compute_denominator",
    "compute_matrix",
    "compute_score",
    "list_snapshots",
    "save_snapshot",
]
