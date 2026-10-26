"""APT-centric analytics: per-group coverage breakdown + gap ranking.

These read from the public ATT&CK catalog joined against the tenant's
detections (via the existing tenant_session) and roll up to the shapes the
APT, Gaps, and Posture UIs render.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import func, select

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import DetectionTechnique
from app.models.public import (
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackSoftwareTechnique,
    AttackTechnique,
)
from app.services.coverage import (
    CoverageState,
    DenominatorKind,
    _cell_state,
    _fetch_tenant_coverage,
    compute_denominator,
)

log = logging.getLogger(__name__)


@dataclass
class GroupBreakdownTechnique:
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    state: CoverageState
    detection_count: int
    max_depth: int
    sources: list[str]  # "direct" and/or "software:<sid>"


@dataclass
class GroupBreakdown:
    group_id: str
    name: str
    aliases: list[str]
    description: Optional[str]
    technique_count: int
    covered_count: int
    deployed_count: int
    by_tactic: dict[str, list[GroupBreakdownTechnique]] = field(default_factory=dict)


@dataclass
class GapEntry:
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    apt_count: int                 # distinct groups using this TTP (direct ∪ software)
    direct_group_count: int
    software_group_count: int
    sample_groups: list[dict]      # up to 5 {group_id,name} for tooltip
    # In-scope but not covered. We expose detection_count too so the UI can
    # show "0 detections" explicitly.
    detection_count: int


# ---- group breakdown ------------------------------------------------------

async def group_coverage_breakdown(
    domain: str,
    group_id: str,
) -> Optional[GroupBreakdown]:
    """Per-tactic technique list for `group_id` annotated with tenant coverage."""
    async with AsyncSessionLocal() as session:
        group = (
            await session.execute(
                select(AttackGroup).where(
                    AttackGroup.domain == domain,
                    AttackGroup.group_id == group_id,
                )
            )
        ).scalar_one_or_none()
        if group is None:
            return None

        direct_tids = set(
            (
                await session.execute(
                    select(AttackGroupTechnique.technique_id).where(
                        AttackGroupTechnique.domain == domain,
                        AttackGroupTechnique.group_id == group_id,
                    )
                )
            ).scalars().all()
        )

        software_ids = (
            await session.execute(
                select(AttackGroupSoftware.software_id).where(
                    AttackGroupSoftware.domain == domain,
                    AttackGroupSoftware.group_id == group_id,
                )
            )
        ).scalars().all()

        software_tid_rows = []
        if software_ids:
            software_tid_rows = (
                await session.execute(
                    select(
                        AttackSoftwareTechnique.technique_id,
                        AttackSoftwareTechnique.software_id,
                    ).where(
                        AttackSoftwareTechnique.domain == domain,
                        AttackSoftwareTechnique.software_id.in_(software_ids),
                    )
                )
            ).all()
        # source provenance per technique
        sources: dict[str, list[str]] = defaultdict(list)
        for tid in direct_tids:
            sources[tid].append("direct")
        for row in software_tid_rows:
            sources[row.technique_id].append(f"software:{row.software_id}")

        all_tids = set(sources.keys())
        if not all_tids:
            return GroupBreakdown(
                group_id=group.group_id,
                name=group.name,
                aliases=list(group.aliases or []),
                description=group.description,
                technique_count=0,
                covered_count=0,
                deployed_count=0,
                by_tactic={},
            )

        # Technique catalog metadata for all techniques the group touches.
        meta_rows = (
            await session.execute(
                select(
                    AttackTechnique.technique_id,
                    AttackTechnique.name,
                    AttackTechnique.tactics,
                    AttackTechnique.is_subtechnique,
                    AttackTechnique.parent_technique_id,
                ).where(
                    AttackTechnique.domain == domain,
                    AttackTechnique.technique_id.in_(all_tids),
                )
            )
        ).all()
        meta = {r.technique_id: r for r in meta_rows}

    # Tenant-scoped detection state for these techniques.
    async with tenant_session() as session:
        coverage = await _fetch_tenant_coverage(session, all_tids)

    by_tactic: dict[str, list[GroupBreakdownTechnique]] = defaultdict(list)
    covered = 0
    deployed = 0
    for tid in sorted(all_tids):
        m = meta.get(tid)
        c = coverage.get(tid, {})
        state = _cell_state(in_scope=True, statuses=c.get("statuses", []))
        if state in (
            CoverageState.DEPLOYED,
            CoverageState.IN_PROGRESS,
            CoverageState.IDEA,
        ):
            covered += 1
        if state == CoverageState.DEPLOYED:
            deployed += 1

        cell = GroupBreakdownTechnique(
            technique_id=tid,
            name=(m.name if m else tid),
            tactics=list(m.tactics or []) if m else [],
            is_subtechnique=bool(m.is_subtechnique) if m else False,
            parent_technique_id=(m.parent_technique_id if m else None),
            state=state,
            detection_count=c.get("detection_count", 0),
            max_depth=c.get("max_depth", 0),
            sources=sorted(set(sources[tid])),
        )
        tactics = cell.tactics or ["uncategorised"]
        for tac in tactics:
            by_tactic[tac].append(cell)

    return GroupBreakdown(
        group_id=group.group_id,
        name=group.name,
        aliases=list(group.aliases or []),
        description=group.description,
        technique_count=len(all_tids),
        covered_count=covered,
        deployed_count=deployed,
        by_tactic=dict(by_tactic),
    )


# ---- gap ranking ----------------------------------------------------------

async def gap_ranking(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    limit: int = 25,
) -> list[GapEntry]:
    """Return top gaps in the chosen denominator, ranked by APT prevalence.

    A gap is a technique inside the denominator that has zero detections in
    the tenant. APT prevalence = distinct groups whose TTPs (direct OR via
    software they use) include the technique.
    """
    denom = await compute_denominator(domain, kind, ref)
    if not denom:
        return []

    # Tenant-side: which of those have any detection at all?
    async with tenant_session() as session:
        covered_rows = (
            await session.execute(
                select(DetectionTechnique.technique_id)
                .where(DetectionTechnique.technique_id.in_(denom))
                .distinct()
            )
        ).scalars().all()
    covered = set(covered_rows)
    gaps = denom - covered
    if not gaps:
        return []

    async with AsyncSessionLocal() as session:
        # Direct group prevalence per technique.
        direct_rows = (
            await session.execute(
                select(
                    AttackGroupTechnique.technique_id,
                    func.count(func.distinct(AttackGroupTechnique.group_id)).label("n"),
                )
                .where(
                    AttackGroupTechnique.domain == domain,
                    AttackGroupTechnique.technique_id.in_(gaps),
                )
                .group_by(AttackGroupTechnique.technique_id)
            )
        ).all()
        direct_by_tid: dict[str, int] = {r.technique_id: int(r.n) for r in direct_rows}

        # Software prevalence: groups → software → technique.
        # Counted as distinct groups (not distinct software).
        sw_rows = (
            await session.execute(
                select(
                    AttackSoftwareTechnique.technique_id,
                    func.count(
                        func.distinct(AttackGroupSoftware.group_id)
                    ).label("n"),
                )
                .join(
                    AttackGroupSoftware,
                    (AttackGroupSoftware.software_id == AttackSoftwareTechnique.software_id)
                    & (AttackGroupSoftware.domain == AttackSoftwareTechnique.domain),
                )
                .where(
                    AttackSoftwareTechnique.domain == domain,
                    AttackSoftwareTechnique.technique_id.in_(gaps),
                )
                .group_by(AttackSoftwareTechnique.technique_id)
            )
        ).all()
        software_by_tid: dict[str, int] = {r.technique_id: int(r.n) for r in sw_rows}

        # For accurate distinct-groups count we need the union of both sets,
        # which a single SQL would express as a UNION subquery. Approximating
        # via max(direct, software) is wrong; instead we pull the actual
        # group_id sets for ranked candidates only.
        rough_score = {
            tid: direct_by_tid.get(tid, 0) + software_by_tid.get(tid, 0)
            for tid in gaps
        }
        # Take the top N by rough score, then refine to true distinct count.
        top_candidates = sorted(rough_score, key=rough_score.get, reverse=True)[
            : max(limit * 2, limit + 10)
        ]
        if not top_candidates:
            return []

        # Pull all group_ids per top candidate technique (both direct & via software).
        direct_g = (
            await session.execute(
                select(
                    AttackGroupTechnique.technique_id,
                    AttackGroupTechnique.group_id,
                )
                .where(
                    AttackGroupTechnique.domain == domain,
                    AttackGroupTechnique.technique_id.in_(top_candidates),
                )
            )
        ).all()
        sw_g = (
            await session.execute(
                select(
                    AttackSoftwareTechnique.technique_id,
                    AttackGroupSoftware.group_id,
                )
                .join(
                    AttackGroupSoftware,
                    (AttackGroupSoftware.software_id == AttackSoftwareTechnique.software_id)
                    & (AttackGroupSoftware.domain == AttackSoftwareTechnique.domain),
                )
                .where(
                    AttackSoftwareTechnique.domain == domain,
                    AttackSoftwareTechnique.technique_id.in_(top_candidates),
                )
            )
        ).all()

        unique_groups: dict[str, set[str]] = defaultdict(set)
        for r in direct_g:
            unique_groups[r.technique_id].add(r.group_id)
        for r in sw_g:
            unique_groups[r.technique_id].add(r.group_id)

        # Metadata for each candidate technique.
        meta_rows = (
            await session.execute(
                select(
                    AttackTechnique.technique_id,
                    AttackTechnique.name,
                    AttackTechnique.tactics,
                    AttackTechnique.is_subtechnique,
                    AttackTechnique.parent_technique_id,
                ).where(
                    AttackTechnique.domain == domain,
                    AttackTechnique.technique_id.in_(top_candidates),
                )
            )
        ).all()
        meta = {r.technique_id: r for r in meta_rows}

        # Names for the sample groups (so tooltips don't show bare G-IDs).
        all_sample_gids = {g for gs in unique_groups.values() for g in list(gs)[:5]}
        gname_rows = (
            await session.execute(
                select(AttackGroup.group_id, AttackGroup.name).where(
                    AttackGroup.domain == domain,
                    AttackGroup.group_id.in_(all_sample_gids),
                )
            )
        ).all() if all_sample_gids else []
        gnames = {r.group_id: r.name for r in gname_rows}

    entries: list[GapEntry] = []
    for tid in top_candidates:
        groups = unique_groups.get(tid, set())
        m = meta.get(tid)
        sample = sorted(groups)[:5]
        entries.append(
            GapEntry(
                technique_id=tid,
                name=(m.name if m else tid),
                tactics=list(m.tactics or []) if m else [],
                is_subtechnique=bool(m.is_subtechnique) if m else False,
                parent_technique_id=(m.parent_technique_id if m else None),
                apt_count=len(groups),
                direct_group_count=direct_by_tid.get(tid, 0),
                software_group_count=software_by_tid.get(tid, 0),
                sample_groups=[
                    {"group_id": gid, "name": gnames.get(gid, gid)} for gid in sample
                ],
                detection_count=0,
            )
        )

    entries.sort(key=lambda e: (e.apt_count, e.direct_group_count), reverse=True)
    return entries[:limit]


__all__ = [
    "GapEntry",
    "GroupBreakdown",
    "GroupBreakdownTechnique",
    "gap_ranking",
    "group_coverage_breakdown",
]
