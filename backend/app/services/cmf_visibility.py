"""Collection Management Framework — visibility coverage engine.

This is the analytical backbone of the CMF workspace ("Slice B" in the
roadmap): it answers *what can this customer actually see?* by joining the
collected data sources (`asset_data_sources`) against the ATT&CK data-source
vocabulary each technique carries (`public.attack_techniques.data_sources`,
strings like ``"Process: Process Creation"``).

Where the *coverage* engine (`app/services/coverage.py`) scores **detections**
against techniques, this scores **telemetry** against techniques — the
question the Collection Management Framework exists to answer. The two are
complementary: you can't write a detection for a technique you have no data
to see.

Three derived products, all reusing the FULL/SECTOR/APT denominator from the
coverage service so the in-scope set is consistent across the app:

1. **Matrix** — per-technique visibility state:
     - visible:        every ATT&CK data source the technique needs is collected.
     - partial:        some (but not all) required sources collected, or only the
                       parent source is collected without the specific component.
     - not_collected:  the technique lists data sources, none are collected.
     - no_data_source: ATT&CK lists no data sources for the technique — it cannot
                       be assessed via collection (excluded from the breadth base).
2. **Score** — visibility breadth (% of *assessable* techniques with ≥ partial
   visibility) + an average DeTT&CT data-quality grade across what's collected.
3. **Recommendations** — the data sources you don't collect yet, ranked by how
   many in-scope techniques each would illuminate ("collect Process Creation →
   touches 47 techniques, 9 become fully visible").

Quality uses the five DeTT&CT data-quality dimensions on each
`asset_data_source` row (0–5, NULL = unscored); a row's quality is the mean of
its scored dimensions, and a technique's quality is the mean across the rows
that make it visible.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import Asset, AssetDataSource
from app.models.public import AttackTechnique
from app.services.coverage import (
    TACTIC_ORDER,
    DenominatorKind,
    compute_denominator,
)

log = logging.getLogger(__name__)


class VisibilityState(str, Enum):
    VISIBLE = "visible"
    PARTIAL = "partial"
    NOT_COLLECTED = "not_collected"
    NO_DATA_SOURCE = "no_data_source"
    OUT_OF_SCOPE = "out_of_scope"


# States that count as "we have some telemetry for this technique".
_SEEN_STATES = (VisibilityState.VISIBLE, VisibilityState.PARTIAL)


@dataclass
class VisibilityCell:
    technique_id: str
    name: str
    parent_technique_id: Optional[str]
    is_subtechnique: bool
    tactics: list[str]
    state: VisibilityState
    required: list[str]            # ATT&CK data sources the technique needs
    missing: list[str]             # required sources not (fully) collected
    quality_avg: Optional[float]   # mean DeTT&CT quality of matching sources, 0..5


@dataclass
class VisibilityMatrix:
    domain: str
    denominator_kind: DenominatorKind
    denominator_ref: Optional[str]
    technique_count: int
    tactics: list[str]
    by_tactic: dict[str, list[VisibilityCell]] = field(default_factory=dict)


@dataclass
class VisibilityScore:
    domain: str
    denominator_kind: DenominatorKind
    denominator_ref: Optional[str]
    denominator_size: int
    assessable_count: int          # in-scope techniques that list ≥1 data source
    visible_count: int
    partial_count: int
    not_collected_count: int
    no_data_source_count: int
    visibility_pct: float          # (visible + partial) / assessable, 0..1
    visible_pct: float             # visible / assessable, 0..1
    quality_avg: float             # 0..5 across techniques with quality
    visibility_grade: str          # A..D
    quality_grade: str             # A..D
    state_counts: dict[str, int]


@dataclass
class DataSourceRecommendation:
    raw: str                       # canonical "Source: Component"
    data_source: str
    data_component: Optional[str]
    touches: int                   # in-scope not-yet-visible techniques needing it
    unlocks: int                   # of those, how many become fully visible if added
    sample_technique_ids: list[str]


@dataclass
class CmfOverview:
    domain: str
    denominator_kind: DenominatorKind
    denominator_ref: Optional[str]
    asset_count: int
    assets_by_category: dict[str, int]
    data_source_count: int
    enabled_data_source_count: int
    distinct_attack_sources: int   # distinct ATT&CK data sources actually collected
    scored_source_count: int       # data-source rows with ≥1 quality dimension set
    unscored_source_count: int
    score: VisibilityScore
    top_recommendations: list[DataSourceRecommendation]


# ---- grading (mirrors coverage.py thresholds) -----------------------------

def _grade_pct(pct: float) -> str:
    if pct >= 0.75:
        return "A"
    if pct >= 0.50:
        return "B"
    if pct >= 0.25:
        return "C"
    return "D"


def _grade_quality(avg: float) -> str:
    if avg >= 4.0:
        return "A"
    if avg >= 3.0:
        return "B"
    if avg >= 2.0:
        return "C"
    return "D"


# ---- catalog + collected-source fetch -------------------------------------

async def _fetch_techniques(domain: str) -> dict[str, dict]:
    """Technique catalog metadata + data_sources for a domain → {tid: row}."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(
                    AttackTechnique.technique_id,
                    AttackTechnique.name,
                    AttackTechnique.parent_technique_id,
                    AttackTechnique.is_subtechnique,
                    AttackTechnique.tactics,
                    AttackTechnique.data_sources,
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
            # dedupe preserving order, drop blanks
            "data_sources": [
                s for s in dict.fromkeys(r.data_sources or []) if s and s.strip()
            ],
        }
        for r in rows
    }


def _row_quality(row: AssetDataSource) -> Optional[float]:
    """Mean of the scored DeTT&CT dimensions on a data-source row (None = unscored)."""
    vals = [
        row.device_completeness_q,
        row.data_field_completeness_q,
        row.timeliness_q,
        row.consistency_q,
        row.retention_q,
    ]
    present = [v for v in vals if v is not None]
    return (sum(present) / len(present)) if present else None


@dataclass
class _Collected:
    full: set[str]                       # "Source: Component" keys collected
    sources: set[str]                    # bare "Source" keys collected
    quality_by_key: dict[str, list[float]]  # key → row qualities (full + source keys)


async def _fetch_collected(session: AsyncSession) -> _Collected:
    """Build the set of ATT&CK data sources the tenant actually collects."""
    rows = (
        await session.execute(
            select(AssetDataSource).where(
                AssetDataSource.enabled.is_(True),
                AssetDataSource.attack_data_source.isnot(None),
            )
        )
    ).scalars().all()

    full: set[str] = set()
    sources: set[str] = set()
    quality_by_key: dict[str, list[float]] = defaultdict(list)

    for r in rows:
        src = (r.attack_data_source or "").strip()
        if not src:
            continue
        comp = (r.attack_data_component or "").strip()
        sources.add(src)
        q = _row_quality(r)
        if q is not None:
            quality_by_key[src].append(q)
        if comp:
            full_key = f"{src}: {comp}"
            full.add(full_key)
            if q is not None:
                quality_by_key[full_key].append(q)

    return _Collected(full=full, sources=sources, quality_by_key=quality_by_key)


# ---- per-technique assessment ---------------------------------------------

@dataclass
class _Assessment:
    state: VisibilityState
    required: list[str]
    missing: list[str]
    quality_avg: Optional[float]


def _assess(required: list[str], collected: _Collected) -> _Assessment:
    """Assess one technique's visibility against what the tenant collects."""
    if not required:
        return _Assessment(VisibilityState.NO_DATA_SOURCE, [], [], None)

    full_matched = 0
    any_matched = 0
    missing: list[str] = []
    quals: list[float] = []

    for raw in required:
        src = raw.split(": ", 1)[0].strip()
        has_comp = ": " in raw
        if raw in collected.full:
            full_matched += 1
            any_matched += 1
            quals.extend(collected.quality_by_key.get(raw, []))
        elif src in collected.sources:
            any_matched += 1
            quals.extend(collected.quality_by_key.get(src, []))
            if has_comp:
                # parent source collected but not this specific component
                missing.append(raw)
            else:
                # required is source-level only → fully covered
                full_matched += 1
        else:
            missing.append(raw)

    if full_matched == len(required):
        state = VisibilityState.VISIBLE
    elif any_matched > 0:
        state = VisibilityState.PARTIAL
    else:
        state = VisibilityState.NOT_COLLECTED

    quality_avg = (sum(quals) / len(quals)) if quals else None
    return _Assessment(state, required, missing, quality_avg)


async def _gather(
    domain: str, denom: set[str]
) -> tuple[dict[str, dict], dict[str, _Assessment]]:
    """Resolve catalog metadata + per-technique assessments for the in-scope set."""
    techniques = await _fetch_techniques(domain)
    async with tenant_session() as session:
        collected = await _fetch_collected(session)
    assessments = {
        tid: _assess(techniques.get(tid, {}).get("data_sources", []), collected)
        for tid in denom
    }
    return techniques, assessments


# ---- matrix ---------------------------------------------------------------

async def compute_visibility_matrix(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    precomputed_denominator: Optional[set[str]] = None,
) -> VisibilityMatrix:
    denom = (
        precomputed_denominator
        if precomputed_denominator is not None
        else await compute_denominator(domain, kind, ref)
    )
    techniques, assessments = await _gather(domain, denom)

    by_tactic: dict[str, list[VisibilityCell]] = {t: [] for t in TACTIC_ORDER}
    for tid in sorted(denom):
        meta = techniques.get(tid)
        a = assessments[tid]
        cell = VisibilityCell(
            technique_id=tid,
            name=meta["name"] if meta else tid,
            parent_technique_id=meta["parent_technique_id"] if meta else None,
            is_subtechnique=meta["is_subtechnique"] if meta else False,
            tactics=meta["tactics"] if meta else [],
            state=a.state,
            required=a.required,
            missing=a.missing,
            quality_avg=a.quality_avg,
        )
        tactics = cell.tactics or ["uncategorised"]
        for tac in tactics:
            by_tactic.setdefault(tac, []).append(cell)

    for tac in by_tactic:
        by_tactic[tac].sort(
            key=lambda c: (c.parent_technique_id or c.technique_id, c.technique_id)
        )

    tactics_used = [t for t in by_tactic if by_tactic[t]]
    extras = sorted(t for t in tactics_used if t not in TACTIC_ORDER)
    ordered = [t for t in TACTIC_ORDER if t in tactics_used] + extras
    return VisibilityMatrix(
        domain=domain,
        denominator_kind=kind,
        denominator_ref=ref,
        technique_count=len(denom),
        tactics=ordered,
        by_tactic={t: by_tactic[t] for t in ordered},
    )


# ---- score ----------------------------------------------------------------

def _summarize(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    denominator_size: int,
    assessments: dict[str, _Assessment],
) -> VisibilityScore:
    """Pure tally of assessments → score. No DB; unit-testable in isolation."""
    state_counts: dict[str, int] = defaultdict(int)
    quals: list[float] = []
    for a in assessments.values():
        state_counts[a.state.value] += 1
        if a.state in _SEEN_STATES and a.quality_avg is not None:
            quals.append(a.quality_avg)

    visible = state_counts.get(VisibilityState.VISIBLE.value, 0)
    partial = state_counts.get(VisibilityState.PARTIAL.value, 0)
    not_collected = state_counts.get(VisibilityState.NOT_COLLECTED.value, 0)
    no_ds = state_counts.get(VisibilityState.NO_DATA_SOURCE.value, 0)
    assessable = visible + partial + not_collected

    visibility_pct = ((visible + partial) / assessable) if assessable else 0.0
    visible_pct = (visible / assessable) if assessable else 0.0
    quality_avg = (sum(quals) / len(quals)) if quals else 0.0

    return VisibilityScore(
        domain=domain,
        denominator_kind=kind,
        denominator_ref=ref,
        denominator_size=denominator_size,
        assessable_count=assessable,
        visible_count=visible,
        partial_count=partial,
        not_collected_count=not_collected,
        no_data_source_count=no_ds,
        visibility_pct=visibility_pct,
        visible_pct=visible_pct,
        quality_avg=quality_avg,
        visibility_grade=_grade_pct(visibility_pct),
        quality_grade=_grade_quality(quality_avg) if quals else "D",
        state_counts={s.value: state_counts.get(s.value, 0) for s in VisibilityState},
    )


def _empty_score(
    domain: str, kind: DenominatorKind, ref: Optional[str]
) -> VisibilityScore:
    return _summarize(domain, kind, ref, 0, {})


async def compute_visibility_score(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    precomputed_denominator: Optional[set[str]] = None,
) -> VisibilityScore:
    denom = (
        precomputed_denominator
        if precomputed_denominator is not None
        else await compute_denominator(domain, kind, ref)
    )
    if not denom:
        return _empty_score(domain, kind, ref)
    _, assessments = await _gather(domain, denom)
    return _summarize(domain, kind, ref, len(denom), assessments)


# ---- recommendations ------------------------------------------------------

def _rank_recommendations(
    assessments: dict[str, _Assessment], limit: int
) -> list[DataSourceRecommendation]:
    """Pure ranking of uncollected ATT&CK data sources by how many in-scope
    techniques each would illuminate. ``unlocks`` counts techniques where this
    is the *only* thing missing — adding it flips them to fully visible.
    Iterates ``assessments`` in sorted-tid order so sample lists are stable."""
    touches: dict[str, int] = defaultdict(int)
    unlocks: dict[str, int] = defaultdict(int)
    samples: dict[str, list[str]] = defaultdict(list)

    for tid in sorted(assessments):
        a = assessments[tid]
        if a.state in (VisibilityState.VISIBLE, VisibilityState.NO_DATA_SOURCE):
            continue
        # `missing` is exactly the required sources not (fully) collected.
        sole = len(a.missing) == 1
        for raw in a.missing:
            touches[raw] += 1
            if sole:
                unlocks[raw] += 1
            if len(samples[raw]) < 5:
                samples[raw].append(tid)

    ranked = sorted(
        touches.keys(),
        key=lambda r: (-touches[r], -unlocks[r], r),
    )[: max(0, limit)]

    out: list[DataSourceRecommendation] = []
    for raw in ranked:
        src, _, comp = raw.partition(": ")
        out.append(
            DataSourceRecommendation(
                raw=raw,
                data_source=src.strip(),
                data_component=comp.strip() or None,
                touches=touches[raw],
                unlocks=unlocks[raw],
                sample_technique_ids=samples[raw],
            )
        )
    return out


async def compute_recommendations(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    limit: int = 25,
    precomputed_denominator: Optional[set[str]] = None,
) -> list[DataSourceRecommendation]:
    denom = (
        precomputed_denominator
        if precomputed_denominator is not None
        else await compute_denominator(domain, kind, ref)
    )
    _, assessments = await _gather(domain, denom)
    return _rank_recommendations(assessments, limit)


# ---- overview -------------------------------------------------------------

async def _fetch_collection_stats(session: AsyncSession) -> dict:
    """Raw inventory counts for the overview header — cheap aggregate queries."""
    asset_count = (
        await session.execute(select(func.count()).select_from(Asset))
    ).scalar_one()

    cat_rows = (
        await session.execute(
            select(Asset.cmf_category, func.count()).group_by(Asset.cmf_category)
        )
    ).all()
    assets_by_category = {
        (cat or "uncategorised"): int(n) for cat, n in cat_rows
    }

    ds_total = (
        await session.execute(select(func.count()).select_from(AssetDataSource))
    ).scalar_one()
    ds_enabled = (
        await session.execute(
            select(func.count())
            .select_from(AssetDataSource)
            .where(AssetDataSource.enabled.is_(True))
        )
    ).scalar_one()
    distinct_sources = (
        await session.execute(
            select(func.count(func.distinct(AssetDataSource.attack_data_source))).where(
                AssetDataSource.attack_data_source.isnot(None)
            )
        )
    ).scalar_one()
    scored = (
        await session.execute(
            select(func.count())
            .select_from(AssetDataSource)
            .where(
                AssetDataSource.device_completeness_q.isnot(None)
                | AssetDataSource.data_field_completeness_q.isnot(None)
                | AssetDataSource.timeliness_q.isnot(None)
                | AssetDataSource.consistency_q.isnot(None)
                | AssetDataSource.retention_q.isnot(None)
            )
        )
    ).scalar_one()

    return {
        "asset_count": int(asset_count),
        "assets_by_category": assets_by_category,
        "data_source_count": int(ds_total),
        "enabled_data_source_count": int(ds_enabled),
        "distinct_attack_sources": int(distinct_sources),
        "scored_source_count": int(scored),
        "unscored_source_count": int(ds_total) - int(scored),
    }


async def compute_overview(
    domain: str,
    kind: DenominatorKind,
    ref: Optional[str],
    *,
    recommendation_limit: int = 5,
) -> CmfOverview:
    async with tenant_session() as session:
        stats = await _fetch_collection_stats(session)
    score = await compute_visibility_score(domain, kind, ref)
    recs = await compute_recommendations(
        domain, kind, ref, limit=recommendation_limit
    )
    return CmfOverview(
        domain=domain,
        denominator_kind=kind,
        denominator_ref=ref,
        score=score,
        top_recommendations=recs,
        **stats,
    )


__all__ = [
    "CmfOverview",
    "DataSourceRecommendation",
    "VisibilityCell",
    "VisibilityMatrix",
    "VisibilityScore",
    "VisibilityState",
    "compute_overview",
    "compute_recommendations",
    "compute_visibility_matrix",
    "compute_visibility_score",
]
