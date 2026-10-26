"""Tests for the CMF visibility engine (app/services/cmf_visibility.py).

The bulk are pure-logic tests over the assessment/scoring/recommendation
helpers — no DB, fully deterministic. A light DB + endpoint section exercises
the wiring against the live `acme` tenant (skipped if not provisioned) and
only asserts the robust *positive* direction (collecting a source makes its
technique visible), so pre-existing seeded collection can't make it flaky.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import Asset, AssetDataSource
from app.models.public import AttackTechnique
from app.services.cmf_visibility import (
    DenominatorKind,
    VisibilityState,
    _Assessment,
    _Collected,
    _assess,
    _grade_pct,
    _grade_quality,
    _rank_recommendations,
    _row_quality,
    _summarize,
    compute_recommendations,
    compute_visibility_matrix,
    compute_visibility_score,
)


def _collected(full=(), sources=(), quality=None) -> _Collected:
    return _Collected(
        full=set(full),
        sources=set(sources),
        quality_by_key={k: list(v) for k, v in (quality or {}).items()},
    )


# ---- _assess: the data-source → technique matching core -------------------

class TestAssess:
    def test_no_data_source_is_unassessable(self) -> None:
        a = _assess([], _collected())
        assert a.state is VisibilityState.NO_DATA_SOURCE
        assert a.missing == []

    def test_all_required_collected_is_visible(self) -> None:
        a = _assess(
            ["Process: Process Creation", "Command: Command Execution"],
            _collected(full={"Process: Process Creation", "Command: Command Execution"}),
        )
        assert a.state is VisibilityState.VISIBLE
        assert a.missing == []

    def test_some_required_collected_is_partial(self) -> None:
        a = _assess(
            ["Process: Process Creation", "Command: Command Execution"],
            _collected(full={"Process: Process Creation"}),
        )
        assert a.state is VisibilityState.PARTIAL
        assert a.missing == ["Command: Command Execution"]

    def test_parent_source_without_component_is_partial(self) -> None:
        # We collect the "Process" source but not the specific component.
        a = _assess(
            ["Process: Process Creation"],
            _collected(sources={"Process"}),
        )
        assert a.state is VisibilityState.PARTIAL
        assert a.missing == ["Process: Process Creation"]

    def test_source_level_requirement_met_by_source(self) -> None:
        # Technique requires a bare source (no component) — collecting it = full.
        a = _assess(["Network Traffic"], _collected(sources={"Network Traffic"}))
        assert a.state is VisibilityState.VISIBLE
        assert a.missing == []

    def test_nothing_collected_is_not_collected(self) -> None:
        a = _assess(["Process: Process Creation"], _collected())
        assert a.state is VisibilityState.NOT_COLLECTED
        assert a.missing == ["Process: Process Creation"]

    def test_quality_averages_matching_sources(self) -> None:
        a = _assess(
            ["Process: Process Creation"],
            _collected(
                full={"Process: Process Creation"},
                quality={"Process: Process Creation": [2.0, 4.0]},
            ),
        )
        assert a.state is VisibilityState.VISIBLE
        assert a.quality_avg == 3.0

    def test_quality_none_when_unscored(self) -> None:
        a = _assess(
            ["Process: Process Creation"],
            _collected(full={"Process: Process Creation"}),
        )
        assert a.quality_avg is None


# ---- _row_quality: DeTT&CT dimension averaging ----------------------------

class TestRowQuality:
    def test_mean_of_scored_dimensions(self) -> None:
        row = SimpleNamespace(
            device_completeness_q=4,
            data_field_completeness_q=2,
            timeliness_q=None,
            consistency_q=None,
            retention_q=None,
        )
        assert _row_quality(row) == 3.0

    def test_all_unscored_is_none(self) -> None:
        row = SimpleNamespace(
            device_completeness_q=None,
            data_field_completeness_q=None,
            timeliness_q=None,
            consistency_q=None,
            retention_q=None,
        )
        assert _row_quality(row) is None


# ---- grading --------------------------------------------------------------

class TestGrades:
    def test_pct_grades(self) -> None:
        assert _grade_pct(0.80) == "A"
        assert _grade_pct(0.75) == "A"
        assert _grade_pct(0.60) == "B"
        assert _grade_pct(0.30) == "C"
        assert _grade_pct(0.10) == "D"

    def test_quality_grades(self) -> None:
        assert _grade_quality(4.5) == "A"
        assert _grade_quality(3.0) == "B"
        assert _grade_quality(2.0) == "C"
        assert _grade_quality(1.0) == "D"


# ---- _summarize: pure scoring tally ---------------------------------------

class TestSummarize:
    def test_excludes_no_data_source_from_assessable_base(self) -> None:
        assessments = {
            "T1": _Assessment(VisibilityState.VISIBLE, ["A: B"], [], 4.0),
            "T2": _Assessment(VisibilityState.PARTIAL, ["A: B", "C: D"], ["C: D"], 2.0),
            "T3": _Assessment(VisibilityState.NOT_COLLECTED, ["E: F"], ["E: F"], None),
            "T4": _Assessment(VisibilityState.NO_DATA_SOURCE, [], [], None),
        }
        s = _summarize("enterprise", DenominatorKind.FULL, None, 4, assessments)
        # T4 (no data source) is NOT counted in the assessable base.
        assert s.assessable_count == 3
        assert s.visible_count == 1
        assert s.partial_count == 1
        assert s.not_collected_count == 1
        assert s.no_data_source_count == 1
        # (visible + partial) / assessable = 2/3
        assert round(s.visibility_pct, 3) == round(2 / 3, 3)
        assert round(s.visible_pct, 3) == round(1 / 3, 3)
        # quality avg over T1 + T2 only (T3 has none) = (4.0 + 2.0)/2
        assert s.quality_avg == 3.0
        assert s.quality_grade == "B"

    def test_empty_assessments_grade_d(self) -> None:
        s = _summarize("enterprise", DenominatorKind.FULL, None, 0, {})
        assert s.assessable_count == 0
        assert s.visibility_pct == 0.0
        assert s.visibility_grade == "D"
        assert s.quality_grade == "D"


# ---- _rank_recommendations: pure ranking ----------------------------------

class TestRankRecommendations:
    def test_ranks_by_touches_then_unlocks(self) -> None:
        assessments = {
            # P touches 3 techniques; Q touches 2.
            "T1": _Assessment(VisibilityState.NOT_COLLECTED, ["P: x"], ["P: x"], None),
            "T2": _Assessment(VisibilityState.PARTIAL, ["P: x", "Z: z"], ["P: x"], None),
            "T3": _Assessment(
                VisibilityState.NOT_COLLECTED, ["P: x", "Q: y"], ["P: x", "Q: y"], None
            ),
            "T4": _Assessment(VisibilityState.NOT_COLLECTED, ["Q: y"], ["Q: y"], None),
            # visible / no-data techniques are ignored entirely.
            "T5": _Assessment(VisibilityState.VISIBLE, ["P: x"], [], 5.0),
            "T6": _Assessment(VisibilityState.NO_DATA_SOURCE, [], [], None),
        }
        recs = _rank_recommendations(assessments, limit=10)
        assert recs[0].raw == "P: x"
        assert recs[0].touches == 3
        # T1 and T2 have P as the sole missing → unlocks=2 (T3 has 2 missing).
        assert recs[0].unlocks == 2
        assert recs[0].data_source == "P"
        assert recs[0].data_component == "x"
        # Q: y next — touches 2 (T3, T4), unlocks 1 (T4 sole-missing).
        q = next(r for r in recs if r.raw == "Q: y")
        assert q.touches == 2
        assert q.unlocks == 1
        # "Z: z" is collected for T2 (not in its `missing`) so it's never
        # recommended — only the unmet sources surface.
        assert all(r.raw != "Z: z" for r in recs)

    def test_limit_truncates(self) -> None:
        assessments = {
            f"T{i}": _Assessment(
                VisibilityState.NOT_COLLECTED, [f"S{i}: c"], [f"S{i}: c"], None
            )
            for i in range(10)
        }
        recs = _rank_recommendations(assessments, limit=3)
        assert len(recs) == 3

    def test_samples_capped_and_stable(self) -> None:
        assessments = {
            f"T{i:02d}": _Assessment(
                VisibilityState.NOT_COLLECTED, ["S: c"], ["S: c"], None
            )
            for i in range(8)
        }
        recs = _rank_recommendations(assessments, limit=5)
        assert recs[0].touches == 8
        assert recs[0].sample_technique_ids == ["T00", "T01", "T02", "T03", "T04"]


# ---- DB + endpoint wiring (live acme tenant) ------------------------------


async def _acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        rows = await session.execute(
            select(func.count())
            .select_from(AttackTechnique)
            .where(AttackTechnique.domain == "enterprise")
        )
        if rows.scalar_one() == 0:
            return False
    from sqlalchemy import text

    async with AsyncSessionLocal() as session:
        r = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return r.scalar_one_or_none() is not None


async def _technique_with_fewest_sources() -> tuple[str, list[str]] | None:
    """Find the enterprise technique with the fewest (≥1) data sources, so a
    test can collect *all* of them and assert full visibility. Returns
    (technique_id, [raw_labels]) or None if the catalog isn't seeded."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(AttackTechnique.technique_id, AttackTechnique.data_sources).where(
                    AttackTechnique.domain == "enterprise",
                    AttackTechnique.deprecated.is_(False),
                    AttackTechnique.revoked.is_(False),
                    func.jsonb_array_length(AttackTechnique.data_sources) >= 1,
                )
            )
        ).all()
    best: tuple[str, list[str]] | None = None
    for tid, ds in rows:
        labels = [s for s in (ds or []) if s]
        if labels and (best is None or len(labels) < len(best[1])):
            best = (tid, labels)
    return best


def _client(token: str) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": "acme"},
    )


@pytest_asyncio.fixture
async def acme_cmf_asset():
    """Create a throwaway asset in acme, yield its id, delete it after
    (CASCADE removes its data sources). Skips if acme/catalog absent."""
    if not await _acme_exists():
        pytest.skip("cust_acme schema or ATT&CK catalog not provisioned — run seed_demo")
    asset_id = uuid.uuid4()
    # set_tenant uses a ContextVar that doesn't survive the pytest-asyncio
    # yield boundary, so scope it around each DB block independently.
    set_tenant("acme")
    try:
        async with tenant_session() as session:
            session.add(
                Asset(id=asset_id, name=f"cmf-test-{asset_id.hex[:8]}", kind="server")
            )
    finally:
        set_tenant(None)
    try:
        yield asset_id
    finally:
        set_tenant("acme")
        try:
            async with tenant_session() as session:
                await session.execute(delete(Asset).where(Asset.id == asset_id))
        finally:
            set_tenant(None)


@pytest.mark.asyncio
class TestVisibilityServiceLive:
    async def test_collected_sources_make_technique_visible(
        self, acme_cmf_asset
    ) -> None:
        found = await _technique_with_fewest_sources()
        if not found:
            pytest.skip("no enterprise technique with data sources in catalog")
        tid, labels = found

        set_tenant("acme")
        try:
            async with tenant_session() as session:
                for i, raw in enumerate(labels):
                    src, _, comp = raw.partition(": ")
                    session.add(
                        AssetDataSource(
                            id=uuid.uuid4(),
                            asset_id=acme_cmf_asset,
                            name=f"cmf-test-source-{i}",
                            attack_data_source=src,
                            attack_data_component=comp or None,
                            device_completeness_q=4,
                            enabled=True,
                        )
                    )
            # Scope the denominator to just this technique for determinism.
            matrix = await compute_visibility_matrix(
                "enterprise", DenominatorKind.FULL, None, precomputed_denominator={tid}
            )
            cells = [c for cells in matrix.by_tactic.values() for c in cells]
            assert any(
                c.technique_id == tid and c.state is VisibilityState.VISIBLE
                for c in cells
            )

            score = await compute_visibility_score(
                "enterprise", DenominatorKind.FULL, None, precomputed_denominator={tid}
            )
            assert score.visible_count == 1
            assert score.assessable_count == 1
            assert score.visibility_pct == 1.0
            assert score.quality_avg == 4.0  # device_completeness_q=4, rest unscored

            # A collected source is never recommended.
            recs = await compute_recommendations(
                "enterprise",
                DenominatorKind.FULL,
                None,
                precomputed_denominator={tid},
            )
            assert recs == []
        finally:
            set_tenant(None)

    async def test_endpoints_respond(self, demo_admin_token) -> None:
        if not await _acme_exists():
            pytest.skip("cust_acme schema or ATT&CK catalog not provisioned")
        async with _client(demo_admin_token) as c:
            ov = await c.get("/cmf/overview", params={"domain": "enterprise"})
            assert ov.status_code == 200, ov.text
            body = ov.json()
            assert "score" in body and "top_recommendations" in body
            assert body["score"]["denominator_kind"] == "full"

            m = await c.get("/cmf/visibility/matrix")
            assert m.status_code == 200
            assert "by_tactic" in m.json()

            s = await c.get("/cmf/visibility/score")
            assert s.status_code == 200

            r = await c.get("/cmf/visibility/recommendations", params={"limit": 5})
            assert r.status_code == 200
            assert isinstance(r.json(), list)

    async def test_score_rejects_bad_denominator(self, demo_admin_token) -> None:
        if not await _acme_exists():
            pytest.skip("cust_acme schema or ATT&CK catalog not provisioned")
        async with _client(demo_admin_token) as c:
            r = await c.get("/cmf/visibility/score", params={"denominator": "bogus"})
            assert r.status_code == 422
