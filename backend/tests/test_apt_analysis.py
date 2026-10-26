"""Service-layer tests for app.services.apt_analysis."""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.services.apt_analysis import gap_ranking, group_coverage_breakdown
from app.services.attack_ingest import refresh_domain
from app.services.coverage import CoverageState, DenominatorKind

pytestmark = pytest.mark.wipes_db


async def _ensure_acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return row.scalar_one_or_none() is not None


async def _wipe_acme() -> None:
    async with tenant_session() as session:
        await session.execute(text("DELETE FROM detection_techniques"))
        await session.execute(text("DELETE FROM detections"))


async def _seed_detection(tid: str, status: str = "deployed", depth: int = 3) -> None:
    async with tenant_session() as session:
        did = uuid.uuid4()
        await session.execute(
            text(
                """
                INSERT INTO detections
                  (id, sigma_id, title, sigma_references, tags, logsource,
                   detection, falsepositives, detection_status, source,
                   score_breadth, score_depth)
                VALUES
                  (:id, :sid, :title, '[]'::jsonb, '[]'::jsonb,
                   '{}'::jsonb, '{}'::jsonb, '[]'::jsonb,
                   :status, 'custom', 0, :depth)
                """
            ),
            {
                "id": did,
                "sid": f"sig-{tid}",
                "title": f"covers {tid}",
                "status": status,
                "depth": depth,
            },
        )
        await session.execute(
            text(
                """
                INSERT INTO detection_techniques
                  (id, detection_id, technique_id, domain)
                VALUES (:id, :did, :tid, 'enterprise')
                """
            ),
            {"id": uuid.uuid4(), "did": did, "tid": tid},
        )


@pytest_asyncio.fixture
async def acme_blank():
    if not await _ensure_acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    set_tenant("acme")
    try:
        await _wipe_acme()
    finally:
        set_tenant(None)
    yield
    set_tenant("acme")
    try:
        await _wipe_acme()
    finally:
        set_tenant(None)


@pytest.mark.asyncio
class TestGroupBreakdown:
    async def test_unknown_group_returns_none(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        result = await group_coverage_breakdown("enterprise", "G0000")
        assert result is None

    async def test_breakdown_unions_direct_and_software(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            await _seed_detection("T1059", status="deployed", depth=4)
            await _seed_detection("T1078", status="idea", depth=0)
            result = await group_coverage_breakdown("enterprise", "G9999")
        finally:
            set_tenant(None)

        assert result is not None
        assert result.group_id == "G9999"
        # 2 direct (T1003, T1078) + 2 software-derived (T1059, T1090) = 4
        assert result.technique_count == 4
        # Covered: T1059 (deployed), T1078 (idea) = 2
        assert result.covered_count == 2
        assert result.deployed_count == 1

        # Flatten by technique
        cells = {
            t.technique_id: t
            for tcells in result.by_tactic.values()
            for t in tcells
        }
        assert cells["T1059"].state == CoverageState.DEPLOYED
        assert cells["T1059"].max_depth == 4
        assert cells["T1078"].state == CoverageState.IDEA
        assert cells["T1003"].state == CoverageState.GAP
        assert cells["T1090"].state == CoverageState.GAP

        # Sources: direct vs software
        assert "direct" in cells["T1003"].sources
        assert any(s.startswith("software:") for s in cells["T1059"].sources)


@pytest.mark.asyncio
class TestGapRanking:
    async def test_ranks_uncovered_by_apt_prevalence(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        # Cover T1059. The remaining 3 (T1003, T1078, T1090) become gaps.
        # Only T1003 and T1078 are used by G9999 directly. T1090 is via software.
        set_tenant("acme")
        try:
            await _seed_detection("T1059", status="deployed")
            gaps = await gap_ranking(
                "enterprise", DenominatorKind.FULL, None, limit=10
            )
        finally:
            set_tenant(None)
        ids = [g.technique_id for g in gaps]
        # T1059 is covered → should NOT appear
        assert "T1059" not in ids
        # All three gap techniques present
        assert sorted(ids) == ["T1003", "T1078", "T1090"]
        # Each gap is leveraged by G9999 (either direct or via software)
        for g in gaps:
            assert g.apt_count == 1
            assert g.sample_groups[0]["group_id"] == "G9999"

    async def test_empty_when_all_covered(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            for tid in ("T1059", "T1003", "T1078", "T1090"):
                await _seed_detection(tid, status="deployed")
            gaps = await gap_ranking(
                "enterprise", DenominatorKind.FULL, None, limit=10
            )
        finally:
            set_tenant(None)
        assert gaps == []

    async def test_apt_denominator_only_counts_in_scope(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        # With APT denominator the gap pool equals the in-scope TTPs not yet
        # covered. We cover one — expect the other 3.
        set_tenant("acme")
        try:
            await _seed_detection("T1003", status="deployed")
            gaps = await gap_ranking(
                "enterprise", DenominatorKind.APT, "G9999", limit=10
            )
        finally:
            set_tenant(None)
        ids = sorted(g.technique_id for g in gaps)
        assert ids == ["T1059", "T1078", "T1090"]
