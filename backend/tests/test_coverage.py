"""Unit + integration tests for app/services/coverage.py.

Service-layer tests against seeded acme schema + the catalog tables.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.models.customer import DetectionStatus
from app.services.attack_ingest import refresh_domain
from app.services.coverage import (
    CoverageState,
    DenominatorKind,
    _breadth_grade,
    _depth_grade,
    _POSTURE_MATRIX,
    compute_denominator,
    compute_matrix,
    compute_score,
    save_snapshot,
)
from app.services.sector_profiles import seed_sector_profiles

pytestmark = pytest.mark.wipes_db


async def _ensure_acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return row.scalar_one_or_none() is not None


async def _wipe_acme_detections() -> None:
    async with tenant_session() as session:
        await session.execute(text("DELETE FROM detection_techniques"))
        await session.execute(text("DELETE FROM detections"))
        await session.execute(text("DELETE FROM coverage_snapshots"))


async def _seed_detections(detections: list[dict]) -> dict[str, uuid.UUID]:
    """Create detections + technique mappings in cust_acme. Returns {sigma_id: uuid}."""
    ids: dict[str, uuid.UUID] = {}
    async with tenant_session() as session:
        for d in detections:
            did = uuid.uuid4()
            ids[d["sigma_id"]] = did
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
                    "sid": d["sigma_id"],
                    "title": d.get("title", d["sigma_id"]),
                    "status": d["status"],
                    "depth": d.get("depth", 0),
                },
            )
            for tid in d["techniques"]:
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
    return ids


@pytest.fixture
async def acme_blank():
    if not await _ensure_acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    set_tenant("acme")
    try:
        await _wipe_acme_detections()
    finally:
        set_tenant(None)
    yield
    set_tenant("acme")
    try:
        await _wipe_acme_detections()
    finally:
        set_tenant(None)


class TestGradeBucketing:
    def test_breadth_grades(self) -> None:
        assert _breadth_grade(0.90) == "A"
        assert _breadth_grade(0.75) == "A"
        assert _breadth_grade(0.74) == "B"
        assert _breadth_grade(0.50) == "B"
        assert _breadth_grade(0.40) == "C"
        assert _breadth_grade(0.25) == "C"
        assert _breadth_grade(0.10) == "D"
        assert _breadth_grade(0.0) == "D"

    def test_depth_grades(self) -> None:
        assert _depth_grade(4.0) == "A"
        assert _depth_grade(3.5) == "B"
        assert _depth_grade(3.0) == "B"
        assert _depth_grade(2.5) == "C"
        assert _depth_grade(2.0) == "C"
        assert _depth_grade(1.0) == "D"

    def test_posture_matrix_caps_at_a(self) -> None:
        # AA → A; DD → D; mixed favours the worse axis but never punishes too hard
        assert _POSTURE_MATRIX[("A", "A")] == "A"
        assert _POSTURE_MATRIX[("D", "D")] == "D"
        assert _POSTURE_MATRIX[("A", "D")] == "B"
        assert _POSTURE_MATRIX[("D", "A")] == "C"


@pytest.mark.asyncio
class TestDenominator:
    async def test_full_denominator_uses_live_catalog(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        denom = await compute_denominator(
            "enterprise", DenominatorKind.FULL, None
        )
        # 4 attack-patterns in the fixture (T1059, T1003, T1078, T1090)
        assert denom == {"T1059", "T1003", "T1078", "T1090"}

    async def test_apt_denominator_unions_software_ttps(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        denom = await compute_denominator(
            "enterprise", DenominatorKind.APT, "G9999"
        )
        # G9999 directly uses T1078, T1003 (group_techniques)
        # plus its software (S9001 uses T1059, S9002 uses T1090)
        assert denom == {"T1078", "T1003", "T1059", "T1090"}

    async def test_apt_denominator_missing_group_returns_empty(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        denom = await compute_denominator(
            "enterprise", DenominatorKind.APT, "G0000"
        )
        assert denom == set()

    async def test_sector_denominator_reads_profile(
        self, clean_sector_profiles
    ) -> None:
        await seed_sector_profiles()
        denom = await compute_denominator(
            "enterprise", DenominatorKind.SECTOR, "finance"
        )
        # Some hand-curated finance techniques (we don't pin the exact list)
        assert "T1566" in denom
        assert "T1003" in denom
        assert len(denom) > 20

    async def test_sector_denominator_unknown_returns_empty(
        self, clean_sector_profiles
    ) -> None:
        await seed_sector_profiles()
        denom = await compute_denominator(
            "enterprise", DenominatorKind.SECTOR, "no-such-sector"
        )
        assert denom == set()


@pytest.mark.asyncio
class TestMatrixAndScore:
    async def test_matrix_state_derivation(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        # T1059: deployed detection. T1003: tuning. T1078: idea only. T1090: no detection.
        set_tenant("acme")
        try:
            await _seed_detections(
                [
                    {"sigma_id": "d1", "techniques": ["T1059"], "status": "deployed", "depth": 4},
                    {"sigma_id": "d2", "techniques": ["T1003"], "status": "tuning", "depth": 2},
                    {"sigma_id": "d3", "techniques": ["T1078"], "status": "idea", "depth": 0},
                ]
            )
            matrix = await compute_matrix(
                "enterprise", DenominatorKind.FULL, None
            )
        finally:
            set_tenant(None)

        # Flatten cells across tactics → first one per technique is fine because
        # the fixture techniques each have exactly one tactic.
        cells = {
            c.technique_id: c
            for tac_cells in matrix.by_tactic.values()
            for c in tac_cells
        }
        assert cells["T1059"].state == CoverageState.DEPLOYED
        assert cells["T1059"].max_depth == 4
        assert cells["T1003"].state == CoverageState.IN_PROGRESS
        assert cells["T1078"].state == CoverageState.IDEA
        assert cells["T1090"].state == CoverageState.GAP

    async def test_score_buckets_breadth_and_depth(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            # 3 of 4 covered → breadth 75% = A; depths {4,3,2}/3 → ~3.0 = B
            await _seed_detections(
                [
                    {"sigma_id": "d1", "techniques": ["T1059"], "status": "deployed", "depth": 4},
                    {"sigma_id": "d2", "techniques": ["T1003"], "status": "deployed", "depth": 3},
                    {"sigma_id": "d3", "techniques": ["T1078"], "status": "deployed", "depth": 2},
                ]
            )
            score = await compute_score(
                "enterprise", DenominatorKind.FULL, None
            )
        finally:
            set_tenant(None)

        assert score.denominator_size == 4
        assert score.covered_count == 3
        assert score.deployed_count == 3
        assert score.breadth_grade == "A"
        assert score.depth_grade == "B"
        assert score.posture_grade == "A"
        assert score.state_counts["deployed"] == 3
        assert score.state_counts["gap"] == 1

    async def test_score_empty_denominator_returns_d(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        # No data for ics in the fixture → empty denominator.
        score = await compute_score("ics", DenominatorKind.FULL, None)
        assert score.denominator_size == 0
        assert score.breadth_grade == "D"
        assert score.depth_grade == "D"
        assert score.posture_grade == "D"


@pytest.mark.asyncio
class TestSnapshots:
    async def test_save_and_list_snapshot(
        self, acme_blank, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            await _seed_detections(
                [
                    {"sigma_id": "d1", "techniques": ["T1059"], "status": "deployed", "depth": 3},
                ]
            )
            snap = await save_snapshot(
                "enterprise",
                DenominatorKind.FULL,
                None,
                notes="phase4-test",
            )
        finally:
            set_tenant(None)
        assert snap.denominator_kind == "full"
        assert snap.breadth_score in ("A", "B", "C", "D")
        assert snap.depth_score in ("A", "B", "C", "D")
        assert snap.posture_grade in ("A", "B", "C", "D")
        # payload captured aggregate state
        assert snap.payload["denominator_size"] == 4
        assert snap.payload["deployed_count"] == 1
        assert snap.notes == "phase4-test"
