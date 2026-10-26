"""Service-layer tests for GRC seeder + control coverage rollup."""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.models.public import (
    GRCControl,
    GRCFramework,
    GRCTechniqueMapping,
)
from app.services.attack_ingest import refresh_domain
from app.services.grc import (
    ControlCoverageState,
    _rollup_state,
    control_coverage,
    evidence_csv,
    evidence_json,
    evidence_payload,
    framework_summary,
)
from app.services.grc_seed import seed_grc
from app.models.customer import DetectionStatus

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
            {"id": did, "sid": f"sig-{tid}", "title": f"covers {tid}", "status": status, "depth": depth},
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


class TestRollupState:
    """Pure-function checks of the per-control rollup."""

    def _statuses(self, *items: DetectionStatus) -> list[list[DetectionStatus]]:
        # Each technique = list[statuses]. Build one-status-per-technique inputs.
        return [[s] for s in items]

    def test_unmapped(self) -> None:
        assert _rollup_state([]) == ControlCoverageState.UNMAPPED

    def test_all_deployed(self) -> None:
        s = self._statuses(DetectionStatus.DEPLOYED, DetectionStatus.DEPLOYED)
        assert _rollup_state(s) == ControlCoverageState.DEPLOYED

    def test_partial_deployed(self) -> None:
        s = self._statuses(DetectionStatus.DEPLOYED, DetectionStatus.IDEA)
        assert _rollup_state(s) == ControlCoverageState.PARTIAL

    def test_in_progress_short_circuit(self) -> None:
        s = self._statuses(DetectionStatus.TUNING, DetectionStatus.IDEA)
        assert _rollup_state(s) == ControlCoverageState.IN_PROGRESS

    def test_idea_only(self) -> None:
        s = self._statuses(DetectionStatus.IDEA, DetectionStatus.IDEA)
        assert _rollup_state(s) == ControlCoverageState.IDEA

    def test_all_gaps(self) -> None:
        # technique with no detection → empty statuses list
        s = [[], []]
        assert _rollup_state(s) == ControlCoverageState.GAP


@pytest.mark.asyncio
class TestSeeder:
    async def test_seed_is_idempotent(self, clean_grc_tables) -> None:
        r1 = await seed_grc()
        assert r1["frameworks"] == 3
        rows1 = await framework_summary()
        n1 = {r["key"]: r["control_count"] for r in rows1}

        # Re-run: no duplicate frameworks/controls, same counts.
        r2 = await seed_grc()
        assert r2["frameworks"] == 3
        rows2 = await framework_summary()
        n2 = {r["key"]: r["control_count"] for r in rows2}
        assert n1 == n2

    async def test_seed_preserves_user_mappings(self, clean_grc_tables) -> None:
        await seed_grc()
        # Insert a user-owned mapping by hand against PR.AT.
        async with AsyncSessionLocal() as session:
            async with session.begin():
                pr_at = (
                    await session.execute(
                        select(GRCControl)
                        .join(GRCFramework, GRCFramework.id == GRCControl.framework_id)
                        .where(
                            GRCFramework.key == "nist_csf",
                            GRCControl.control_id == "PR.AT",
                        )
                    )
                ).scalar_one()
                session.add(
                    GRCTechniqueMapping(
                        id=uuid.uuid4(),
                        control_id=pr_at.id,
                        domain="enterprise",
                        technique_id="T9999",
                        source="user",
                        rationale="hand-crafted",
                        author="alice@example.test",
                    )
                )
        # Re-run seeder — user row must survive.
        await seed_grc()
        async with AsyncSessionLocal() as session:
            user_rows = (
                await session.execute(
                    select(GRCTechniqueMapping).where(
                        GRCTechniqueMapping.source == "user",
                        GRCTechniqueMapping.technique_id == "T9999",
                    )
                )
            ).scalars().all()
        assert len(user_rows) == 1
        assert user_rows[0].author == "alice@example.test"


@pytest.mark.asyncio
class TestControlCoverage:
    async def test_unknown_framework_returns_none(self, clean_grc_tables) -> None:
        await seed_grc()
        assert (await control_coverage("not-a-framework")) is None

    async def test_rolls_up_tenant_detection_state(
        self, acme_blank, clean_grc_tables, clean_attack_tables, fetch_groups
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        await seed_grc()
        set_tenant("acme")
        try:
            # The fixture has T1003 and T1078 in scope. Seeded NIST CSF
            # PR.AA includes T1078, T1078.004, T1098, T1110. We deploy T1078,
            # which should flip PR.AA's rollup to PARTIAL (some mapped TTPs
            # deployed but not all).
            await _seed_detection("T1078", status="deployed", depth=4)
            cov = await control_coverage("nist_csf")
        finally:
            set_tenant(None)
        assert cov is not None
        by_id = {c.control_id: c for c in cov.controls}
        assert "PR.AA" in by_id
        assert by_id["PR.AA"].state == ControlCoverageState.PARTIAL
        assert by_id["PR.AA"].deployed_count == 1


@pytest.mark.asyncio
class TestEvidenceExports:
    async def test_evidence_payload_shape(
        self, acme_blank, clean_grc_tables
    ) -> None:
        await seed_grc()
        set_tenant("acme")
        try:
            payload = await evidence_payload("nist_csf")
        finally:
            set_tenant(None)
        assert payload is not None
        assert payload["framework"]["key"] == "nist_csf"
        assert "controls" in payload
        assert "counts_by_state" in payload

    async def test_evidence_csv_has_header_and_rows(
        self, acme_blank, clean_grc_tables
    ) -> None:
        await seed_grc()
        set_tenant("acme")
        try:
            payload = await evidence_payload("nist_csf")
        finally:
            set_tenant(None)
        body = evidence_csv(payload)
        lines = body.decode("utf-8").splitlines()
        assert lines[0].startswith("framework,control_id,name,family,state")
        # 24 controls in NIST CSF seed → 24 data rows + 1 header
        assert len(lines) >= 25

    async def test_evidence_json_is_valid_json(
        self, acme_blank, clean_grc_tables
    ) -> None:
        import json
        await seed_grc()
        set_tenant("acme")
        try:
            payload = await evidence_payload("nist_csf")
        finally:
            set_tenant(None)
        body = evidence_json(payload)
        parsed = json.loads(body)
        assert parsed["framework"]["key"] == "nist_csf"
