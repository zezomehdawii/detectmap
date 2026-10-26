"""Integration tests for the ATT&CK ingest service.

These touch a real Postgres via AsyncSessionLocal — they pass when run inside
the backend container where DATABASE_URL points at the docker-compose `db`.
"""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackCatalogVersion,
    AttackMitigation,
    AttackTechnique,
    AttackTechniqueMitigation,
)
from app.services.attack_ingest import parse_bundle, refresh_domain
from tests.conftest import load_bundle

pytestmark = pytest.mark.wipes_db


class TestParseBundle:
    def test_techniques_and_mitigations(self) -> None:
        parsed = parse_bundle("enterprise", load_bundle("enterprise_v1"))
        tids = sorted(t["technique_id"] for t in parsed["techniques"])
        mids = sorted(m["mitigation_id"] for m in parsed["mitigations"])
        rels = sorted(
            (r["technique_id"], r["mitigation_id"]) for r in parsed["relationships"]
        )
        assert tids == ["T1003", "T1059", "T1059.001"]
        assert mids == ["M1040"]
        assert rels == [("T1059", "M1040")]
        assert parsed["version"] == "1.0"

    def test_subtechnique_parent_id(self) -> None:
        parsed = parse_bundle("enterprise", load_bundle("enterprise_v1"))
        sub = next(t for t in parsed["techniques"] if t["technique_id"] == "T1059.001")
        assert sub["is_subtechnique"] is True
        assert sub["parent_technique_id"] == "T1059"


@pytest.mark.asyncio
class TestRefreshDomain:
    async def test_idempotent_upsert(self, clean_attack_tables, fetch_v1) -> None:
        # First ingest seeds the catalog.
        r1 = await refresh_domain("enterprise", fetch_fn=fetch_v1)
        assert r1["no_op"] is False
        assert r1["technique_count"] == 3
        assert r1["mitigation_count"] == 1
        assert r1["relationship_count"] == 1

        async with AsyncSessionLocal() as session:
            tech_count = (
                await session.execute(
                    select(func.count()).select_from(AttackTechnique)
                )
            ).scalar_one()
            ver_count = (
                await session.execute(
                    select(func.count()).select_from(AttackCatalogVersion)
                )
            ).scalar_one()
            mit_count = (
                await session.execute(
                    select(func.count()).select_from(AttackMitigation)
                )
            ).scalar_one()
            rel_count = (
                await session.execute(
                    select(func.count()).select_from(AttackTechniqueMitigation)
                )
            ).scalar_one()
        assert tech_count == 3
        assert ver_count == 1
        assert mit_count == 1
        assert rel_count == 1

        # Re-ingest the same bundle: no duplicate techniques, no new version row.
        r2 = await refresh_domain("enterprise", fetch_fn=fetch_v1)
        assert r2["no_op"] is True

        async with AsyncSessionLocal() as session:
            tech_count2 = (
                await session.execute(
                    select(func.count()).select_from(AttackTechnique)
                )
            ).scalar_one()
            ver_count2 = (
                await session.execute(
                    select(func.count()).select_from(AttackCatalogVersion)
                )
            ).scalar_one()
        assert tech_count2 == 3
        assert ver_count2 == 1

    async def test_diff_v1_to_v2(
        self, clean_attack_tables, fetch_v1, fetch_v2
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_v1)
        r2 = await refresh_domain("enterprise", fetch_fn=fetch_v2)
        assert r2["no_op"] is False

        # v2 bundle should be current; v1 should not be.
        async with AsyncSessionLocal() as session:
            versions = (
                await session.execute(
                    select(AttackCatalogVersion).order_by(
                        AttackCatalogVersion.version
                    )
                )
            ).scalars().all()
        assert [v.version for v in versions] == ["1.0", "2.0"]
        assert [v.is_current for v in versions] == [False, True]

        v2 = versions[1]
        diff = v2.summary["diff"]
        assert "T1078" in diff["added"]
        assert "T1003" in diff["deprecated"]
        renamed_tids = [r["technique_id"] for r in diff["renamed"]]
        assert "T1059" in renamed_tids
        # T1059 renamed: ensure the new name is recorded.
        renamed = next(r for r in diff["renamed"] if r["technique_id"] == "T1059")
        assert renamed["new_name"] == "Command and Scripting Interpreters"
        assert renamed["old_name"] == "Command and Scripting Interpreter"

        # Relationships should reflect v2 (T1059→M1040 + T1078→M1026).
        async with AsyncSessionLocal() as session:
            rels = (
                await session.execute(
                    select(AttackTechniqueMitigation).where(
                        AttackTechniqueMitigation.domain == "enterprise"
                    )
                )
            ).scalars().all()
        pairs = sorted((r.technique_id, r.mitigation_id) for r in rels)
        assert pairs == [("T1059", "M1040"), ("T1078", "M1026")]
