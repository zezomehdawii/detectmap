"""HTTP-level tests for /coverage/* endpoints — RBAC, denominator selection,
and snapshot CRUD via the ASGI transport.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.services.attack_ingest import refresh_domain
from app.services.sector_profiles import seed_sector_profiles

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
        await session.execute(text("DELETE FROM coverage_snapshots"))


@pytest_asyncio.fixture
async def acme_clean():
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


async def _seed_one(tid: str, status: str = "deployed", depth: int = 3) -> None:
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


def _client(token: str):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": "acme"},
    )


class TestCoverageRBAC:
    async def test_score_requires_active_customer(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        # No X-Customer header → 400 from require_active_customer
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/coverage/score")
        assert r.status_code == 400

    async def test_readonly_can_read(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_readonly_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_readonly_token) as c:
            r = await c.get("/coverage/score")
        assert r.status_code == 200


class TestCoverageMatrix:
    async def test_matrix_returns_tactic_grouped_cells(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            await _seed_one("T1059", status="deployed", depth=3)
        finally:
            set_tenant(None)

        async with _client(demo_admin_token) as c:
            r = await c.get("/coverage/matrix?denominator=full&domain=enterprise")
        assert r.status_code == 200
        body = r.json()
        assert body["technique_count"] == 4
        # The execution tactic should contain T1059 with state=deployed.
        cells = body["by_tactic"].get("execution", [])
        by_tid = {c["technique_id"]: c for c in cells}
        assert "T1059" in by_tid
        assert by_tid["T1059"]["state"] == "deployed"
        assert by_tid["T1059"]["max_depth"] == 3
        # A gap technique (T1078) should be present under initial-access as 'gap'
        ia = body["by_tactic"].get("initial-access", [])
        by_tid_ia = {c["technique_id"]: c for c in ia}
        assert by_tid_ia["T1078"]["state"] == "gap"

    async def test_apt_denominator_via_endpoint(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/coverage/score?denominator=apt&ref=G9999")
        assert r.status_code == 200
        body = r.json()
        # G9999 direct (T1003, T1078) + software (T1059, T1090) = 4 techniques
        assert body["denominator_size"] == 4

    async def test_sector_denominator_via_endpoint(
        self,
        acme_clean,
        clean_attack_tables,
        clean_sector_profiles,
        fetch_groups,
        demo_admin_token,
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        await seed_sector_profiles()
        async with _client(demo_admin_token) as c:
            r = await c.get("/coverage/score?denominator=sector&ref=finance")
        assert r.status_code == 200
        body = r.json()
        assert body["denominator_kind"] == "sector"
        assert body["denominator_ref"] == "finance"
        # The seeded finance profile has more than 20 techniques.
        assert body["denominator_size"] > 20


class TestSnapshotsEndpoint:
    async def test_create_and_list_snapshot(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/coverage/snapshots",
                json={"domain": "enterprise", "denominator_kind": "full"},
            )
            assert r.status_code == 201
            body = r.json()
            assert body["denominator_kind"] == "full"
            assert body["posture_grade"] in ("A", "B", "C", "D")

            r2 = await c.get("/coverage/snapshots")
        assert r2.status_code == 200
        rows = r2.json()
        assert len(rows) >= 1
        assert rows[0]["id"] == body["id"]


class TestReferenceEndpoints:
    async def test_list_groups(
        self, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/coverage/groups?q=test")
        assert r.status_code == 200
        names = [g["name"] for g in r.json()]
        assert "TestGroup" in names

    async def test_list_sectors(
        self, clean_sector_profiles, demo_admin_token
    ) -> None:
        await seed_sector_profiles()
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/coverage/sectors")
        assert r.status_code == 200
        sectors = [s["sector"] for s in r.json()]
        for s in ("finance", "healthcare", "energy", "retail", "government"):
            assert s in sectors
