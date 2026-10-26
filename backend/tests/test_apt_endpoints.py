"""HTTP-level tests for /apt/*, /gaps/*, /posture/* endpoints."""
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


def _client(token: str):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": "acme"},
    )


class TestAPTEndpoints:
    async def test_list_groups_paginates(
        self, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/apt/groups?page_size=10")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["group_id"] == "G9999"

    async def test_group_detail_404(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/apt/groups/G0000")
        assert r.status_code == 404

    async def test_group_detail_shape(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            await _seed_detection("T1003", status="deployed", depth=4)
        finally:
            set_tenant(None)
        async with _client(demo_admin_token) as c:
            r = await c.get("/apt/groups/G9999")
        assert r.status_code == 200
        body = r.json()
        assert body["group_id"] == "G9999"
        assert body["technique_count"] == 4
        assert body["covered_count"] == 1
        assert body["deployed_count"] == 1
        # Cells flat
        cells = {
            t["technique_id"]: t
            for tcells in body["by_tactic"].values()
            for t in tcells
        }
        assert cells["T1003"]["state"] == "deployed"
        assert cells["T1078"]["state"] == "gap"


class TestGapsEndpoint:
    async def test_top_gaps_lists_uncovered_with_apt(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        set_tenant("acme")
        try:
            await _seed_detection("T1059", status="deployed")
        finally:
            set_tenant(None)
        async with _client(demo_admin_token) as c:
            r = await c.get("/gaps/top?limit=10")
        assert r.status_code == 200
        body = r.json()
        ids = sorted(g["technique_id"] for g in body["items"])
        assert ids == ["T1003", "T1078", "T1090"]
        for g in body["items"]:
            assert g["apt_count"] == 1
            assert g["sample_groups"][0]["group_id"] == "G9999"

    async def test_readonly_can_read_gaps(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_readonly_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_readonly_token) as c:
            r = await c.get("/gaps/top")
        assert r.status_code == 200


class TestPostureEndpoint:
    async def test_trend_returns_oldest_to_newest(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        # Drop two snapshots via the API (so taken_at is real).
        async with _client(demo_admin_token) as c:
            r1 = await c.post(
                "/coverage/snapshots",
                json={"domain": "enterprise", "denominator_kind": "full"},
            )
            assert r1.status_code == 201
            r2 = await c.post(
                "/coverage/snapshots",
                json={
                    "domain": "enterprise",
                    "denominator_kind": "apt",
                    "denominator_ref": "G9999",
                },
            )
            assert r2.status_code == 201

            rT = await c.get("/posture/trend")
            assert rT.status_code == 200
            points = rT.json()["points"]
            assert len(points) == 2
            assert points[0]["taken_at"] <= points[1]["taken_at"]

            # Filter by denominator kind narrows the set.
            rT2 = await c.get("/posture/trend?denominator=apt")
            assert rT2.status_code == 200
            apt_pts = rT2.json()["points"]
            assert len(apt_pts) == 1
            assert apt_pts[0]["denominator_kind"] == "apt"
