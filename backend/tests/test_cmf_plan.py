"""End-to-end tests for the CMF lifecycle endpoints (requirements + plan).

Uses the live `acme` tenant. Each test wipes acme's collection_requirements /
collection_plan_items before+after so the shared dev DB stays clean. Skips if
acme isn't provisioned.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import CollectionPlanItem, CollectionRequirement


def _client(token: str, customer: str = "acme") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": customer},
    )


async def _acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        r = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return r.scalar_one_or_none() is not None


async def _wipe() -> None:
    set_tenant("acme")
    try:
        async with tenant_session() as session:
            await session.execute(delete(CollectionPlanItem))
            await session.execute(delete(CollectionRequirement))
    finally:
        set_tenant(None)


@pytest_asyncio.fixture
async def acme_clean_cmf():
    if not await _acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    await _wipe()
    yield
    await _wipe()


# ---- requirements ---------------------------------------------------------


class TestRequirements:
    async def test_create_list_patch_delete(self, acme_clean_cmf, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/cmf/requirements",
                json={
                    "title": "  Detect Kerberoasting (TTX-2026-03)  ",
                    "driver": "ttx",
                    "priority": "high",
                    "attack_technique_ids": ["T1558.003"],
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["title"] == "Detect Kerberoasting (TTX-2026-03)"  # trimmed
            assert body["driver"] == "ttx"
            assert body["status"] == "proposed"
            assert body["plan_item_count"] == 0
            assert body["author_email"]
            rid = body["id"]

            listed = await c.get("/cmf/requirements")
            assert listed.status_code == 200
            assert len(listed.json()) == 1

            patched = await c.patch(
                f"/cmf/requirements/{rid}", json={"status": "active"}
            )
            assert patched.status_code == 200
            assert patched.json()["status"] == "active"

            d = await c.delete(f"/cmf/requirements/{rid}")
            assert d.status_code == 204
            assert (await c.get("/cmf/requirements")).json() == []

    async def test_rejects_bad_enums(self, acme_clean_cmf, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/cmf/requirements", json={"title": "x", "driver": "astrology"}
            )
            assert r.status_code == 422
            assert "driver must be one of" in r.text

            r = await c.post(
                "/cmf/requirements", json={"title": "x", "priority": "ultra"}
            )
            assert r.status_code == 422

    async def test_patch_missing_404(self, acme_clean_cmf, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                "/cmf/requirements/00000000-0000-0000-0000-000000000000",
                json={"status": "active"},
            )
            assert r.status_code == 404


# ---- plan / implementation tracker ----------------------------------------


class TestPlan:
    async def test_create_links_requirement_and_tracks_status(
        self, acme_clean_cmf, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            req = await c.post(
                "/cmf/requirements", json={"title": "Req A", "driver": "risk_management"}
            )
            rid = req.json()["id"]

            item = await c.post(
                "/cmf/plan",
                json={
                    "data_source": "Process Creation",
                    "requirement_id": rid,
                    "priority": "high",
                },
            )
            assert item.status_code == 201, item.text
            b = item.json()
            assert b["data_source"] == "Process Creation"
            assert b["status"] == "proposed"
            assert b["source_kind"] == "manual"
            assert b["requirement_id"] == rid
            assert b["requirement_title"] == "Req A"  # joined
            iid = b["id"]

            # requirement now reports the linked plan item.
            reqs = await c.get("/cmf/requirements")
            assert reqs.json()[0]["plan_item_count"] == 1

            # advance the tracker.
            patched = await c.patch(f"/cmf/plan/{iid}", json={"status": "in_progress"})
            assert patched.status_code == 200
            assert patched.json()["status"] == "in_progress"

            # filter by status.
            ip = await c.get("/cmf/plan", params={"status": "in_progress"})
            assert len(ip.json()) == 1
            assert (await c.get("/cmf/plan", params={"status": "collected"})).json() == []

            d = await c.delete(f"/cmf/plan/{iid}")
            assert d.status_code == 204

    async def test_plan_rejects_bad_status(self, acme_clean_cmf, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/cmf/plan", json={"data_source": "X", "status": "halfway"}
            )
            assert r.status_code == 422


# ---- seed from gaps -------------------------------------------------------


class TestSeedFromGaps:
    async def test_seeds_then_idempotent(self, acme_clean_cmf, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            first = await c.post(
                "/cmf/plan/seed-from-gaps",
                json={"domain": "enterprise", "denominator": "full", "limit": 10},
            )
            assert first.status_code == 200, first.text
            fb = first.json()
            if fb["created"] == 0:
                pytest.skip("no gap recommendations in catalog — nothing to seed")
            assert fb["created"] > 0
            assert fb["skipped"] == 0
            # seeded items carry provenance + technique counts.
            seeded = [i for i in fb["items"] if i["source_kind"] == "gap_seed"]
            assert seeded
            assert all(i["status"] == "proposed" for i in seeded)
            assert any(i["technique_count"] > 0 for i in seeded)

            # second run is a no-op on the same sources.
            second = await c.post(
                "/cmf/plan/seed-from-gaps",
                json={"domain": "enterprise", "denominator": "full", "limit": 10},
            )
            sb = second.json()
            assert sb["created"] == 0
            assert sb["skipped"] == fb["created"]
