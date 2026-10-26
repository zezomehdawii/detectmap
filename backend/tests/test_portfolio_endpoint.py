"""Tests for /portfolio/overview — MSSP cross-customer roll-up."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app


async def _ensure_demo_mssp_customers() -> bool:
    async with AsyncSessionLocal() as session:
        # The seed_demo script provisions acme + globex under "Demo MSSP".
        rows = await session.execute(
            text(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name IN ('cust_acme', 'cust_globex')"
            )
        )
        names = {r[0] for r in rows}
        return "cust_acme" in names


async def _wipe_acme() -> None:
    async with tenant_session() as session:
        await session.execute(text("DELETE FROM detection_techniques"))
        await session.execute(text("DELETE FROM detections"))


@pytest_asyncio.fixture
async def demo_mssp_state():
    if not await _ensure_demo_mssp_customers():
        pytest.skip("Demo MSSP customers not provisioned — run seed_demo first")
    yield


class TestPortfolioOverview:
    async def test_admin_sees_their_org_customers(
        self, demo_mssp_state, demo_admin_token
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/portfolio/overview")
        assert r.status_code == 200
        body = r.json()
        codenames = {c["codename"] for c in body["customers"]}
        # Demo MSSP must own at least acme; globex may or may not be present
        # depending on whether the test suite has wiped its schema.
        assert "acme" in codenames
        # Posture distribution sums to <= customer count (provisioning rows skip).
        s = sum(body["posture_distribution"].values())
        assert s <= body["customer_count"]

    async def test_invalid_denominator_422(
        self, demo_mssp_state, demo_admin_token
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/portfolio/overview?denominator=invalid")
        assert r.status_code == 422

    async def test_no_org_user_denied(
        self, demo_mssp_state, super_admin_token
    ) -> None:
        # Super admin has SUPERADMIN audience, not TENANT — should be 401.
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {super_admin_token}"},
        ) as c:
            r = await c.get("/portfolio/overview")
        assert r.status_code == 401
