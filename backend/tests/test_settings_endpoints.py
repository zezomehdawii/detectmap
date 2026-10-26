"""Tests for /settings/* — branding patches, catalog schedule, ATT&CK diffs, users."""
from __future__ import annotations

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


@pytest_asyncio.fixture
async def acme_active():
    if not await _ensure_acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    yield


def _client(token: str, customer: str = ""):
    headers = {"Authorization": f"Bearer {token}"}
    if customer:
        headers["X-Customer"] = customer
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    )


class TestBranding:
    async def test_mssp_branding_patch_round_trip(self, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/mssp/branding")
            assert r.status_code == 200

            r2 = await c.patch(
                "/settings/mssp/branding",
                json={
                    "display_name": "Demo MSSP (test)",
                    "primary_color": "#4f46e5",
                    "extra": {"footer_note": "Confidential"},
                },
            )
            assert r2.status_code == 200
            body = r2.json()
            assert body["branding"]["display_name"] == "Demo MSSP (test)"
            assert body["branding"]["primary_color"] == "#4f46e5"
            assert body["branding"]["footer_note"] == "Confidential"

    async def test_customer_branding_requires_active_customer(
        self, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/customer/branding")
        assert r.status_code == 400  # X-Customer required

    async def test_customer_branding_patch(
        self, acme_active, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token, customer="acme") as c:
            r = await c.patch(
                "/settings/customer/branding",
                json={
                    "display_name": "Acme Industries",
                    "extra": {"legend_overrides": {"deployed": "#00ff00"}},
                },
            )
        assert r.status_code == 200
        body = r.json()
        assert body["branding"]["display_name"] == "Acme Industries"
        assert body["branding"]["legend_overrides"]["deployed"] == "#00ff00"


class TestCatalogSettings:
    async def test_super_admin_can_patch_schedule(
        self, super_admin_token
    ) -> None:
        async with _client(super_admin_token) as c:
            r = await c.get("/settings/catalog")
            assert r.status_code == 200, r.text
            r2 = await c.patch(
                "/settings/catalog",
                json={
                    "attack_refresh_enabled": True,
                    "attack_refresh_cron": "0 3 * * 0",
                },
            )
            assert r2.status_code == 200
            body = r2.json()
            assert body["attack_refresh_enabled"] is True
            assert body["attack_refresh_cron"] == "0 3 * * 0"

    async def test_tenant_user_cannot_access_catalog_settings(
        self, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/catalog")
        # Tenant JWT can't decode against the super-admin secret.
        assert r.status_code == 401


class TestAttackDiffs:
    async def test_diffs_endpoint_returns_recent_versions(
        self, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/attack-diffs?limit=10")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) >= 1
        assert rows[0]["domain"] == "enterprise"
        assert "T1059" in rows[0]["added"]


class TestUsers:
    async def test_list_users_returns_org_users(self, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/users")
        assert r.status_code == 200
        emails = {u["email"] for u in r.json()}
        # The demo-admin fixture creates phase3-demo-admin@detectmap.test.
        assert any(e.endswith("@detectmap.test") for e in emails)
