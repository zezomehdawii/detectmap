"""Tests for /customers — list, get, patch, lifecycle transitions.

We avoid the heavy POST /customers path (which runs alembic + creates a
schema). Instead we insert a synthetic Customer row directly so we can
exercise the patch / lifecycle endpoint cheaply.
"""
from __future__ import annotations

import uuid

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.db.base import AsyncSessionLocal
from app.main import app
from app.models.public import Customer, CustomerStatus, MSSPOrg


@pytest_asyncio.fixture
async def synthetic_customer():
    """Insert a synthetic ACTIVE customer in the 'Demo MSSP' org and clean up."""
    codename = f"testc_{uuid.uuid4().hex[:8]}"
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(select(MSSPOrg).where(MSSPOrg.name == "Demo MSSP"))
        ).scalar_one_or_none()
        if org is None:
            org = MSSPOrg(id=uuid.uuid4(), name="Demo MSSP")
            session.add(org)
            await session.flush()
        customer = Customer(
            id=uuid.uuid4(),
            mssp_org_id=org.id,
            codename=codename,
            name="Synthetic Test Customer",
            sector="finance",
            status=CustomerStatus.ACTIVE,
        )
        session.add(customer)
        await session.commit()
    yield codename
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Customer).where(Customer.codename == codename))
        await session.commit()


def _client(token: str):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )


class TestCustomerList:
    async def test_admin_lists_own_org_customers(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/customers")
        assert r.status_code == 200
        codenames = {row["codename"] for row in r.json()}
        assert synthetic_customer in codenames

    async def test_get_one(self, synthetic_customer, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get(f"/customers/{synthetic_customer}")
        assert r.status_code == 200
        body = r.json()
        assert body["codename"] == synthetic_customer
        assert body["status"] == "active"
        assert body["schema_name"] == f"cust_{synthetic_customer}"


class TestCustomerPatchMetadata:
    async def test_patch_name_and_sector(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}",
                json={"name": "Renamed Co", "sector": "energy"},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == "Renamed Co"
        assert body["sector"] == "energy"

    async def test_patch_clears_sector_with_empty_string(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}",
                json={"sector": ""},
            )
        assert r.status_code == 200
        assert r.json()["sector"] is None


class TestCustomerLifecycle:
    async def test_active_to_suspended_and_back(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "suspended"}
            )
            assert r.status_code == 200
            assert r.json()["status"] == "suspended"

            r2 = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "active"}
            )
            assert r2.status_code == 200
            assert r2.json()["status"] == "active"

    async def test_active_to_archived(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "archived"}
            )
        assert r.status_code == 200
        assert r.json()["status"] == "archived"

    async def test_archived_is_terminal(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "archived"}
            )
            assert r.status_code == 200
            # Cannot move out of archived
            r2 = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "active"}
            )
            assert r2.status_code == 409
            # Cannot edit metadata while archived
            r3 = await c.patch(
                f"/customers/{synthetic_customer}", json={"name": "Renamed again"}
            )
            assert r3.status_code == 409

    async def test_cannot_provision_via_patch(
        self, synthetic_customer, demo_admin_token
    ) -> None:
        # ACTIVE -> PROVISIONING is not in the transition matrix.
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}",
                json={"status": "provisioning"},
            )
        assert r.status_code == 409


class TestCustomerPatchRBAC:
    async def test_readonly_cannot_patch(
        self, synthetic_customer, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.patch(
                f"/customers/{synthetic_customer}", json={"status": "suspended"}
            )
        # MSSP_READONLY lacks CUSTOMER_PROVISION
        assert r.status_code == 403

    async def test_other_org_404(self, synthetic_customer, readonly_token) -> None:
        # readonly_token belongs to "Phase2 Test MSSP" — must not see the
        # Demo MSSP synthetic customer at all.
        async with _client(readonly_token) as c:
            r = await c.get(f"/customers/{synthetic_customer}")
        assert r.status_code == 404
