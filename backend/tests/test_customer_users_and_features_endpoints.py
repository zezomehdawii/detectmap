"""End-to-end tests for the customer-page management surface:

- /customers/{codename}/users   — customer_user CRUD scoped to a tenant
- /customers/{codename}/features — per-customer toggle GET/PATCH
- The require_feature dependency enforcing toggles on real endpoints
- The customer-portal login gate in /auth/login
- The Settings → Users filter (MSSP staff only) + primary-admin lock

Uses a synthetic customer in the 'Demo MSSP' org so it never collides with
seeded acme/globex state, and an isolated MSSPOrg-scoped sandbox where
needed. All fixtures clean up after themselves; the dev DB is shared.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.core.security import TokenAudience, create_access_token, hash_password
from app.db.base import AsyncSessionLocal
from app.main import app
from app.models.public import Customer, CustomerStatus, MSSPOrg, Role, User


# ---- helpers + fixtures --------------------------------------------------


def _client(token: str, *, customer: str | None = None) -> AsyncClient:
    headers = {"Authorization": f"Bearer {token}"}
    if customer:
        headers["X-Customer"] = customer
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    )


async def _demo_org_id() -> uuid.UUID:
    """Ensure the 'Demo MSSP' org exists and return its id. The token
    fixtures from conftest.py create users in this org, so we use it
    here too for consistent ownership."""
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = (
                await session.execute(
                    select(MSSPOrg).where(MSSPOrg.name == "Demo MSSP")
                )
            ).scalar_one_or_none()
            if org is None:
                org = MSSPOrg(id=uuid.uuid4(), name="Demo MSSP")
                session.add(org)
                await session.flush()
            org_id = org.id
    return org_id


@pytest_asyncio.fixture
async def sandbox_customer():
    """An ACTIVE customer in 'Demo MSSP', removed after the test along
    with any customer-pinned users created against it."""
    org_id = await _demo_org_id()
    codename = f"sbox_{uuid.uuid4().hex[:8]}"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            session.add(
                Customer(
                    id=uuid.uuid4(),
                    mssp_org_id=org_id,
                    codename=codename,
                    name="Sandbox Customer",
                    sector="finance",
                    status=CustomerStatus.ACTIVE,
                )
            )
    yield codename
    # Cascade: drop dependent users first, then the customer.
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(
                delete(User).where(
                    User.customer_id.in_(
                        select(Customer.id).where(Customer.codename == codename)
                    )
                )
            )
            await session.execute(
                delete(Customer).where(Customer.codename == codename)
            )


@pytest_asyncio.fixture
async def archived_customer():
    """An ARCHIVED customer to exercise the read-only guard."""
    org_id = await _demo_org_id()
    codename = f"arc_{uuid.uuid4().hex[:8]}"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            session.add(
                Customer(
                    id=uuid.uuid4(),
                    mssp_org_id=org_id,
                    codename=codename,
                    name="Archived Customer",
                    status=CustomerStatus.ARCHIVED,
                )
            )
    yield codename
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(
                delete(Customer).where(Customer.codename == codename)
            )


# ---- /customers/{cn}/users CRUD ------------------------------------------


class TestCustomerUserCRUD:
    async def test_list_empty_initially(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get(f"/customers/{sandbox_customer}/users")
        assert r.status_code == 200
        assert r.json() == []

    async def test_create_then_list(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={
                    "email": "Alice@Example.COM",  # mixed case → normalised
                    "password": "hunter2hunter2",
                    "full_name": "Alice Q.",
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["email"] == "alice@example.com"  # lowercased
            assert body["role"] == "customer_user"
            assert body["is_active"] is True
            assert body["custom_role_id"] is None

            r = await c.get(f"/customers/{sandbox_customer}/users")
        assert r.status_code == 200
        emails = [u["email"] for u in r.json()]
        assert emails == ["alice@example.com"]

    async def test_duplicate_email_rejected(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r1 = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "dup@example.com", "password": "passw0rd-ok"},
            )
            assert r1.status_code == 201
            r2 = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "dup@example.com", "password": "passw0rd-ok"},
            )
        assert r2.status_code == 409

    async def test_create_rejects_short_password(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "shorty@example.com", "password": "short"},
            )
        # Pydantic min_length=8 → 422.
        assert r.status_code == 422

    async def test_create_rejects_email_without_at(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "noatsign", "password": "passw0rd-ok"},
            )
        assert r.status_code == 422

    async def test_patch_full_name_and_deactivate(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            create = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "u1@example.com", "password": "passw0rd-ok"},
            )
            uid = create.json()["id"]
            r = await c.patch(
                f"/customers/{sandbox_customer}/users/{uid}",
                json={"full_name": "Updated Name", "is_active": False},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["is_active"] is False

    async def test_delete_then_404(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            create = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "doomed@example.com", "password": "passw0rd-ok"},
            )
            uid = create.json()["id"]
            d = await c.delete(f"/customers/{sandbox_customer}/users/{uid}")
            assert d.status_code == 204
            # Second delete → 404.
            d2 = await c.delete(f"/customers/{sandbox_customer}/users/{uid}")
        assert d2.status_code == 404

    async def test_create_on_archived_customer_409(
        self, archived_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                f"/customers/{archived_customer}/users",
                json={"email": "x@example.com", "password": "passw0rd-ok"},
            )
        assert r.status_code == 409

    async def test_readonly_user_cannot_create(
        self, sandbox_customer, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                f"/customers/{sandbox_customer}/users",
                json={"email": "blocked@example.com", "password": "passw0rd-ok"},
            )
        assert r.status_code == 403


# ---- /customers/{cn}/features --------------------------------------------


class TestCustomerFeatures:
    async def test_get_returns_catalog_and_defaults(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get(f"/customers/{sandbox_customer}/features")
        assert r.status_code == 200
        body = r.json()
        assert body["codename"] == sandbox_customer
        assert len(body["catalog"]) >= 7
        # Defaults are all on (matches the service-layer contract).
        assert all(v for v in body["features"].values()), body["features"]

    async def test_patch_persists_overrides(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{sandbox_customer}/features",
                json={"features": {"ai_authoring": False}},
            )
            assert r.status_code == 200
            assert r.json()["features"]["ai_authoring"] is False
            # Verify persistence via a fresh GET.
            r2 = await c.get(f"/customers/{sandbox_customer}/features")
        assert r2.json()["features"]["ai_authoring"] is False
        # Untouched flags keep defaults.
        assert r2.json()["features"]["bulk_export"] is True

    async def test_patch_unknown_key_422(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{sandbox_customer}/features",
                json={"features": {"bogus_key": True}},
            )
        assert r.status_code == 422
        assert "unknown feature key" in r.text

    async def test_patch_archived_409(
        self, archived_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/customers/{archived_customer}/features",
                json={"features": {"ai_authoring": False}},
            )
        assert r.status_code == 409

    async def test_readonly_cannot_patch(
        self, sandbox_customer, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.patch(
                f"/customers/{sandbox_customer}/features",
                json={"features": {"ai_authoring": False}},
            )
        assert r.status_code == 403


# ---- require_feature enforcement on real endpoints -----------------------


class TestFeatureEnforcement:
    async def test_ai_draft_gated(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        """ai_authoring=False → /detections/ai-draft 403; back on → past the
        gate (downstream may 400/422 — we only care the gate fired)."""
        async with _client(demo_admin_token, customer=sandbox_customer) as c:
            # Turn it off via the unscoped client (PATCH features doesn't
            # take X-Customer; use a separate request).
            async with _client(demo_admin_token) as a:
                await a.patch(
                    f"/customers/{sandbox_customer}/features",
                    json={"features": {"ai_authoring": False}},
                )
            r = await c.post(
                "/detections/ai-draft",
                json={"intent": "x"},
            )
            assert r.status_code == 403
            assert "ai_authoring" in r.text

            async with _client(demo_admin_token) as a:
                await a.patch(
                    f"/customers/{sandbox_customer}/features",
                    json={"features": {"ai_authoring": True}},
                )
            r2 = await c.post(
                "/detections/ai-draft",
                json={"intent": "x"},
            )
        # With the gate open the request reaches the AI service which
        # bails because the MSSP has no key configured. Either way, it's
        # NOT 403 from the gate.
        assert r2.status_code != 403

    async def test_bulk_export_gated(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token, customer=sandbox_customer) as c:
            async with _client(demo_admin_token) as a:
                await a.patch(
                    f"/customers/{sandbox_customer}/features",
                    json={"features": {"bulk_export": False}},
                )
            r = await c.get("/reports/coverage.csv?domain=enterprise&denominator=full")
        assert r.status_code == 403
        assert "bulk_export" in r.text

    async def test_grc_gate_optional_customer(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        """grc_editing off + X-Customer set → 403. Same flag off, no
        X-Customer → request reaches body validation (proves the gate
        no-ops without a customer context)."""
        async with _client(demo_admin_token) as a:
            await a.patch(
                f"/customers/{sandbox_customer}/features",
                json={"features": {"grc_editing": False}},
            )

        bogus = {
            "control_uuid": str(uuid.uuid4()),
            "target_kind": "technique",
            "target_id": "T0000",
        }
        async with _client(demo_admin_token, customer=sandbox_customer) as c:
            with_cust = await c.post("/grc/mappings", json=bogus)
        async with _client(demo_admin_token) as c:
            no_cust = await c.post("/grc/mappings", json=bogus)

        assert with_cust.status_code == 403
        # No customer in context — gate skips, request gets through to
        # the body validator. Could be 404/422 depending on payload
        # validation order; the contract is "not 403 from the gate".
        assert no_cust.status_code != 403


# ---- customer-portal login gate ------------------------------------------


@pytest_asyncio.fixture
async def sandbox_customer_user(sandbox_customer):
    """A customer_user in the sandbox customer, with a known password.

    Yields `(codename, email, password)`. The user is dropped as part of
    `sandbox_customer`'s cleanup (cascades on customer delete).
    """
    org_id = await _demo_org_id()
    email = f"u_{uuid.uuid4().hex[:8]}@example.com"
    password = "hunter2hunter2"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            customer = (
                await session.execute(
                    select(Customer).where(Customer.codename == sandbox_customer)
                )
            ).scalar_one()
            session.add(
                User(
                    id=uuid.uuid4(),
                    email=email,
                    hashed_password=hash_password(password),
                    auth_source="local",
                    role=Role.CUSTOMER_USER,
                    is_active=True,
                    mssp_org_id=org_id,
                    customer_id=customer.id,
                )
            )
    yield sandbox_customer, email, password


class TestCustomerPortalLogin:
    async def test_login_blocked_when_portal_off(
        self, sandbox_customer_user, demo_admin_token
    ) -> None:
        codename, email, password = sandbox_customer_user
        # Flip the toggle off.
        async with _client(demo_admin_token) as a:
            await a.patch(
                f"/customers/{codename}/features",
                json={"features": {"customer_portal": False}},
            )
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
        assert r.status_code == 403
        assert "Customer portal" in r.text

    async def test_login_succeeds_when_portal_on(
        self, sandbox_customer_user, demo_admin_token
    ) -> None:
        codename, email, password = sandbox_customer_user
        # Explicit on (default), then attempt login.
        async with _client(demo_admin_token) as a:
            await a.patch(
                f"/customers/{codename}/features",
                json={"features": {"customer_portal": True}},
            )
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
        assert r.status_code == 200
        assert "access_token" in r.json()

    async def test_portal_off_does_not_block_mssp_admin(
        self, sandbox_customer, demo_admin_token
    ) -> None:
        """The toggle is scoped to the user's pinned customer. An MSSP
        admin's login flow never visits a customer record, so flipping
        portal off for one tenant must not affect MSSP staff.

        Provisions a throwaway MSSP admin in 'Demo MSSP' with a known
        password so this test doesn't depend on whatever the long-lived
        demo admin's password has been rotated to.
        """
        org_id = await _demo_org_id()
        email = f"mssp_{uuid.uuid4().hex[:8]}@example.com"
        password = "hunter2hunter2"
        async with AsyncSessionLocal() as session:
            async with session.begin():
                session.add(
                    User(
                        id=uuid.uuid4(),
                        email=email,
                        hashed_password=hash_password(password),
                        auth_source="local",
                        role=Role.MSSP_ADMIN,
                        is_active=True,
                        mssp_org_id=org_id,
                    )
                )

        try:
            async with _client(demo_admin_token) as a:
                await a.patch(
                    f"/customers/{sandbox_customer}/features",
                    json={"features": {"customer_portal": False}},
                )
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                r = await c.post(
                    "/auth/login",
                    json={"email": email, "password": password},
                )
            assert r.status_code == 200
        finally:
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    await session.execute(
                        delete(User).where(User.email == email)
                    )


# ---- Settings → Users filter + primary-admin lock ------------------------


class TestSettingsUsersFilter:
    async def test_settings_users_excludes_customer_users(
        self, sandbox_customer_user, demo_admin_token
    ) -> None:
        """The customer_user we just seeded must NOT appear in
        /settings/users — that endpoint is MSSP staff only now."""
        _codename, email, _pw = sandbox_customer_user
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/users")
        assert r.status_code == 200
        roles = {u["role"] for u in r.json()}
        emails = {u["email"] for u in r.json()}
        assert "customer_user" not in roles
        assert email not in emails

    async def test_settings_users_create_rejects_customer_user_role(
        self, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/settings/users",
                json={
                    "email": f"rejected_{uuid.uuid4().hex[:6]}@example.com",
                    "password": "passw0rd-ok",
                    "role": "customer_user",
                },
            )
        assert r.status_code == 422
        assert "customer's page" in r.text


class TestPrimaryAdminLock:
    async def test_primary_admin_flagged_in_listing(
        self, demo_admin_token
    ) -> None:
        """The earliest-created user in the org carries `is_primary=true`,
        everyone else is false. Exactly one primary per org."""
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/users")
        assert r.status_code == 200
        rows = r.json()
        primaries = [u for u in rows if u["is_primary"]]
        assert len(primaries) == 1, primaries

    async def test_primary_admin_cannot_be_demoted_or_deactivated(
        self, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            rows = (await c.get("/settings/users")).json()
            primary = next(u for u in rows if u["is_primary"])
            r = await c.patch(
                f"/settings/users/{primary['id']}",
                json={"role": "mssp_analyst"},
            )
            assert r.status_code == 422
            assert "primary administrator" in r.text
            # Deactivate is also locked.
            r2 = await c.patch(
                f"/settings/users/{primary['id']}",
                json={"is_active": False},
            )
        assert r2.status_code == 422

    async def test_primary_admin_full_name_still_editable(
        self, demo_admin_token
    ) -> None:
        """full_name remains editable on the primary admin — only the
        lock-yourself-out fields (role, is_active, custom_role_id,
        customer_id) are blocked. We deliberately don't poke the
        password from here: the primary admin's password is owned by
        the operator (see the `pass-reset` utility) and rotating it
        from a test would silently break unrelated test logins."""
        async with _client(demo_admin_token) as c:
            rows = (await c.get("/settings/users")).json()
            primary = next(u for u in rows if u["is_primary"])
            previous = primary.get("full_name") or ""
            r = await c.patch(
                f"/settings/users/{primary['id']}",
                json={"full_name": "Primary Admin (test)"},
            )
            assert r.status_code == 200, r.text
            # Restore so the listing stays stable for other tests.
            restore = await c.patch(
                f"/settings/users/{primary['id']}",
                json={"full_name": previous},
            )
        assert restore.status_code == 200
