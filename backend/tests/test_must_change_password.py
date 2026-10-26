"""Tests for the `must_change_password` flag end-to-end.

Lifecycle:
  1. Admin creates a user (or factory_reset seeds the bootstrap admin)
     with `must_change_password=True`.
  2. /auth/login returns a usable token + `must_change_password=true`.
  3. /auth/me also reports the flag (the SPA reads this on every page
     mount, so a reload doesn't bypass the rotation screen).
  4. /auth/change-password clears the flag on success.
  5. Subsequent logins return `must_change_password=false`.

The factory_reset script itself is not exercised here because it would
wipe the shared dev DB; its core wipe + seed behaviour is tested
indirectly via the existing fixtures (a successful reset would leave
the same shape that fixtures create).
"""
from __future__ import annotations

import uuid

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.core.security import hash_password
from app.db.base import AsyncSessionLocal
from app.main import app
from app.models.public import MSSPOrg, Role, User


@pytest_asyncio.fixture
async def bootstrap_user():
    """Create a fresh user with must_change_password=True, yield
    `(email, password, user_id)`, drop the user in teardown."""
    email = f"bootstrap_{uuid.uuid4().hex[:8]}@example.com"
    password = "initial-pw-1234"
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
            user = User(
                id=uuid.uuid4(),
                email=email,
                hashed_password=hash_password(password),
                auth_source="local",
                role=Role.MSSP_ANALYST,
                is_active=True,
                mssp_org_id=org.id,
                must_change_password=True,
            )
            session.add(user)
            await session.flush()
            user_id = user.id
    yield email, password, user_id
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(User).where(User.id == user_id))


def _client(token: str | None = None) -> AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    )


class TestMustChangePassword:
    async def test_login_reports_flag(self, bootstrap_user) -> None:
        email, password, _ = bootstrap_user
        async with _client() as c:
            r = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["must_change_password"] is True
        assert body["access_token"]

    async def test_me_reports_flag(self, bootstrap_user) -> None:
        email, password, _ = bootstrap_user
        async with _client() as c:
            login = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
            token = login.json()["access_token"]
        async with _client(token) as c:
            r = await c.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["must_change_password"] is True

    async def test_change_password_clears_flag(self, bootstrap_user) -> None:
        email, password, user_id = bootstrap_user
        new_password = "rotated-pw-12345"
        async with _client() as c:
            login = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
            token = login.json()["access_token"]
        async with _client(token) as c:
            r = await c.post(
                "/auth/change-password",
                json={
                    "current_password": password,
                    "new_password": new_password,
                },
            )
            assert r.status_code == 204, r.text
            me = await c.get("/auth/me")
        assert me.status_code == 200
        assert me.json()["must_change_password"] is False

        # And a fresh login should now report false.
        async with _client() as c:
            login2 = await c.post(
                "/auth/login",
                json={"email": email, "password": new_password},
            )
        assert login2.status_code == 200
        assert login2.json()["must_change_password"] is False

    async def test_login_still_succeeds_when_flag_set(
        self, bootstrap_user
    ) -> None:
        """Critical contract: the flag must NEVER block login itself —
        the user needs to authenticate so they can call /change-password.
        The frontend reads the flag and gates navigation in the SPA."""
        email, password, _ = bootstrap_user
        async with _client() as c:
            r = await c.post(
                "/auth/login", json={"email": email, "password": password}
            )
        assert r.status_code == 200
        # Token is real — works on a protected endpoint.
        async with _client(r.json()["access_token"]) as c:
            me = await c.get("/auth/me")
        assert me.status_code == 200
