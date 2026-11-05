"""Tests for the sign-in page credential hint.

These tests only touch the `app_settings.show_login_hint` singleton flag, so
they are safe to run against the shared dev DB (no `wipes_db` marker). The
fixture restores the original value afterwards.
"""
from __future__ import annotations

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import settings as app_config
from app.db.base import AsyncSessionLocal
from app.main import app
from app.models.public import AppSettings


def _client(token: str | None = None) -> AsyncClient:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    )


async def _set_hint(enabled: bool) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            row = (await session.execute(select(AppSettings))).scalar_one_or_none()
            if row is None:
                row = AppSettings(singleton=True)
                session.add(row)
            row.show_login_hint = enabled


async def _get_hint() -> bool:
    async with AsyncSessionLocal() as session:
        row = (await session.execute(select(AppSettings))).scalar_one_or_none()
        return row.show_login_hint if row is not None else True


@pytest_asyncio.fixture
async def restore_login_hint():
    original = await _get_hint()
    yield
    await _set_hint(original)


class TestPublicLoginHint:
    async def test_enabled_returns_configured_credentials(
        self, restore_login_hint
    ) -> None:
        await _set_hint(True)
        async with _client() as c:
            r = await c.get("/auth/login-hint")
        assert r.status_code == 200
        assert r.json() == {
            "enabled": True,
            "email": app_config.default_login_email,
            "password": app_config.default_login_password,
        }

    async def test_disabled_omits_credentials(self, restore_login_hint) -> None:
        await _set_hint(False)
        async with _client() as c:
            r = await c.get("/auth/login-hint")
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        assert body["email"] is None
        assert body["password"] is None


class TestLoginHintSettings:
    async def test_admin_toggle_updates_public_hint(
        self, restore_login_hint, demo_admin_token
    ) -> None:
        await _set_hint(True)
        async with _client(demo_admin_token) as c:
            r = await c.get("/settings/login-hint")
            assert r.status_code == 200
            assert r.json()["enabled"] is True

            r = await c.patch("/settings/login-hint", json={"enabled": False})
            assert r.status_code == 200
            assert r.json()["enabled"] is False

        assert await _get_hint() is False
        async with _client() as c:
            r = await c.get("/auth/login-hint")
        assert r.json()["enabled"] is False
        assert r.json()["email"] is None

    async def test_readonly_can_read_but_not_write(
        self, restore_login_hint, demo_readonly_token
    ) -> None:
        await _set_hint(True)
        async with _client(demo_readonly_token) as c:
            r = await c.get("/settings/login-hint")
            assert r.status_code == 200
            assert r.json()["enabled"] is True

            r = await c.patch("/settings/login-hint", json={"enabled": False})
        assert r.status_code == 403
        assert await _get_hint() is True
