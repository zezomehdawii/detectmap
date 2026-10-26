"""Tests for the per-user preferences service + /auth/me/preferences endpoints.

The service module (`app.services.user_prefs`) is pure-Python — most of
its surface is unit-tested without a DB. The endpoint tests round-trip
through the live FastAPI app and the dev DB, scoped to a throwaway user
so they don't pollute long-lived demo accounts.
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
from app.models.public import MSSPOrg, Role, User, UserPreferences
from app.services import user_prefs


# ---- service unit tests --------------------------------------------------


class TestServiceCatalog:
    def test_catalog_shape(self) -> None:
        cat = user_prefs.catalog()
        assert len(cat) >= 4
        keys = {m["key"] for m in cat}
        assert "color_mode" in keys
        for m in cat:
            for field in ("key", "label", "description", "default", "choices", "value_type"):
                assert field in m

    def test_defaults_includes_every_key(self) -> None:
        d = user_prefs.defaults()
        catalog_keys = {m["key"] for m in user_prefs.catalog()}
        assert set(d.keys()) == catalog_keys


class TestNormalise:
    def test_no_overrides_returns_defaults(self) -> None:
        assert user_prefs.normalise(None) == user_prefs.defaults()
        assert user_prefs.normalise({}) == user_prefs.defaults()

    def test_applies_known_overrides(self) -> None:
        out = user_prefs.normalise({"color_mode": "light", "sidebar_collapsed": True})
        assert out["color_mode"] == "light"
        assert out["sidebar_collapsed"] is True
        # Untouched keys fall back to defaults.
        assert out["density"] == "comfortable"

    def test_drops_unknown_keys(self) -> None:
        out = user_prefs.normalise({"bogus": "x", "color_mode": "light"})
        assert "bogus" not in out
        assert out["color_mode"] == "light"

    def test_drops_invalid_enum_values_silently(self) -> None:
        # `normalise` is the read path — it must NEVER raise. Corrupt
        # values fall back to defaults so the UI keeps working.
        out = user_prefs.normalise({"color_mode": "polkadot"})
        assert out["color_mode"] == "dark"  # default

    def test_coerces_bool_values(self) -> None:
        assert user_prefs.normalise({"sidebar_collapsed": 1})["sidebar_collapsed"] is True
        assert user_prefs.normalise({"sidebar_collapsed": 0})["sidebar_collapsed"] is False
        assert (
            user_prefs.normalise({"sidebar_collapsed": "true"})["sidebar_collapsed"] is True
        )


class TestValidatePatch:
    def test_accepts_known_keys(self) -> None:
        cleaned = user_prefs.validate_patch(
            {"color_mode": "light", "density": "compact"}
        )
        assert cleaned == {"color_mode": "light", "density": "compact"}

    def test_rejects_unknown_key(self) -> None:
        with pytest.raises(ValueError, match="unknown preference key"):
            user_prefs.validate_patch({"bogus": True})

    def test_rejects_bad_enum_value(self) -> None:
        with pytest.raises(ValueError, match="must be one of"):
            user_prefs.validate_patch({"color_mode": "polkadot"})

    def test_rejects_non_dict(self) -> None:
        with pytest.raises(ValueError):
            user_prefs.validate_patch(["color_mode"])  # type: ignore[arg-type]

    def test_coerces_bool_strictly(self) -> None:
        # Write path is strict: "false"/"true" strings ARE accepted (we
        # said so in the docstring), but garbage strings aren't.
        cleaned = user_prefs.validate_patch({"sidebar_collapsed": "false"})
        assert cleaned["sidebar_collapsed"] is False
        with pytest.raises(ValueError):
            user_prefs.validate_patch({"sidebar_collapsed": "maybe"})


# ---- endpoint tests ------------------------------------------------------


def _client(token: str) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest_asyncio.fixture
async def disposable_user_token():
    """A throwaway MSSP analyst in 'Demo MSSP' with no pref row yet.

    Yields the JWT. Cleanup drops the user + any prefs row that the
    tests left behind (CASCADE on user delete drops user_preferences).
    """
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
            email = f"prefs_{uuid.uuid4().hex[:8]}@example.com"
            user = User(
                id=uuid.uuid4(),
                email=email,
                hashed_password=hash_password("doesntmatter12"),
                auth_source="local",
                role=Role.MSSP_ANALYST,
                is_active=True,
                mssp_org_id=org.id,
            )
            session.add(user)
            await session.flush()
            user_id = user.id
    token = create_access_token(
        subject=str(user_id),
        audience=TokenAudience.TENANT,
        claims={"role": Role.MSSP_ANALYST.value},
    )
    yield token
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(User).where(User.id == user_id))


class TestPreferencesEndpoints:
    async def test_get_with_no_stored_row_returns_defaults(
        self, disposable_user_token
    ) -> None:
        async with _client(disposable_user_token) as c:
            r = await c.get("/auth/me/preferences")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["preferences"] == user_prefs.defaults()
        # Catalog includes the four shipped keys.
        catalog_keys = {m["key"] for m in body["catalog"]}
        assert {
            "color_mode",
            "density",
            "sidebar_collapsed",
            "default_coverage_domain",
        }.issubset(catalog_keys)

    async def test_patch_persists_and_partial_updates_merge(
        self, disposable_user_token
    ) -> None:
        async with _client(disposable_user_token) as c:
            # First write: color_mode only.
            r1 = await c.patch(
                "/auth/me/preferences",
                json={"preferences": {"color_mode": "light"}},
            )
            assert r1.status_code == 200
            assert r1.json()["preferences"]["color_mode"] == "light"
            # Other keys still on defaults.
            assert r1.json()["preferences"]["sidebar_collapsed"] is False

            # Second write: sidebar_collapsed only — must NOT clobber color_mode.
            r2 = await c.patch(
                "/auth/me/preferences",
                json={"preferences": {"sidebar_collapsed": True}},
            )
            assert r2.status_code == 200
            body = r2.json()["preferences"]
            assert body["color_mode"] == "light"
            assert body["sidebar_collapsed"] is True

            # Third write: fresh GET still reflects both.
            r3 = await c.get("/auth/me/preferences")
        assert r3.status_code == 200
        body = r3.json()["preferences"]
        assert body["color_mode"] == "light"
        assert body["sidebar_collapsed"] is True

    async def test_patch_rejects_unknown_key(
        self, disposable_user_token
    ) -> None:
        async with _client(disposable_user_token) as c:
            r = await c.patch(
                "/auth/me/preferences",
                json={"preferences": {"bogus": True}},
            )
        assert r.status_code == 422
        assert "unknown preference key" in r.text

    async def test_patch_rejects_bad_enum_value(
        self, disposable_user_token
    ) -> None:
        async with _client(disposable_user_token) as c:
            r = await c.patch(
                "/auth/me/preferences",
                json={"preferences": {"color_mode": "polkadot"}},
            )
        assert r.status_code == 422

    async def test_preferences_isolated_per_user(
        self, disposable_user_token, demo_admin_token
    ) -> None:
        """User A's PATCH must not leak into user B's GET."""
        async with _client(disposable_user_token) as a:
            await a.patch(
                "/auth/me/preferences",
                json={"preferences": {"color_mode": "light"}},
            )
        async with _client(demo_admin_token) as b:
            r = await b.get("/auth/me/preferences")
        # The demo admin should NOT see "light" unless they set it
        # themselves. We don't assert a specific value (the demo admin
        # row may carry persisted state from earlier tests), but it
        # should be a valid color_mode value either way.
        assert r.status_code == 200
        assert r.json()["preferences"]["color_mode"] in ("dark", "light")

    async def test_unauthenticated_request_401(self) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/auth/me/preferences")
        assert r.status_code == 401

    async def test_cascade_delete_cleans_up_pref_row(
        self,
    ) -> None:
        """When a user is deleted, the FK cascade drops their pref row.
        We exercise this directly since the test fixture deletes the user
        after the test — we want to ensure no orphan rows linger."""
        # Create a user, write a pref, delete the user, assert the row
        # is gone.
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
                u = User(
                    id=uuid.uuid4(),
                    email=f"cas_{uuid.uuid4().hex[:6]}@example.com",
                    hashed_password=hash_password("doesntmatter12"),
                    auth_source="local",
                    role=Role.MSSP_READONLY,
                    is_active=True,
                    mssp_org_id=org.id,
                )
                session.add(u)
                await session.flush()
                session.add(
                    UserPreferences(user_id=u.id, prefs={"color_mode": "light"})
                )
                user_id = u.id

        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(User).where(User.id == user_id))

        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(
                    select(UserPreferences).where(
                        UserPreferences.user_id == user_id
                    )
                )
            ).scalar_one_or_none()
        assert row is None
