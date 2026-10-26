"""HTTP-level tests for /connectors/* — CRUD, masking, RBAC, /test stub."""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.crypto import decrypt
from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import Connector


async def _ensure_acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return row.scalar_one_or_none() is not None


async def _wipe_connectors() -> None:
    async with tenant_session() as session:
        await session.execute(text("DELETE FROM connectors"))


@pytest_asyncio.fixture
async def acme_no_connectors():
    if not await _ensure_acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    set_tenant("acme")
    try:
        await _wipe_connectors()
    finally:
        set_tenant(None)
    yield
    set_tenant("acme")
    try:
        await _wipe_connectors()
    finally:
        set_tenant(None)


def _client(token: str):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": "acme"},
    )


class TestConnectorCRUD:
    async def test_create_lists_and_masks_secret(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={
                    "kind": "splunk",
                    "label": "Prod Splunk",
                    "description": "the main cluster",
                    "config": {
                        "host": "splunk.acme.local",
                        "port": 8088,
                        "hec_token": "abcd-supersecret-1234",
                    },
                },
            )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["kind"] == "splunk"
        assert body["status"] == "planned"
        # Plain config keys kept, secret keys stripped.
        assert body["config"] == {"host": "splunk.acme.local", "port": 8088}
        # Secret echoed only as masked tail.
        assert "hec_token" in body["secret_fields"]
        assert body["secret_fields"]["hec_token"].endswith("1234")
        assert "abcd" not in body["secret_fields"]["hec_token"]
        assert "supersecret" not in str(body)

    async def test_secret_round_trips_via_fernet(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={
                    "kind": "elastic",
                    "label": "Prod Elastic",
                    "config": {"host": "es.acme", "api_key": "very-secret"},
                },
            )
            assert r.status_code == 201
            connector_id = r.json()["id"]

        # Verify the DB stores ciphertext, and that we can decrypt it back.
        set_tenant("acme")
        try:
            async with tenant_session() as session:
                from sqlalchemy import select
                row = (
                    await session.execute(
                        select(Connector).where(Connector.id == uuid.UUID(connector_id))
                    )
                ).scalar_one()
                ct = row.encrypted_config["api_key"]
                assert ct != "very-secret"
                assert decrypt(ct) == "very-secret"
        finally:
            set_tenant(None)

    async def test_duplicate_returns_409(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r1 = await c.post(
                "/connectors",
                json={"kind": "splunk", "label": "Dup", "config": {}},
            )
            assert r1.status_code == 201
            r2 = await c.post(
                "/connectors",
                json={"kind": "splunk", "label": "Dup", "config": {}},
            )
        assert r2.status_code == 409

    async def test_unsupported_kind_422(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={"kind": "snowflake", "label": "x", "config": {}},
            )
        assert r.status_code == 422

    async def test_patch_updates_label_and_rotates_secret(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={
                    "kind": "splunk",
                    "label": "Rotate me",
                    "config": {"hec_token": "old-1111"},
                },
            )
            cid = r.json()["id"]
            rp = await c.patch(
                f"/connectors/{cid}",
                json={"label": "Rotated", "config": {"hec_token": "new-2222"}},
            )
        assert rp.status_code == 200
        body = rp.json()
        assert body["label"] == "Rotated"
        assert body["secret_fields"]["hec_token"].endswith("2222")

    async def test_clear_secret(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={
                    "kind": "splunk",
                    "label": "Clearable",
                    "config": {"hec_token": "remove-me-1234"},
                },
            )
            cid = r.json()["id"]
            assert "hec_token" in r.json()["secret_fields"]

            rp = await c.patch(
                f"/connectors/{cid}",
                json={"clear_secrets": ["hec_token"]},
            )
        assert rp.status_code == 200
        assert "hec_token" not in rp.json()["secret_fields"]

    async def test_test_endpoint_runs_live(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        """Live connector test endpoint returns a real outcome.

        We create a Splunk connector with no host configured, so the test
        will report a config error rather than attempting a network call.
        Status must be 'error' (not 'planned') — the stub is gone.
        """
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={"kind": "splunk", "label": "TestIt", "config": {}},
            )
            cid = r.json()["id"]
            rt = await c.post(f"/connectors/{cid}/test")
        assert rt.status_code == 202
        body = rt.json()
        # Empty config → service rejects with a structured error before any
        # HTTP attempt. Verifies the live test path is actually wired in.
        assert body["status"] == "error"
        assert "missing host" in body["message"].lower() or "no credentials" in body["message"].lower()

    async def test_delete_round_trip(
        self, acme_no_connectors, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/connectors",
                json={"kind": "splunk", "label": "Doomed", "config": {}},
            )
            cid = r.json()["id"]
            rd = await c.delete(f"/connectors/{cid}")
            assert rd.status_code == 204
            rL = await c.get("/connectors")
        assert rL.status_code == 200
        assert not any(c["id"] == cid for c in rL.json())


class TestConnectorRBAC:
    async def test_readonly_cannot_create(
        self, acme_no_connectors, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                "/connectors",
                json={"kind": "splunk", "label": "Reject", "config": {}},
            )
        assert r.status_code == 403

    async def test_readonly_can_list(
        self, acme_no_connectors, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.get("/connectors")
        assert r.status_code == 200
