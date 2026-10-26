"""HTTP-level tests for /grc/* endpoints — RBAC + mapping CRUD."""
from __future__ import annotations

import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.public import GRCControl, GRCFramework
from app.services.grc_seed import seed_grc

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


async def _pr_ps_uuid() -> str:
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(
                select(GRCControl.id)
                .join(GRCFramework, GRCFramework.id == GRCControl.framework_id)
                .where(
                    GRCFramework.key == "nist_csf",
                    GRCControl.control_id == "PR.PS-04",
                )
            )
        ).scalar_one()
        return str(row)


class TestFrameworksEndpoint:
    async def test_list_frameworks_returns_seeded_three(
        self, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/grc/frameworks")
        assert r.status_code == 200
        keys = {f["key"] for f in r.json()}
        assert keys == {"nist_csf", "iso_27001", "nca_ecc"}

    async def test_unknown_framework_404(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        async with _client(demo_admin_token) as c:
            r = await c.get("/grc/frameworks/no-such/controls")
        assert r.status_code == 404


class TestMappingCRUD:
    async def test_post_then_delete_user_mapping(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        ctrl = await _pr_ps_uuid()
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/grc/mappings",
                json={
                    "control_id": ctrl,
                    "target_kind": "technique",
                    "target_id": "T1218",
                    "rationale": "LOLBin execution",
                },
            )
            assert r.status_code == 201, r.text
            created = r.json()
            assert created["source"] == "user"
            assert created["target_id"] == "T1218"
            assert created["author"]  # populated from JWT

            # Mappings list should now include the user row + seeded T1059 + T1059.001.
            rL = await c.get(f"/grc/controls/{ctrl}/mappings")
            assert rL.status_code == 200
            tids = {m["target_id"] for m in rL.json()}
            assert {"T1059", "T1059.001", "T1218"}.issubset(tids)

            # DELETE should remove it.
            rD = await c.delete(
                f"/grc/mappings/{created['id']}?target_kind=technique"
            )
            assert rD.status_code == 204

            rA = await c.get(f"/grc/controls/{ctrl}/mappings")
            tids_after = {m["target_id"] for m in rA.json()}
            assert "T1218" not in tids_after

    async def test_post_is_idempotent_upsert(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        ctrl = await _pr_ps_uuid()
        async with _client(demo_admin_token) as c:
            r1 = await c.post(
                "/grc/mappings",
                json={
                    "control_id": ctrl,
                    "target_kind": "technique",
                    "target_id": "T1218",
                    "rationale": "first",
                },
            )
            assert r1.status_code == 201
            id1 = r1.json()["id"]

            r2 = await c.post(
                "/grc/mappings",
                json={
                    "control_id": ctrl,
                    "target_kind": "technique",
                    "target_id": "T1218",
                    "rationale": "updated",
                },
            )
            assert r2.status_code == 201
            assert r2.json()["id"] == id1
            assert r2.json()["rationale"] == "updated"

    async def test_readonly_cannot_write_mappings(
        self, acme_clean, clean_grc_tables, demo_readonly_token
    ) -> None:
        await seed_grc()
        ctrl = await _pr_ps_uuid()
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                "/grc/mappings",
                json={"control_id": ctrl, "target_kind": "technique", "target_id": "T1218"},
            )
        assert r.status_code == 403

    async def test_invalid_target_kind_returns_422(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        ctrl = await _pr_ps_uuid()
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/grc/mappings",
                json={
                    "control_id": ctrl,
                    "target_kind": "snowflake",
                    "target_id": "T1218",
                },
            )
        assert r.status_code == 422


class TestEvidenceEndpoint:
    async def test_evidence_csv_round_trip(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        async with _client(demo_admin_token) as c:
            r = await c.get("/grc/evidence/nist_csf.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert r.text.splitlines()[0].startswith("framework,control_id,name")

    async def test_evidence_json_round_trip(
        self, acme_clean, clean_grc_tables, demo_admin_token
    ) -> None:
        await seed_grc()
        async with _client(demo_admin_token) as c:
            r = await c.get("/grc/evidence/iso_27001.json")
        assert r.status_code == 200
        body = json.loads(r.text)
        assert body["framework"]["key"] == "iso_27001"
        assert len(body["controls"]) >= 18
