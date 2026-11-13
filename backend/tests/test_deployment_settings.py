"""An org can hide and recover samples without changing its own workspace."""
from __future__ import annotations

import uuid

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from app.core.security import TokenAudience, create_access_token
from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for
from app.main import app
from app.models.public import AuditLog, Customer, MSSPOrg, Role, User


@pytest_asyncio.fixture
async def deployment_admin():
    org_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    email = f"deployment-{admin_id.hex}@test.local"
    async with AsyncSessionLocal.begin() as session:
        session.add(MSSPOrg(id=org_id, name=f"Test deployment {org_id}"))
        await session.flush()
        session.add(User(id=admin_id, mssp_org_id=org_id, role=Role.MSSP_ADMIN, email=email))

    yield create_access_token(subject=str(admin_id), audience=TokenAudience.TENANT)

    async with AsyncSessionLocal.begin() as session:
        customers = await session.scalars(select(Customer.codename).where(Customer.mssp_org_id == org_id))
        for codename in customers:
            await session.execute(text(f'DROP SCHEMA IF EXISTS "{schema_for(codename)}" CASCADE'))
        await session.execute(delete(AuditLog).where(AuditLog.actor_email == email))
        await session.execute(delete(MSSPOrg).where(MSSPOrg.id == org_id))


async def test_deployment_can_show_and_hide_samples_without_losing_data(deployment_admin):
    path = "/settings/mssp/environment"
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", headers={"Authorization": f"Bearer {deployment_admin}"},
    ) as client:
        codename = f"test_environment_{uuid.uuid4().hex[:8]}"
        created = await client.post("/customers", json={"codename": codename, "name": "Test environment"})
        assert created.status_code == 201, created.text

        rejected = await client.patch(path, json={"mode": "single", "primary_customer": codename})
        assert rejected.status_code == 422, rejected.text
        configured = await client.get(path)
        assert configured.json()["initial_customer"] == codename
        regular = {"X-Customer": codename}
        marker = await client.post("/assets", json={"name": "Test controller", "kind": "iot_ot"}, headers=regular)
        assert marker.status_code == 201, marker.text

        enabled = await client.patch(path, json={"sample_data_enabled": True})
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["mode"] == "multi_tenant"
        sample = next(item["codename"] for item in enabled.json()["environments"] if item["is_sample"])
        sample_scope = {"X-Customer": sample}
        detections = await client.get("/detections", params={"source": "custom"}, headers=sample_scope)
        assert detections.status_code == 200, detections.text
        assert detections.json()["total"] > 0
        assert (await client.get("/assets", headers=sample_scope)).json()
        assert (await client.get("/networks", headers=sample_scope)).json()
        sample_edit = await client.post("/assets", json={"name": "Sample test asset", "kind": "iot_ot"},
                                        headers=sample_scope)
        assert sample_edit.status_code == 201, sample_edit.text

        disabled = await client.patch(path, json={"sample_data_enabled": False})
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["initial_customer"] == codename
        assert not any(item["is_sample"] for item in disabled.json()["environments"])
        assert (await client.get("/assets", headers=sample_scope)).status_code == 403
        assert (await client.get(f"/customers/{sample}/users")).status_code == 404
        assets = await client.get("/assets", headers=regular)
        assert [asset["id"] for asset in assets.json()] == [marker.json()["id"]]

        multi = await client.patch(path, json={"sample_data_enabled": True})
        assert multi.status_code == 200, multi.text
        assets = await client.get("/assets", headers=sample_scope)
        assert sample_edit.json()["id"] in {asset["id"] for asset in assets.json()}
