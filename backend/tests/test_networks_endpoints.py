"""Test network registration and scoping using fresh tenant schemas."""
from __future__ import annotations

import asyncio
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import delete, func, select, text

from app.api.networks import NetworkCreate, NetworkPatch
from app.core.rbac import Permission
from app.core.security import TokenAudience, create_access_token
from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for, set_tenant, tenant_session
from app.main import app
from app.models.customer import Detection, NetworkDataSource, NetworkDetection
from app.models.public import Customer, CustomerStatus, CustomRole, MSSPOrg, Role, User
from app.services.provisioning import provisioned_customer


def _client(user: User, codename: str | None = None) -> AsyncClient:
    token = create_access_token(subject=str(user.id), audience=TokenAudience.TENANT)
    headers = {"Authorization": f"Bearer {token}"}
    if codename is not None:
        headers["X-Customer"] = codename
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers)


@pytest_asyncio.fixture
async def workspaces():
    run_id = uuid.uuid4().hex[:12]
    names = (f"nettest_a_{run_id}", f"nettest_b_{run_id}")
    async with AsyncSessionLocal() as session, session.begin():
        org = MSSPOrg(name=f"Network tests {run_id}")
        session.add(org)
        await session.flush()
        customers = [
            Customer(mssp_org_id=org.id, codename=name, name=name, status=CustomerStatus.ACTIVE)
            for name in names
        ]
        asset_role = CustomRole(
            mssp_org_id=org.id,
            key="network_assets",
            label="Asset editor",
            permissions=[Permission.ASSET_READ.value, Permission.ASSET_WRITE.value],
        )
        session.add_all([*customers, asset_role])
        await session.flush()

        def make_user(label: str, role: Role, **fields) -> User:
            return User(email=f"{label}-{run_id}@detectmap.test", role=role, mssp_org_id=org.id, **fields)

        users = {
            "admin": make_user("admin", Role.MSSP_ADMIN),
            "readonly": make_user("readonly", Role.MSSP_READONLY),
            "student": make_user("student", Role.CUSTOMER_USER, customer_id=customers[0].id),
            "asset_editor": make_user("editor", Role.MSSP_ANALYST, custom_role_id=asset_role.id),
        }
        session.add_all(users.values())
        for name in names:
            async with provisioned_customer(session, name):
                pass

    try:
        yield names, users
    finally:
        async with AsyncSessionLocal() as session, session.begin():
            for name in names:
                await session.execute(text(f'DROP SCHEMA IF EXISTS "{schema_for(name)}" CASCADE'))
            await session.execute(delete(MSSPOrg).where(MSSPOrg.id == org.id))


@pytest.mark.parametrize(("raw", "canonical"), [
    (" 192.0.2.42/24 ", "192.0.2.0/24"),
    ("2001:0DB8:0123:0:0:0:0:ab/48", "2001:db8:123::/48"),
    ("::/0", "::/0"),
    ("0.0.0.0/0", "0.0.0.0/0"),
    ("192.0.2.42/32", "192.0.2.42/32"),
])
def test_network_input_canonicalizes_cidr(raw, canonical):
    assert NetworkCreate(name=" Test ", cidr=raw).cidr == canonical
    assert NetworkPatch(cidr=raw).cidr == canonical


@pytest.mark.parametrize("raw", [
    "192.0.2.0", "192.0.2.0/33", "192.0.2.0/255.255.255.0", "2001:db8::/129",
    "fe80::%eth0/128", "invalid", None,
])
def test_network_input_rejects_invalid_cidr(raw):
    with pytest.raises(ValidationError):
        NetworkCreate(name="Test", cidr=raw)
    with pytest.raises(ValidationError):
        NetworkPatch(cidr=raw)


async def test_register_edit_delete_and_duplicate_network(workspaces):
    (name, _), users = workspaces
    async with _client(users["admin"], name) as client:
        assert (await client.get("/networks")).json() == []
        created = await client.post("/networks", json={
            "name": " Control network ",
            "cidr": "192.0.2.19/24",
            "description": "Control endpoints",
            "location": "Substation",
        })
        assert created.status_code == 201, created.text
        row = created.json()
        path = f"/networks/{row['id']}"
        assert row["name"] == "Control network"
        assert row["cidr"] == "192.0.2.0/24"
        assert (await client.get("/networks")).json() == [row]
        assert (await client.get(path)).json() == row
        duplicate = await client.post("/networks", json={"name": "Duplicate", "cidr": "192.0.2.42/24"})
        assert duplicate.status_code == 409, duplicate.text
        overlapping = await client.post("/networks", json={"name": "Segment", "cidr": "192.0.2.1/25"})
        assert overlapping.status_code == 201, overlapping.text
        conflict = await client.patch(path, json={"cidr": "192.0.2.44/25"})
        assert conflict.status_code == 409, conflict.text
        updated = await client.patch(path, json={"cidr": "2001:0db8:ffff::abcd/64", "description": None})
        assert updated.status_code == 200, updated.text
        assert updated.json()["cidr"] == "2001:db8:ffff::/64"
        assert updated.json()["description"] is None
        assert updated.json()["location"] == "Substation"
        for payload in ({"name": None}, {"name": " "}, {"cidr": None}):
            assert (await client.patch(path, json=payload)).status_code == 422
        assert (await client.delete(path)).status_code == 204
        assert (await client.get(path)).status_code == 404


async def test_concurrent_registration_preserves_one_canonical_network(workspaces):
    (name, _), users = workspaces
    async with _client(users["admin"], name) as client:
        outcomes = await asyncio.gather(
            client.post("/networks", json={"name": "Sensor 1", "cidr": "198.51.100.12/24"}),
            client.post("/networks", json={"name": "Sensor 2", "cidr": "198.51.100.9/24"}),
        )
        assert sorted(response.status_code for response in outcomes) == [201, 409]
        assert len((await client.get("/networks")).json()) == 1


async def test_network_reads_and_writes_respect_active_customer_and_permissions(workspaces):
    (name, other_name), users = workspaces
    async with _client(users["student"]) as student:
        created = await student.post("/networks", json={"name": "Student", "cidr": "203.0.113.0/24"})
        assert created.status_code == 201, created.text
        path = f"/networks/{created.json()['id']}"
        assert (await student.get(path)).status_code == 200
        assert (await student.get(path, headers={"X-Customer": other_name})).status_code == 403
    async with _client(users["admin"], other_name) as other:
        assert (await other.get("/networks")).json() == []
        assert (await other.get(path)).status_code == 404
        assert (await other.patch(path, json={"name": "No"})).status_code == 404
        assert (await other.delete(path)).status_code == 404
        same_cidr = await other.post("/networks", json={"name": "Other", "cidr": "203.0.113.0/24"})
        assert same_cidr.status_code == 201, same_cidr.text
    async with _client(users["readonly"], name) as readonly:
        assert (await readonly.get(path)).status_code == 200
        assert (await readonly.post("/networks", json={"name": "No", "cidr": "203.0.113.0/24"})).status_code == 403
        assert (await readonly.patch(path, json={"name": "No"})).status_code == 403
        assert (await readonly.delete(path)).status_code == 403
        assert (await readonly.put(f"{path}/data-sources/{uuid.uuid4()}")).status_code == 403
    async with _client(users["admin"]) as unscoped:
        assert (await unscoped.get("/networks")).status_code == 400


async def test_network_evidence_links_are_idempotent_and_remove_only_mappings(workspaces):
    (name, other_name), users = workspaces
    async with _client(users["admin"], name) as client:
        network = (await client.post("/networks", json={"name": "Control", "cidr": "192.0.2.0/24"})).json()
        path = f"/networks/{network['id']}"
        asset = (await client.post("/assets", json={
            "name": "External tap", "kind": "network_device", "ip_address": "198.51.100.20",
        })).json()
        source_path = f"/assets/{asset['id']}/data-sources"
        source = await client.post(source_path, json={"name": "Packet telemetry"})
        assert source.status_code == 201, source.text
        source_id = source.json()["id"]

        options = (await client.get("/networks/data-source-options", params={"q": "external"})).json()
        assert options == [{
            "id": source_id, "name": "Packet telemetry", "asset_id": asset["id"],
            "asset_name": "External tap", "enabled": True,
        }]

        set_tenant(name)
        try:
            async with tenant_session() as session:
                detection = Detection(sigma_id=str(uuid.uuid4()), title="Packet anomaly")
                session.add(detection)
                await session.flush()
                rule_id = detection.id
        finally:
            set_tenant(None)

        source_link = f"{path}/data-sources/{source_id}"
        rule_link = f"{path}/detections/{rule_id}"
        assert (await client.put(f"{path}/data-sources/{uuid.uuid4()}")).status_code == 422
        assert (await client.put(f"{path}/detections/{uuid.uuid4()}")).status_code == 422
        for endpoint in (source_link, rule_link):
            assert (await client.put(endpoint)).status_code == 204
            assert (await client.put(endpoint)).status_code == 204
        assert (await client.patch(path, json={"cidr": "203.0.113.0/24"})).status_code == 200

        async with _client(users["admin"], other_name) as other:
            other_network = (await other.post("/networks", json={
                "name": "Other", "cidr": "192.0.2.0/24",
            })).json()
            other_path = f"/networks/{other_network['id']}"
            assert (await other.get("/networks/data-source-options")).json() == []
            assert (await other.put(f"{other_path}/data-sources/{source_id}")).status_code == 422
            assert (await other.put(f"{other_path}/detections/{rule_id}")).status_code == 422
            assert (await other.put(source_link)).status_code == 404

        async with _client(users["asset_editor"], name) as editor:
            assert (await editor.put(source_link)).status_code == 204
            assert (await editor.put(rule_link)).status_code == 403
            assert (await editor.delete(rule_link)).status_code == 403
            response = await editor.get(f"{path}/coverage")
            assert response.status_code == 200, response.text
            assert response.json()["detection_evidence_available"] is False
            assert response.json()["connector_evidence_available"] is False
            assert "Packet anomaly" not in response.text

        set_tenant(name)
        try:
            async with tenant_session() as session:
                assert await session.scalar(select(func.count()).select_from(NetworkDataSource)) == 1
                assert await session.scalar(select(func.count()).select_from(NetworkDetection)) == 1
        finally:
            set_tenant(None)

        assert (await client.delete(source_link)).status_code == 204
        assert (await client.delete(source_link)).status_code == 204
        assert (await client.get(source_path)).json()[0]["id"] == source_id
        assert (await client.put(source_link)).status_code == 204
        assert (await client.delete(f"{source_path}/{source_id}")).status_code == 204
        assert (await client.delete(path)).status_code == 204
        set_tenant(name)
        try:
            async with tenant_session() as session:
                assert await session.scalar(select(func.count()).select_from(NetworkDataSource)) == 0
                assert await session.scalar(select(func.count()).select_from(NetworkDetection)) == 0
                assert await session.get(Detection, rule_id) is not None
        finally:
            set_tenant(None)
