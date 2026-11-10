"""CMF acceptance checks on an explicitly isolated cmf_test database only.

Never use acme/shared fixtures. Each run creates two random tenants and drops
only those schemas and its own public organization in teardown.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, text
from sqlalchemy.engine import make_url

from app.config import settings
from app.core.security import TokenAudience, create_access_token, hash_password
from app.db.base import AsyncSessionLocal, engine
from app.db.tenant import schema_for
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.public import Customer, CustomerStatus, MSSPOrg, Role, User
from app.services.provisioning import provision_customer
from app.scripts.cmf_classroom import apply_starter
from app.services.cmf_classroom_data import record_id


@pytest_asyncio.fixture
async def isolated_students():
    url = make_url(settings.database_url)
    if url.database != "cmf_test" or url.host not in {"127.0.0.1", "localhost"} or url.port != 15432:
        pytest.skip("requires disposable localhost:15432/cmf_test database")
    run_id = uuid.uuid4().hex[:10]
    org_id = uuid.uuid4()
    customers = [uuid.uuid4(), uuid.uuid4()]
    users = [uuid.uuid4(), uuid.uuid4()]
    codes = [f"cmftest_a_{run_id}", f"cmftest_b_{run_id}"]
    async with AsyncSessionLocal() as session, session.begin():
        session.add(MSSPOrg(id=org_id, name=f"CMF acceptance {run_id}"))
        await session.flush()
        for cid, uid, code in zip(customers, users, codes):
            session.add(Customer(id=cid, mssp_org_id=org_id, codename=code,
                                 name=code, status=CustomerStatus.ACTIVE))
            await session.flush()
            session.add(User(id=uid, email=f"{code}@cmf.test", role=Role.CUSTOMER_USER,
                             mssp_org_id=org_id, customer_id=cid,
                             hashed_password=hash_password("CmfTestOnly2026!")))
    try:
        for code in codes:
            await provision_customer(code)
        headers = [{"Authorization": "Bearer " + create_access_token(
            subject=str(uid), audience=TokenAudience.TENANT,
            claims={"role": Role.CUSTOMER_USER.value},
        )} for uid in users]
        yield codes, headers
    finally:
        async with engine.begin() as conn:
            for code in codes:
                assert code.startswith("cmftest_") and code.endswith(run_id)
                await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema_for(code)}" CASCADE'))
        async with AsyncSessionLocal() as session, session.begin():
            await session.execute(delete(MSSPOrg).where(MSSPOrg.id == org_id))


@pytest.mark.asyncio
async def test_student_collection_validation_export_and_isolation(isolated_students):
    codes, headers = isolated_students
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test",
                           headers=headers[0]) as student:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test",
                               headers=headers[1]) as other:
            response = await student.post("/assets", json={
                "name": "Control Center HMI", "kind": "workstation",
                "location": "Control Center", "cmf_category": "ot",
            })
            assert response.status_code == 201, response.text
            asset = response.json()
            aid = asset["id"]
            response = await student.post(f"/assets/{aid}/data-sources", json={
                "name": "Network sensor", "attack_data_source": "Network Traffic: Network Traffic Content",
                "kill_chain_phase": "Command and Control", "follow_on_collection": "Packet Capture",
                "storage_location": "Enterprise SIEM", "retention_days": 30,
                "timeliness_q": 4,
            })
            assert response.status_code == 201, response.text
            source = response.json()
            sid = source["id"]
            assert source["attack_data_source"] == "Network Traffic"
            assert source["attack_data_component"] == "Network Traffic Content"
            assert source["follow_on_collection"] == "Packet Capture"
            response = await student.patch(f"/assets/{aid}/data-sources/{sid}", json={
                "retention_days": None, "timeliness_q": None, "storage_location": None,
            })
            assert response.status_code == 200, response.text
            reopened = (await student.get(f"/assets/{aid}/data-sources")).json()[0]
            assert reopened["retention_days"] is None
            assert reopened["timeliness_q"] is None
            assert reopened["storage_location"] is None
            assert reopened["attack_data_component"] == "Network Traffic Content"
            assert reopened["kill_chain_phase"] == "Command and Control"
            for payload in [{"retention_days": -1}, {"retention_days": 1.5}, {"name": None}]:
                response = await student.patch(f"/assets/{aid}/data-sources/{sid}", json=payload)
                assert response.status_code == 422, response.text

            response = await student.post("/cmf/requirements", json={
                "title": "Investigate unexpected network connections", "driver": "incident",
                "priority": "high",
            })
            assert response.status_code == 201, response.text
            rid = response.json()["id"]
            response = await student.post("/cmf/plan", json={
                "data_source": "Network Traffic: Network Traffic Content", "requirement_id": rid,
                "target_asset_id": aid, "status": "proposed",
            })
            assert response.status_code == 201, response.text
            pid = response.json()["id"]
            response = await student.patch(f"/cmf/plan/{pid}", json={"status": "validated"})
            assert response.status_code == 422, response.text
            response = await student.patch(f"/cmf/plan/{pid}", json={
                "status": "validated", "asset_data_source_id": sid,
                "notes": "2026-11-10: inspected sensor sample; expected connection fields present; retention remains a gap.",
            })
            assert response.status_code == 200, response.text
            assert response.json()["asset_data_source_id"] == sid
            assert response.json()["status"] == "validated"
            for endpoint, payload in [(f"/cmf/plan/{pid}", {"status": None}),
                                      (f"/cmf/requirements/{rid}", {"title": None})]:
                response = await student.patch(endpoint, json=payload)
                assert response.status_code == 422, response.text

            assert (await other.get("/assets")).json() == []
            assert (await other.get(f"/assets/{aid}/data-sources")).status_code == 404
            assert (await other.patch(f"/cmf/plan/{pid}", json={"status": "approved"})).status_code == 404
            assert (await student.get("/assets", headers={"X-Customer": codes[1]})).status_code == 403

            response = await student.get("/cmf/export.json")
            assert response.status_code == 200, response.text
            exported = response.json()
            assert "Network sensor" in response.text
            assert "Packet Capture" in response.text
            assert "retention remains a gap" in response.text
            assert "cmf_test_only" not in response.text
            assert "hashed_password" not in response.text
            assert (await other.get("/cmf/export.json")).status_code == 200
            response = await student.get("/cmf/export.csv")
            assert response.status_code == 200, response.text
            assert "Network sensor" in response.text and "Control Center" in response.text
            # A past validation must not keep claiming current collection
            # after its underlying evidence source changes or disappears.
            response = await student.patch(f"/assets/{aid}/data-sources/{sid}", json={"enabled": False})
            assert response.status_code == 200, response.text
            plan = next(p for p in (await student.get("/cmf/plan")).json() if p["id"] == pid)
            assert plan["status"] == "in_progress"
            assert "retention remains a gap" in plan["notes"]
            response = await student.patch(f"/assets/{aid}/data-sources/{sid}", json={"enabled": True})
            assert response.status_code == 200, response.text
            response = await student.patch(f"/cmf/plan/{pid}", json={
                "status": "validated", "notes": "Source enabled and sample checked again.",
            })
            assert response.status_code == 200, response.text
            assert (await student.delete(f"/assets/{aid}/data-sources/{sid}")).status_code == 204
            plan = next(p for p in (await student.get("/cmf/plan")).json() if p["id"] == pid)
            assert plan["status"] == "in_progress" and plan["asset_data_source_id"] is None
            assert "sample checked again" in plan["notes"]


@pytest.mark.asyncio
async def test_starter_restore_is_scoped_and_preserves_student_additions(isolated_students):
    codes, headers = isolated_students
    result = await apply_starter(codes[0])
    assert result["created"] == 9
    assert (await apply_starter(codes[0]))["created"] == 0
    await apply_starter(codes[1])
    aid = str(record_id(codes[0], "asset", "rtu"))
    sid = str(record_id(codes[0], "source", "rtu"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers[0]) as student:
        response = await student.patch(f"/assets/{aid}/data-sources/{sid}", json={"retention_days": 30})
        assert response.status_code == 200, response.text
        response = await student.post(f"/assets/{aid}/data-sources", json={"name": "Student-added controller logic"})
        assert response.status_code == 201, response.text
        added_id = response.json()["id"]
        # Idempotent seeding must not erase students' edits.
        await apply_starter(codes[0])
        sources = (await student.get(f"/assets/{aid}/data-sources")).json()
        assert next(s for s in sources if s["id"] == sid)["retention_days"] == 30
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers[1]) as other:
            before = (await other.get("/cmf/export.json")).json()
            result = await apply_starter(codes[0], reset=True)
            assert result["restored"] == 9
            after = (await other.get("/cmf/export.json")).json()
            # Snapshot timestamps differ, but all tenant records must match.
            for key in ["assets", "data_sources", "requirements", "plan"]:
                if key in before:
                    assert before[key] == after[key]
        sources = (await student.get(f"/assets/{aid}/data-sources")).json()
        assert next(s for s in sources if s["id"] == sid)["retention_days"] == 7
        assert added_id in {s["id"] for s in sources}


@pytest.mark.asyncio
async def test_existing_source_mapping_is_repaired_by_tenant_migration(isolated_students):
    codes, headers = isolated_students
    code = codes[0]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers[0]) as student:
        response = await student.post("/assets", json={"name": "Migration HMI", "kind": "workstation"})
        assert response.status_code == 201, response.text
        aid = response.json()["id"]
        response = await student.post(f"/assets/{aid}/data-sources", json={"name": "Legacy feed"})
        assert response.status_code == 201, response.text
        sid = response.json()["id"]
        env = {**os.environ, "DETECTMAP_TARGET_SCHEMA": schema_for(code)}
        backend = Path(__file__).resolve().parents[1]
        async def migrate(target):
            command = [sys.executable, "-m", "alembic", "-n", "customer", *target]
            result = await asyncio.to_thread(subprocess.run, command, cwd=backend, env=env,
                                             capture_output=True, text=True)
            assert result.returncode == 0, result.stdout + result.stderr
        await engine.dispose()
        await migrate(["downgrade", "0012_detection_review_gate"])
        set_tenant(code)
        try:
            async with tenant_session() as session:
                await session.execute(text("UPDATE asset_data_sources SET attack_data_source=:source, attack_data_component=:component WHERE id=:id"),
                                      {"source": "Process: Process Creation", "component": "Obsolete Component", "id": uuid.UUID(sid)})
        finally:
            set_tenant(None)
        await engine.dispose()
        await migrate(["upgrade", "head"])
        sources = (await student.get(f"/assets/{aid}/data-sources")).json()
        assert sources[0]["attack_data_source"] == "Process"
        assert sources[0]["attack_data_component"] == "Process Creation"
        assert sources[0]["kill_chain_phase"] is None
