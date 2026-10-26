"""Integration tests for /detections/* endpoints.

These reuse the seeded `acme` customer (provisioned by `app.scripts.seed_demo`)
and a demo_admin_token (mssp_admin). Each test wipes acme.detections so it starts
from a clean slate.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app


SAMPLE_RULE = """
title: Test PowerShell EncodedCommand
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: A test sigma rule.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  s:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: s
level: high
"""

OTHER_RULE = """
title: Test Valid Accounts
id: 22222222-2222-2222-2222-222222222222
status: experimental
tags:
  - attack.t1078.004
logsource:
  product: aws
detection:
  s:
    eventName: ConsoleLogin
  condition: s
level: medium
"""


async def _ensure_acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return row.scalar_one_or_none() is not None


async def _wipe_acme_detections() -> None:
    async with tenant_session() as session:
        await session.execute(text("DELETE FROM detection_techniques"))
        await session.execute(text("DELETE FROM detections"))


@pytest_asyncio.fixture
async def acme_clean():
    """Skip if acme isn't provisioned (developer hasn't run seed_demo yet)."""
    if not await _ensure_acme_exists():
        pytest.skip("cust_acme schema not provisioned — run seed_demo first")
    # Wipe before the test. HTTP requests inside the test manage their own
    # tenant context via the middleware; we re-set just before the post-wipe.
    set_tenant("acme")
    try:
        await _wipe_acme_detections()
    finally:
        set_tenant(None)
    yield
    set_tenant("acme")
    try:
        await _wipe_acme_detections()
    finally:
        set_tenant(None)


async def _post_global_row_directly() -> str:
    """Insert a `source='global'` detection so PATCH-clone can be exercised."""
    set_tenant("acme")
    try:
        det_id = uuid.uuid4()
        async with tenant_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO detections
                      (id, sigma_id, title, description, level, sigma_references,
                       tags, logsource, detection, falsepositives, raw_yaml,
                       detection_status, source, score_breadth, score_depth,
                       upstream_global_id)
                    VALUES
                      (:id, :sid, 'Seeded Global Rule', 'desc', 'medium',
                       '[]'::jsonb, '["attack.t1059.001"]'::jsonb,
                       '{"product":"windows"}'::jsonb,
                       '{"s":{"a":"b"},"condition":"s"}'::jsonb,
                       '[]'::jsonb, :raw, 'idea', 'global', 0, 0, :gid)
                    """
                ),
                {
                    "id": det_id,
                    "sid": "33333333-3333-3333-3333-333333333333",
                    "raw": SAMPLE_RULE,
                    "gid": "33333333-3333-3333-3333-333333333333",
                },
            )
            await session.execute(
                text(
                    """
                    INSERT INTO detection_techniques
                      (id, detection_id, technique_id, domain)
                    VALUES (:tid, :did, 'T1059.001', 'enterprise')
                    """
                ),
                {"tid": uuid.uuid4(), "did": det_id},
            )
        return str(det_id)
    finally:
        set_tenant(None)


def _client(token: str):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": "acme"},
    )


class TestDetectionsCRUD:
    async def test_empty_list(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/detections")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["items"] == []

    async def test_create_and_get(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            assert r.status_code == 201
            created = r.json()
            assert created["source"] == "custom"
            assert created["sigma_id"] == "11111111-1111-1111-1111-111111111111"
            assert "T1059.001" in created["techniques"]

            r2 = await c.get(f"/detections/{created['id']}")
        assert r2.status_code == 200
        body = r2.json()
        assert body["title"].startswith("Test PowerShell")
        assert body["techniques"] == ["T1059.001"]

    async def test_create_rejects_invalid_yaml(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post("/detections", json={"raw_yaml": "not: valid: sigma"})
        assert r.status_code == 422

    async def test_duplicate_sigma_id_conflicts(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r1 = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            assert r1.status_code == 201
            r2 = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
        assert r2.status_code == 409

    async def test_patch_custom_mutates(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            det_id = r.json()["id"]
            r2 = await c.patch(
                f"/detections/{det_id}",
                json={"detection_status": "deployed", "score_breadth": 3},
            )
        assert r2.status_code == 200
        body = r2.json()
        assert body["id"] == det_id
        assert body["detection_status"] == "deployed"
        assert body["score_breadth"] == 3
        assert body["source"] == "custom"

    async def test_patch_global_clones_to_customized(
        self, acme_clean, demo_admin_token
    ) -> None:
        global_id = await _post_global_row_directly()
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/detections/{global_id}",
                json={"detection_status": "deployed", "score_breadth": 5},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["id"] != global_id
        assert body["source"] == "customized"
        assert body["upstream_global_id"] == "33333333-3333-3333-3333-333333333333"
        assert body["detection_status"] == "deployed"
        assert body["score_breadth"] == 5

        # Original global row left intact.
        async with _client(demo_admin_token) as c:
            r2 = await c.get(f"/detections/{global_id}")
        assert r2.status_code == 200
        assert r2.json()["source"] == "global"
        assert r2.json()["detection_status"] == "idea"

    async def test_delete_custom(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            det_id = r.json()["id"]
            rd = await c.delete(f"/detections/{det_id}")
            assert rd.status_code == 204
            rg = await c.get(f"/detections/{det_id}")
        assert rg.status_code == 404

    async def test_delete_global_refused(self, acme_clean, demo_admin_token) -> None:
        global_id = await _post_global_row_directly()
        async with _client(demo_admin_token) as c:
            rd = await c.delete(f"/detections/{global_id}")
        assert rd.status_code == 409

    async def test_export_yaml(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            det_id = r.json()["id"]
            rx = await c.get(f"/detections/{det_id}/export")
        assert rx.status_code == 200
        assert "application/x-yaml" in rx.headers.get("content-type", "")
        assert b"Test PowerShell" in rx.content

    async def test_filter_by_technique(self, acme_clean, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
            await c.post("/detections", json={"raw_yaml": OTHER_RULE})
            r = await c.get("/detections?technique_id=T1059.001")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["sigma_id"] == "11111111-1111-1111-1111-111111111111"


class TestRBAC:
    async def test_readonly_cannot_create(self, acme_clean, demo_readonly_token) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post("/detections", json={"raw_yaml": SAMPLE_RULE})
        assert r.status_code == 403

    async def test_readonly_can_read(self, acme_clean, demo_readonly_token) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.get("/detections")
        assert r.status_code == 200
