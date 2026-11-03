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
                json={"detection_status": "tuning", "score_breadth": 3},
            )
        assert r2.status_code == 200
        body = r2.json()
        assert body["id"] == det_id
        assert body["detection_status"] == "tuning"
        assert body["score_breadth"] == 3
        assert body["source"] == "custom"
        assert body["review_status"] == "draft"

    async def test_patch_global_clones_to_customized(
        self, acme_clean, demo_admin_token
    ) -> None:
        global_id = await _post_global_row_directly()
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/detections/{global_id}",
                json={"detection_status": "tuning", "score_breadth": 5},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["id"] != global_id
        assert body["source"] == "customized"
        assert body["upstream_global_id"] == "33333333-3333-3333-3333-333333333333"
        assert body["detection_status"] == "tuning"
        assert body["score_breadth"] == 5
        assert body["review_status"] == "draft"

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

    async def test_readonly_cannot_review(
        self, acme_clean, demo_admin_token, demo_readonly_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                f"/detections/{det['id']}/review",
                json={"action": "submit"},
            )
        assert r.status_code == 403


async def _create(c, rule: str = SAMPLE_RULE) -> dict:
    r = await c.post("/detections", json={"raw_yaml": rule})
    assert r.status_code == 201, r.text
    return r.json()


async def _review(c, detection_id: str, action: str, **payload):
    return await c.post(
        f"/detections/{detection_id}/review",
        json={"action": action, **payload},
    )


class TestDetectionReviewGate:
    async def test_deploy_requires_approval(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert det["review_status"] == "draft"
            assert det["owner"] is None

            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 409
            assert "Approval required" in r.json()["detail"]

            r = await _review(
                c,
                det["id"],
                "submit",
                reviewer_email="reviewer@example.com",
                note="please review",
            )
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "in_review"
            assert body["reviewer_email"] == "reviewer@example.com"
            assert body["review_requested_at"] is not None
            assert [e["action"] for e in body["review_events"]] == ["submit"]

            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 409

            r = await _review(c, det["id"], "approve", note="looks good")
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "approved"
            assert body["reviewed_at"] is not None
            assert body["review_note"] == "looks good"
            assert body["reviewer_email"] == "reviewer@example.com"
            assert body["review_events"][0]["action"] == "approve"

            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 200
            assert r.json()["detection_status"] == "deployed"

    async def test_substantive_edit_invalidates_approval(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert (await _review(c, det["id"], "submit")).status_code == 200
            assert (await _review(c, det["id"], "approve")).status_code == 200
            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 200

            r = await c.patch(
                f"/detections/{det['id']}",
                json={"score_depth": 4},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "draft"
            assert body["detection_status"] == "deployed"
            assert body["review_events"][0]["action"] == "invalidated"

            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "tuning"},
            )
            assert r.status_code == 200
            r = await c.patch(
                f"/detections/{det['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 409

    async def test_edit_and_deploy_in_one_patch_is_rejected(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert (await _review(c, det["id"], "submit")).status_code == 200
            assert (await _review(c, det["id"], "approve")).status_code == 200
            r = await c.patch(
                f"/detections/{det['id']}",
                json={
                    "detection_status": "deployed",
                    "description": "edited at promotion time",
                },
            )
            assert r.status_code == 409
            assert "substantive edits" in r.json()["detail"]

    async def test_request_changes_and_resubmit(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert (await _review(c, det["id"], "submit")).status_code == 200
            r = await _review(
                c,
                det["id"],
                "request_changes",
                note="add a negative test",
            )
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "changes_requested"
            assert body["review_note"] == "add a negative test"

            r = await _review(c, det["id"], "submit", note="updated")
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "in_review"
            assert [e["action"] for e in body["review_events"]] == [
                "submit",
                "request_changes",
                "submit",
            ]

    async def test_reset_review_clears_assignment(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert (
                await _review(
                    c,
                    det["id"],
                    "submit",
                    reviewer_email="reviewer@example.com",
                    review_due_at="2026-12-01T17:00:00Z",
                )
            ).status_code == 200
            assert (await _review(c, det["id"], "approve")).status_code == 200
            r = await _review(c, det["id"], "reset")
            assert r.status_code == 200
            body = r.json()
            assert body["review_status"] == "draft"
            assert body["reviewer_email"] is None
            assert body["review_requested_at"] is None
            assert body["reviewed_at"] is None
            assert body["review_due_at"] is None
            assert body["review_events"][0]["action"] == "reset"

    async def test_owner_change_does_not_invalidate_approval(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            assert (await _review(c, det["id"], "submit")).status_code == 200
            assert (await _review(c, det["id"], "approve")).status_code == 200
            r = await c.patch(
                f"/detections/{det['id']}",
                json={"owner": "soc-owner@example.com"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["owner"] == "soc-owner@example.com"
            assert body["review_status"] == "approved"

    async def test_invalid_review_transition(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            det = await _create(c)
            r = await _review(c, det["id"], "approve")
            assert r.status_code == 409
            r = await _review(c, det["id"], "ship_it")
            assert r.status_code == 422

    async def test_global_rule_cannot_be_reviewed(
        self, acme_clean, demo_admin_token
    ) -> None:
        global_id = await _post_global_row_directly()
        async with _client(demo_admin_token) as c:
            r = await _review(c, global_id, "submit")
        assert r.status_code == 409
        assert "Customize" in r.json()["detail"]

    async def test_global_customization_must_be_reviewed_before_deploy(
        self, acme_clean, demo_admin_token
    ) -> None:
        global_id = await _post_global_row_directly()
        async with _client(demo_admin_token) as c:
            r = await c.patch(
                f"/detections/{global_id}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 409

            r = await c.patch(
                f"/detections/{global_id}",
                json={"detection_status": "tuning"},
            )
            assert r.status_code == 200
            cloned = r.json()
            assert cloned["review_status"] == "draft"

            assert (await _review(c, cloned["id"], "submit")).status_code == 200
            assert (await _review(c, cloned["id"], "approve")).status_code == 200
            r = await c.patch(
                f"/detections/{cloned['id']}",
                json={"detection_status": "deployed"},
            )
            assert r.status_code == 200

    async def test_create_cannot_start_deployed(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/detections",
                json={"raw_yaml": SAMPLE_RULE, "detection_status": "deployed"},
            )
        assert r.status_code == 409

    async def test_bulk_status_blocks_unapproved(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            approved = await _create(c, SAMPLE_RULE)
            pending = await _create(c, OTHER_RULE)
            assert (await _review(c, approved["id"], "submit")).status_code == 200
            assert (await _review(c, approved["id"], "approve")).status_code == 200

            r = await c.post(
                "/detections/bulk-status",
                json={
                    "ids": [approved["id"], pending["id"]],
                    "detection_status": "deployed",
                },
            )
            assert r.status_code == 200
            body = r.json()
            assert body["updated"] == 1
            assert body["blocked"] == 1
            assert body["skipped"] == 0

            r = await c.get(f"/detections/{approved['id']}")
            assert r.json()["detection_status"] == "deployed"
            r = await c.get(f"/detections/{pending['id']}")
            assert r.json()["detection_status"] == "idea"

    async def test_filter_by_review_status(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            approved = await _create(c, SAMPLE_RULE)
            await _create(c, OTHER_RULE)
            assert (await _review(c, approved["id"], "submit")).status_code == 200
            assert (await _review(c, approved["id"], "approve")).status_code == 200

            r = await c.get("/detections?review_status=approved")
            assert r.status_code == 200
            body = r.json()
            assert body["total"] == 1
            assert body["items"][0]["id"] == approved["id"]

            r = await c.get("/detections?review_status=not-a-state")
            assert r.status_code == 422
