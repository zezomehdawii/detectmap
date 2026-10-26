"""Non-destructive smoke tests for endpoints added in this feature push.

These talk to the live dev DB but only touch tenant rows inside the
existing `cust_acme` schema (which the demo seed always provisions) and
roll back any per-test mutations. They do NOT wipe public reference
tables, so running `pytest -q` does not destroy the seeded ATT&CK
catalog, sectors, or GRC controls.

Tests rely on `demo_admin_token` from conftest and the fact that the
default seeded MSSP org owns `acme` + `globex`. If those don't exist
yet, run `python -m app.scripts.bootstrap` and `provision_customer`
before invoking pytest.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import (
    Detection,
    DetectionEventSample,
    DetectionOutcome,
    SavedView,
)


def _client(token: str, customer: str = "acme") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Customer": customer,
        },
    )


@pytest_asyncio.fixture
async def acme_detection_id() -> str:
    """Return any existing detection id in cust_acme. Skip if none."""
    set_tenant("acme")
    try:
        async with tenant_session() as session:
            row = (
                await session.execute(select(Detection).limit(1))
            ).scalar_one_or_none()
            if row is None:
                pytest.skip("cust_acme has no detections — run seed_dummy_data first")
            return str(row.id)
    finally:
        set_tenant(None)


# ---- /search ------------------------------------------------------------

class TestGlobalSearch:
    async def test_search_returns_techniques_for_known_term(self, demo_admin_token):
        async with _client(demo_admin_token) as c:
            r = await c.get("/search", params={"q": "powershell"})
        assert r.status_code == 200
        hits = r.json()["hits"]
        kinds = {h["kind"] for h in hits}
        assert "technique" in kinds  # T1059.001 PowerShell

    async def test_search_short_query_returns_empty(self, demo_admin_token):
        async with _client(demo_admin_token) as c:
            r = await c.get("/search", params={"q": "a"})
        assert r.status_code == 200
        assert r.json()["hits"] == []


# ---- /views CRUD --------------------------------------------------------

class TestSavedViews:
    async def test_save_list_delete_roundtrip(self, demo_admin_token):
        name = f"pytest-view-{uuid.uuid4().hex[:6]}"
        body = {
            "name": name,
            "kind": "coverage_matrix",
            "payload": {"kind": "full", "ref": "", "stateFilter": ["gap"]},
        }
        async with _client(demo_admin_token) as c:
            cr = await c.post("/views", json=body)
            assert cr.status_code == 201
            view_id = cr.json()["id"]

            lr = await c.get("/views", params={"kind": "coverage_matrix"})
            assert lr.status_code == 200
            assert any(v["id"] == view_id for v in lr.json())

            dr = await c.delete(f"/views/{view_id}")
            assert dr.status_code == 204


# ---- /coverage/denominator/custom + /matrix-custom ---------------------

class TestCustomDenominator:
    async def test_finance_sector_intersection(self, demo_admin_token):
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/coverage/denominator/custom",
                json={"sectors": ["finance"], "operator": "union"},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["technique_count"] > 0
        assert isinstance(body["technique_ids"], list)

    async def test_empty_intersection_yields_422_on_matrix(self, demo_admin_token):
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/coverage/matrix-custom",
                json={
                    "sectors": ["finance"],
                    "platforms": ["nonsense-platform"],
                    "operator": "union",
                },
            )
        assert r.status_code == 422


# ---- /detections/{id}/outcomes ------------------------------------------

class TestDetectionOutcomes:
    async def test_create_summary_delete_outcome(
        self, demo_admin_token, acme_detection_id
    ):
        async with _client(demo_admin_token) as c:
            cr = await c.post(
                f"/detections/{acme_detection_id}/outcomes",
                json={"kind": "tp", "summary": "test outcome"},
            )
            assert cr.status_code == 201
            outcome_id = cr.json()["id"]

            sr = await c.get(f"/detections/{acme_detection_id}/effectiveness")
            assert sr.status_code == 200
            assert sr.json()["tp"] >= 1

            dr = await c.delete(f"/detections/outcomes/{outcome_id}")
            assert dr.status_code == 204

    async def test_invalid_outcome_kind_rejected(
        self, demo_admin_token, acme_detection_id
    ):
        async with _client(demo_admin_token) as c:
            r = await c.post(
                f"/detections/{acme_detection_id}/outcomes",
                json={"kind": "garbage"},
            )
        assert r.status_code == 422


# ---- /detections/{id}/samples + /run ------------------------------------

class TestDetectionSamples:
    async def test_create_run_delete_sample(
        self, demo_admin_token, acme_detection_id
    ):
        async with _client(demo_admin_token) as c:
            cr = await c.post(
                f"/detections/{acme_detection_id}/samples",
                json={
                    "label": "pytest positive",
                    "kind": "positive",
                    "event": {"Image": "C:\\Windows\\System32\\powershell.exe"},
                },
            )
            assert cr.status_code == 201
            sample_id = cr.json()["id"]

            rr = await c.post(f"/detections/{acme_detection_id}/samples/run")
            assert rr.status_code == 200
            assert any(x["sample_id"] == sample_id for x in rr.json())

            dr = await c.delete(f"/detections/samples/{sample_id}")
            assert dr.status_code == 204


# ---- /portfolio/compare -------------------------------------------------

class TestPortfolioCompare:
    async def test_compare_two_customers(self, demo_admin_token):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get(
                "/portfolio/compare", params={"customers": "acme,globex"}
            )
        if r.status_code == 422:
            pytest.skip("either acme or globex not provisioned")
        assert r.status_code == 200
        body = r.json()
        codes = {c["codename"] for c in body["customers"]}
        assert codes == {"acme", "globex"}

    async def test_compare_rejects_single_customer(self, demo_admin_token):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/portfolio/compare", params={"customers": "acme"})
        assert r.status_code == 422


# ---- /detections/suggestions + /promote --------------------------------

class TestCrossCustomerPromotion:
    async def test_suggestions_then_promote_then_undo(
        self, demo_admin_token
    ):
        async with _client(demo_admin_token, customer="acme") as c:
            sug = await c.get("/detections/suggestions")
        if sug.status_code != 200 or not sug.json():
            pytest.skip("no cross-tenant suggestions available")
        first = sug.json()[0]

        async with _client(demo_admin_token, customer="acme") as c:
            pr = await c.post(
                "/detections/promote",
                json={
                    "source_codename": first["source_customer_codename"],
                    "source_detection_id": first["detection_id"],
                },
            )
        # 409 is fine if a previous run already imported this rule
        assert pr.status_code in {201, 409}
        if pr.status_code == 201:
            promoted_id = pr.json()["id"]
            # Cleanup so the test is idempotent on the shared dev DB.
            set_tenant("acme")
            try:
                async with tenant_session() as session:
                    await session.execute(
                        delete(Detection).where(Detection.id == uuid.UUID(promoted_id))
                    )
            finally:
                set_tenant(None)
