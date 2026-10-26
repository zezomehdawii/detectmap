"""Integration tests for /catalog/attack/* endpoints.

Uses httpx ASGITransport so the requests hit the FastAPI app in-process.
Database state is seeded via the ingest service with fixture bundles.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.attack_ingest import refresh_domain

pytestmark = pytest.mark.wipes_db


@pytest.mark.asyncio
class TestRefreshEndpoint:
    async def test_refresh_requires_super_admin(
        self, clean_attack_tables, tenant_token
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/catalog/attack/refresh",
                headers={"Authorization": f"Bearer {tenant_token}"},
                json={"domains": ["enterprise"]},
            )
        assert r.status_code == 401

    async def test_refresh_unknown_domain_400(
        self, clean_attack_tables, super_admin_token
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/catalog/attack/refresh",
                headers={"Authorization": f"Bearer {super_admin_token}"},
                json={"domains": ["bogus"]},
            )
        assert r.status_code == 400


@pytest.mark.asyncio
class TestReadEndpoints:
    async def test_paginated_techniques(
        self, clean_attack_tables, fetch_v1, tenant_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_v1)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/catalog/attack/techniques?domain=enterprise&page_size=2",
                headers={"Authorization": f"Bearer {tenant_token}"},
            )
        assert r.status_code == 200
        payload = r.json()
        assert payload["total"] == 3
        assert payload["page"] == 1
        assert payload["page_size"] == 2
        assert len(payload["items"]) == 2

    async def test_techniques_filter_by_tactic(
        self, clean_attack_tables, fetch_v1, tenant_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_v1)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/catalog/attack/techniques?tactic=credential-access",
                headers={"Authorization": f"Bearer {tenant_token}"},
            )
        assert r.status_code == 200
        items = r.json()["items"]
        tids = [t["technique_id"] for t in items]
        assert tids == ["T1003"]

    async def test_technique_with_mitigations(
        self, clean_attack_tables, fetch_v1, tenant_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_v1)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/catalog/attack/techniques/T1059?domain=enterprise",
                headers={"Authorization": f"Bearer {tenant_token}"},
            )
        assert r.status_code == 200
        payload = r.json()
        assert payload["technique_id"] == "T1059"
        mit_ids = [m["mitigation_id"] for m in payload["mitigations"]]
        assert mit_ids == ["M1040"]

    async def test_versions_endpoint(
        self, clean_attack_tables, fetch_v1, fetch_v2, tenant_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_v1)
        await refresh_domain("enterprise", fetch_fn=fetch_v2)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/catalog/attack/versions",
                headers={"Authorization": f"Bearer {tenant_token}"},
            )
        assert r.status_code == 200
        versions = r.json()
        assert len(versions) == 2
        cur = [v for v in versions if v["is_current"]]
        assert len(cur) == 1
        assert cur[0]["version"] == "2.0"
        # The current version's diff must include the added/deprecated/renamed sets.
        diff = cur[0]["summary"]["diff"]
        assert "T1078" in diff["added"]
        assert "T1003" in diff["deprecated"]
