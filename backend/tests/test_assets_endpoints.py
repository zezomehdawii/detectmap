"""End-to-end tests for the customer profile (assets + contacts + linkage).

Uses the live `acme` tenant schema (provisioned by seed_demo). Each test
cleans up its own asset / contact rows in teardown so the shared dev DB
stays consistent across runs.
"""
from __future__ import annotations

import uuid

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import Asset, AssetDetection, CustomerContact, Detection


def _client(token: str, customer: str = "acme") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Customer": customer,
        },
    )


async def _clean_profile(codename: str) -> None:
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            # asset_detections gone via FK CASCADE on assets / detections.
            await session.execute(delete(Asset))
            await session.execute(delete(CustomerContact))
    finally:
        set_tenant(None)


@pytest_asyncio.fixture
async def acme_clean_profile():
    """Wipe the acme tenant's profile rows before/after each test."""
    await _clean_profile("acme")
    yield
    await _clean_profile("acme")


@pytest_asyncio.fixture
async def globex_clean_profile():
    """Same as acme_clean_profile but for the globex tenant — used by
    linkage tests because globex is the one seeded with the full
    SigmaHQ catalog (~3k detections), so we always have rows to link."""
    await _clean_profile("globex")
    yield
    await _clean_profile("globex")


# ---- assets CRUD --------------------------------------------------------


class TestAssetCRUD:
    async def test_list_empty(self, acme_clean_profile, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/assets")
        assert r.status_code == 200
        assert r.json() == []

    async def test_create_then_list(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/assets",
                json={
                    "name": "  web-prod-01  ",  # leading/trailing space
                    "kind": "server",
                    "criticality": "critical",
                    "ip_address": "10.20.30.40",
                    "compliance_scope": ["pci", "iso_27001", "pci"],  # dedupe
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["name"] == "web-prod-01"  # trimmed
            assert body["compliance_scope"] == ["pci", "iso_27001"]  # deduped
            assert body["criticality"] == "critical"
            assert body["created_by_email"]  # populated from principal

            listed = await c.get("/assets")
        assert listed.status_code == 200
        assert len(listed.json()) == 1

    async def test_create_rejects_bad_enums(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/assets",
                json={"name": "x", "kind": "fridge"},
            )
            assert r.status_code == 422
            assert "kind must be one of" in r.text

            r = await c.post(
                "/assets",
                json={"name": "x", "kind": "server", "criticality": "ultra"},
            )
            assert r.status_code == 422

            r = await c.post(
                "/assets",
                json={
                    "name": "x",
                    "kind": "server",
                    "compliance_scope": ["unknown_framework"],
                },
            )
        assert r.status_code == 422

    async def test_filter_by_criticality(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            for crit in ("low", "high", "critical", "critical"):
                await c.post(
                    "/assets",
                    json={"name": f"a-{crit}", "kind": "server", "criticality": crit},
                )
            r = await c.get("/assets?criticality=critical")
        assert r.status_code == 200
        names = {a["name"] for a in r.json()}
        assert names == {"a-critical"}  # both same name → one row, dedupe via PK

    async def test_filter_by_q_matches_name_and_hostname(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            await c.post(
                "/assets",
                json={"name": "edge-router", "kind": "network_device"},
            )
            await c.post(
                "/assets",
                json={"name": "db-01", "kind": "database", "hostname": "edge-db.local"},
            )
            await c.post(
                "/assets",
                json={"name": "unrelated", "kind": "server"},
            )
            r = await c.get("/assets?q=edge")
        names = sorted(a["name"] for a in r.json())
        assert names == ["db-01", "edge-router"]

    async def test_patch_updates_partial(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/assets",
                    json={"name": "x", "kind": "server", "criticality": "low"},
                )
            ).json()
            r = await c.patch(
                f"/assets/{created['id']}",
                json={"criticality": "high", "tags": ["pii", "external"]},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["criticality"] == "high"
            assert body["tags"] == ["pii", "external"]
            # Untouched fields preserved.
            assert body["kind"] == "server"

    async def test_delete_then_404(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/assets",
                    json={"name": "x", "kind": "server"},
                )
            ).json()
            d = await c.delete(f"/assets/{created['id']}")
            assert d.status_code == 204
            d2 = await c.delete(f"/assets/{created['id']}")
        assert d2.status_code == 404

    async def test_readonly_cannot_write(
        self, acme_clean_profile, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                "/assets",
                json={"name": "x", "kind": "server"},
            )
        assert r.status_code == 403

    async def test_cmf_category_set_and_validated(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            ok = await c.post(
                "/assets",
                json={"name": "dc", "kind": "server", "cmf_category": "identity"},
            )
            assert ok.status_code == 201, ok.text
            assert ok.json()["cmf_category"] == "identity"
            assert ok.json()["data_source_count"] == 0

            bad = await c.post(
                "/assets",
                json={"name": "x", "kind": "server", "cmf_category": "teleport"},
            )
        assert bad.status_code == 422
        assert "cmf_category must be one of" in bad.text


# ---- collection sources (CMF) -------------------------------------------


class TestAssetDataSources:
    async def _make_asset(self, c) -> str:
        r = await c.post("/assets", json={"name": "dc-01", "kind": "server"})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    async def test_crud_and_count_rollup(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            aid = await self._make_asset(c)

            # empty
            assert (await c.get(f"/assets/{aid}/data-sources")).json() == []

            created = await c.post(
                f"/assets/{aid}/data-sources",
                json={
                    "name": "Windows Security event logs",
                    "attack_data_source": "Logon Session",
                    "attack_data_component": "Logon Session Creation",
                    "log_source": "windows/security",
                    "retention_days": 90,
                    "device_completeness_q": 4,
                },
            )
            assert created.status_code == 201, created.text
            ds = created.json()
            assert ds["retention_days"] == 90
            assert ds["device_completeness_q"] == 4
            assert ds["enabled"] is True

            # second source so we can assert the count rollup
            await c.post(
                f"/assets/{aid}/data-sources",
                json={"name": "Sysmon", "log_source": "windows/sysmon"},
            )

            listed = await c.get(f"/assets/{aid}/data-sources")
            assert len(listed.json()) == 2

            # rollup count surfaces on the asset list + get
            row = next(a for a in (await c.get("/assets")).json() if a["id"] == aid)
            assert row["data_source_count"] == 2

            # patch
            patched = await c.patch(
                f"/assets/{aid}/data-sources/{ds['id']}",
                json={"retention_days": 365, "enabled": False},
            )
            assert patched.status_code == 200
            assert patched.json()["retention_days"] == 365
            assert patched.json()["enabled"] is False

            # delete
            d = await c.delete(f"/assets/{aid}/data-sources/{ds['id']}")
            assert d.status_code == 204
            assert len((await c.get(f"/assets/{aid}/data-sources")).json()) == 1

    async def test_quality_dim_out_of_range_rejected(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            aid = await self._make_asset(c)
            r = await c.post(
                f"/assets/{aid}/data-sources",
                json={"name": "ds", "timeliness_q": 6},
            )
        assert r.status_code == 422
        assert "timeliness_q" in r.text

    async def test_duplicate_name_conflict(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            aid = await self._make_asset(c)
            first = await c.post(f"/assets/{aid}/data-sources", json={"name": "EDR"})
            assert first.status_code == 201
            dup = await c.post(f"/assets/{aid}/data-sources", json={"name": "EDR"})
        assert dup.status_code == 409

    async def test_unknown_connector_rejected(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            aid = await self._make_asset(c)
            r = await c.post(
                f"/assets/{aid}/data-sources",
                json={
                    "name": "ds",
                    "storage_connector_id": "00000000-0000-0000-0000-000000000000",
                },
            )
        assert r.status_code == 422
        assert "storage_connector_id" in r.text

    async def test_source_404_when_asset_missing(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get(
                "/assets/00000000-0000-0000-0000-000000000000/data-sources"
            )
        assert r.status_code == 404

    async def test_readonly_cannot_write_sources(
        self, acme_clean_profile, demo_admin_token, demo_readonly_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            aid = await self._make_asset(c)
        async with _client(demo_readonly_token) as c:
            r = await c.post(f"/assets/{aid}/data-sources", json={"name": "ds"})
        assert r.status_code == 403


# ---- CMF import ----------------------------------------------------------


class TestAssetImport:
    async def test_import_create_dedupe_and_errors(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            # one row with external_id + a data source, one without, one bad.
            res = await c.post(
                "/assets/import",
                json={
                    "rows": [
                        {
                            "name": "DC-01",
                            "kind": "server",
                            "criticality": "critical",
                            "cmf_category": "identity",
                            "external_id": "cmdb-1",
                            "data_sources": [
                                {"name": "Security logs", "retention_days": 90}
                            ],
                        },
                        {"name": "web-01", "kind": "server"},
                        {"name": "bad", "kind": "fridge"},  # invalid enum
                    ]
                },
            )
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["created"] == 2
            assert body["updated"] == 0
            assert body["data_sources_added"] == 1
            assert len(body["errors"]) == 1
            assert body["errors"][0]["row"] == 2

            # re-import the same external_id with a new name → update, not dup.
            res2 = await c.post(
                "/assets/import",
                json={
                    "rows": [
                        {"name": "DC-01-renamed", "kind": "server", "external_id": "cmdb-1"}
                    ]
                },
            )
            assert res2.status_code == 200
            assert res2.json() == {
                "created": 0,
                "updated": 1,
                "data_sources_added": 0,
                "errors": [],
            }

            names = sorted(a["name"] for a in (await c.get("/assets")).json())
            assert names == ["DC-01-renamed", "web-01"]

    async def test_import_appends_sources_without_clobber(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            payload = {
                "rows": [
                    {
                        "name": "host",
                        "kind": "server",
                        "external_id": "h1",
                        "data_sources": [{"name": "logs-A"}],
                    }
                ]
            }
            await c.post("/assets/import", json=payload)
            # second import: same source name (skipped) + a new one (added)
            res = await c.post(
                "/assets/import",
                json={
                    "rows": [
                        {
                            "name": "host",
                            "kind": "server",
                            "external_id": "h1",
                            "data_sources": [{"name": "logs-A"}, {"name": "logs-B"}],
                        }
                    ]
                },
            )
            assert res.json()["data_sources_added"] == 1  # only logs-B
            aid = next(
                a["id"] for a in (await c.get("/assets")).json() if a["external_id"] == "h1"
            )
            sources = sorted(d["name"] for d in (await c.get(f"/assets/{aid}/data-sources")).json())
        assert sources == ["logs-A", "logs-B"]

    async def test_import_requires_write_perm(
        self, acme_clean_profile, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                "/assets/import",
                json={"rows": [{"name": "x", "kind": "server"}]},
            )
        assert r.status_code == 403


# ---- asset ↔ detection linkage -----------------------------------------


async def _pick_two_detection_ids(codename: str) -> list[uuid.UUID]:
    """Two arbitrary detection ids from the named tenant — used to
    exercise the linkage paths. The acme schema is seeded with the
    default catalog so this always finds enough rows."""
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            r = await session.execute(text("SELECT id FROM detections LIMIT 2"))
            return [row[0] for row in r.fetchall()]
    finally:
        set_tenant(None)


class TestAssetDetectionLinkage:
    """Linkage tests target the globex tenant — seeded with the full
    SigmaHQ catalog so we always have detections to link against. The
    `acme` schema is left empty by `seed_demo` (intentionally) and would
    leave these tests skipped."""

    async def test_link_and_unlink(
        self, globex_clean_profile, demo_admin_token
    ) -> None:
        det_ids = await _pick_two_detection_ids("globex")
        if len(det_ids) < 2:
            import pytest
            pytest.skip("globex tenant has fewer than 2 detections seeded")
        async with _client(demo_admin_token, customer="globex") as c:
            asset = (
                await c.post("/assets", json={"name": "dc-01", "kind": "server"})
            ).json()
            r = await c.put(
                f"/assets/{asset['id']}/detections",
                json={"detection_ids": [str(d) for d in det_ids]},
            )
            assert r.status_code == 200
            assert r.json() == {"linked": 2, "unlinked": 0, "total": 2}

            listed = await c.get(f"/assets/{asset['id']}/detections")
            assert listed.status_code == 200
            assert len(listed.json()) == 2

            # Replace with just the first id.
            r2 = await c.put(
                f"/assets/{asset['id']}/detections",
                json={"detection_ids": [str(det_ids[0])]},
            )
            assert r2.status_code == 200
            assert r2.json() == {"linked": 0, "unlinked": 1, "total": 1}

            listed2 = await c.get(f"/assets/{asset['id']}/detections")
            assert len(listed2.json()) == 1

            # Empty list unlinks everything — idempotent.
            r3 = await c.put(
                f"/assets/{asset['id']}/detections",
                json={"detection_ids": []},
            )
            assert r3.status_code == 200
            assert r3.json() == {"linked": 0, "unlinked": 1, "total": 0}

    async def test_link_unknown_detection_id_rejected(
        self, globex_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token, customer="globex") as c:
            asset = (
                await c.post("/assets", json={"name": "x", "kind": "server"})
            ).json()
            r = await c.put(
                f"/assets/{asset['id']}/detections",
                json={
                    "detection_ids": [
                        "00000000-0000-0000-0000-000000000000"
                    ]
                },
            )
        assert r.status_code == 422
        assert "unknown detection_id" in r.text

    async def test_coverage_rollup_in_list_response(
        self, globex_clean_profile, demo_admin_token
    ) -> None:
        det_ids = await _pick_two_detection_ids("globex")
        if len(det_ids) < 2:
            import pytest
            pytest.skip("globex tenant has fewer than 2 detections seeded")
        async with _client(demo_admin_token, customer="globex") as c:
            asset = (
                await c.post("/assets", json={"name": "dc", "kind": "server"})
            ).json()
            await c.put(
                f"/assets/{asset['id']}/detections",
                json={"detection_ids": [str(d) for d in det_ids]},
            )
            row = (await c.get("/assets")).json()[0]
        assert row["coverage"]["linked_detections"] == 2

    async def test_asset_delete_cascades_links(
        self, globex_clean_profile, demo_admin_token
    ) -> None:
        det_ids = await _pick_two_detection_ids("globex")
        if not det_ids:
            import pytest
            pytest.skip("globex has no detections")
        async with _client(demo_admin_token, customer="globex") as c:
            asset = (
                await c.post("/assets", json={"name": "doomed", "kind": "server"})
            ).json()
            await c.put(
                f"/assets/{asset['id']}/detections",
                json={"detection_ids": [str(det_ids[0])]},
            )
            await c.delete(f"/assets/{asset['id']}")

        # Verify the join row is gone (no orphan rows).
        set_tenant("globex")
        try:
            async with tenant_session() as session:
                rows = (
                    await session.execute(
                        select(AssetDetection).where(
                            AssetDetection.asset_id == uuid.UUID(asset["id"])
                        )
                    )
                ).scalars().all()
        finally:
            set_tenant(None)
        assert rows == []


# ---- contacts CRUD ------------------------------------------------------


class TestContactCRUD:
    async def test_list_orders_primary_first(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            await c.post(
                "/contacts",
                json={"name": "Bob", "is_primary": False},
            )
            await c.post(
                "/contacts",
                json={"name": "Alice", "is_primary": True},
            )
            await c.post(
                "/contacts",
                json={"name": "Carol", "is_primary": False},
            )
            r = await c.get("/contacts")
        assert r.status_code == 200
        names = [c["name"] for c in r.json()]
        # Primary first, then the rest alphabetical.
        assert names == ["Alice", "Bob", "Carol"]

    async def test_create_validates_name_required(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/contacts",
                json={"name": "", "email": "x@example.com"},
            )
        assert r.status_code == 422

    async def test_patch_and_delete(
        self, acme_clean_profile, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post("/contacts", json={"name": "Dan"})
            ).json()
            r = await c.patch(
                f"/contacts/{created['id']}",
                json={"phone": "+1 555 0199", "is_primary": True},
            )
            assert r.status_code == 200
            assert r.json()["phone"] == "+1 555 0199"
            assert r.json()["is_primary"] is True

            d = await c.delete(f"/contacts/{created['id']}")
        assert d.status_code == 204

    async def test_readonly_can_read_cannot_write(
        self, acme_clean_profile, demo_admin_token, demo_readonly_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            await c.post("/contacts", json={"name": "X"})
        async with _client(demo_readonly_token) as c:
            assert (await c.get("/contacts")).status_code == 200
            assert (
                await c.post("/contacts", json={"name": "Y"})
            ).status_code == 403


# ---- tenant scoping ------------------------------------------------------


class TestTenantScoping:
    async def test_requires_active_customer(self, demo_admin_token) -> None:
        # Without X-Customer the MSSP admin can't reach tenant-scoped routes.
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/assets")
        assert r.status_code == 400  # require_active_customer

    async def test_unauthenticated_blocked(self) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/assets", headers={"X-Customer": "acme"})
        assert r.status_code == 401
