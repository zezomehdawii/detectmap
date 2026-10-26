"""HTTP-level tests for /reports/* endpoints — RBAC + content types."""
from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.services.attack_ingest import refresh_domain

pytestmark = pytest.mark.wipes_db


SAMPLE_RULE = """
title: PowerShell EncodedCommand
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  product: windows
  category: process_creation
detection:
  s:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: s
level: high
"""


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
        await session.execute(text("DELETE FROM coverage_snapshots"))


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


class TestReportRBAC:
    async def test_active_customer_required(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            r = await c.get("/reports/coverage.csv")
        assert r.status_code == 400


class TestCoverageExports:
    async def test_csv_export(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/reports/coverage.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        body = r.text
        first_line = body.splitlines()[0]
        assert first_line.startswith("tactic,technique_id,name")
        # 4 enterprise techniques in fixture → at least 4 data rows
        assert len(body.splitlines()) >= 5

    async def test_xlsx_export(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/reports/coverage.xlsx")
        assert r.status_code == 200
        assert "spreadsheetml" in r.headers["content-type"]
        # XLSX = ZIP under the hood; first 2 bytes are PK
        assert r.content[:2] == b"PK"

    async def test_navigator_export(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get(
                "/reports/coverage.navigator.json?denominator=apt&ref=G9999"
            )
        assert r.status_code == 200
        body = json.loads(r.text)
        assert body["domain"] == "enterprise-attack"
        assert body["versions"]["layer"] == "4.5"
        tids = {t["techniqueID"] for t in body["techniques"]}
        # G9999 in scope: T1003, T1078, T1059, T1090
        assert tids == {"T1003", "T1078", "T1059", "T1090"}

    async def test_pdf_export(
        self, acme_clean, clean_attack_tables, fetch_groups, demo_admin_token
    ) -> None:
        await refresh_domain("enterprise", fetch_fn=fetch_groups)
        async with _client(demo_admin_token) as c:
            r = await c.get("/reports/coverage.pdf")
        assert r.status_code == 200
        assert "application/pdf" in r.headers["content-type"]
        assert r.content[:4] == b"%PDF"


class TestSigmaBundleAndConvert:
    async def _seed_one(self) -> str:
        det_id = str(uuid.uuid4())
        async with tenant_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO detections
                      (id, sigma_id, title, sigma_references, tags, logsource,
                       detection, falsepositives, raw_yaml,
                       detection_status, source, score_breadth, score_depth)
                    VALUES
                      (:id, '11111111-1111-1111-1111-111111111111',
                       'PowerShell EncodedCommand',
                       '[]'::jsonb, '[]'::jsonb,
                       '{"product":"windows"}'::jsonb,
                       '{"s":{"a":"b"},"condition":"s"}'::jsonb,
                       '[]'::jsonb, :raw,
                       'idea', 'custom', 0, 0)
                    """
                ),
                {"id": det_id, "raw": SAMPLE_RULE},
            )
        return det_id

    async def test_bundle_zip_round_trip(
        self, acme_clean, demo_admin_token
    ) -> None:
        set_tenant("acme")
        try:
            det_id = await self._seed_one()
        finally:
            set_tenant(None)
        async with _client(demo_admin_token) as c:
            r = await c.get("/reports/sigma-bundle.zip")
        assert r.status_code == 200
        assert "application/zip" in r.headers["content-type"]
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            names = zf.namelist()
            assert "MANIFEST.csv" in names
            # custom/<sigma_id>.yml expected
            yml_files = [n for n in names if n.endswith(".yml")]
            assert len(yml_files) == 1
            assert yml_files[0].startswith("custom/")

    async def test_convert_endpoint_three_backends(
        self, acme_clean, demo_admin_token
    ) -> None:
        set_tenant("acme")
        try:
            det_id = await self._seed_one()
        finally:
            set_tenant(None)
        for backend in ("splunk", "elastic", "sentinel"):
            async with _client(demo_admin_token) as c:
                r = await c.post(
                    "/reports/sigma-convert",
                    json={"backend": backend, "detection_ids": [det_id]},
                )
            assert r.status_code == 200, (backend, r.text)
            body = r.json()
            assert body["backend"] == backend
            assert body["total"] == 1
            assert body["converted"] == 1
            assert body["results"][0]["queries"]

    async def test_convert_endpoint_unknown_backend(
        self, acme_clean, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/reports/sigma-convert", json={"backend": "snowflake"}
            )
        assert r.status_code == 422
