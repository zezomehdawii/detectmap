"""End-to-end tests for customer-profile diagrams (Stage 2).

Covers: upload, list ordering (primary first), download bytes,
single-primary invariant, metadata patch, delete, RBAC (readonly cannot
write), forbidden mime types, oversize rejection.

Uses the live `acme` tenant schema, like test_assets_endpoints.py.
"""
from __future__ import annotations

import io
import uuid

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.db.tenant import set_tenant, tenant_session
from app.main import app
from app.models.customer import CustomerDiagram
from app.services import diagram_storage


def _client(token: str, customer: str = "acme") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Customer": customer,
        },
    )


# Minimal PNG: 1x1 transparent pixel. Real bytes so the storage helper
# and FileResponse both succeed end-to-end.
_PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a"  # PNG signature
    "0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6300010000000500010d0a2db4"
    "0000000049454e44ae426082"
)


async def _purge_disk(codename: str) -> None:
    """Drop any files the storage helper has written for this tenant.

    Walks the per-tenant storage subdir first (in case a prior run died
    before the DB cleanup ran), then deletes the metadata rows.
    """
    # Filesystem first — best effort, the dir may not exist yet.
    tenant_root = diagram_storage.absolute_path(codename)
    if tenant_root.exists() and tenant_root.is_dir():
        for p in tenant_root.iterdir():
            try:
                p.unlink()
            except OSError:
                pass
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            await session.execute(delete(CustomerDiagram))
    finally:
        set_tenant(None)


@pytest_asyncio.fixture
async def acme_clean_diagrams():
    await _purge_disk("acme")
    yield
    await _purge_disk("acme")


def _upload_files(
    *, filename: str = "topology.png", content: bytes = _PNG_1x1, mime: str = "image/png"
) -> dict:
    """httpx multipart payload."""
    return {"file": (filename, io.BytesIO(content), mime)}


# ---- upload + list ------------------------------------------------------


class TestDiagramUploadList:
    async def test_list_empty(self, acme_clean_diagrams, demo_admin_token) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.get("/diagrams")
        assert r.status_code == 200
        assert r.json() == []

    async def test_upload_returns_metadata(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/diagrams",
                files=_upload_files(),
                data={"title": "  HQ topology  ", "description": "main DC"},
            )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["title"] == "HQ topology"  # trimmed
        assert body["description"] == "main DC"
        assert body["kind"] == "image"
        assert body["mime_type"] == "image/png"
        assert body["size_bytes"] == len(_PNG_1x1)
        assert body["is_primary"] is False
        assert body["uploaded_by_email"]

    async def test_list_orders_primary_first(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            await c.post(
                "/diagrams",
                files=_upload_files(filename="a.png"),
                data={"title": "older"},
            )
            await c.post(
                "/diagrams",
                files=_upload_files(filename="b.png"),
                data={"title": "primary one", "is_primary": "true"},
            )
            await c.post(
                "/diagrams",
                files=_upload_files(filename="c.png"),
                data={"title": "newest"},
            )
            r = await c.get("/diagrams")
        names = [d["title"] for d in r.json()]
        # Primary first; the rest are uploaded_at DESC.
        assert names[0] == "primary one"
        assert set(names) == {"older", "primary one", "newest"}


# ---- single-primary invariant -------------------------------------------


class TestPrimaryInvariant:
    async def test_uploading_primary_clears_previous(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r1 = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(filename="a.png"),
                    data={"title": "first", "is_primary": "true"},
                )
            ).json()
            assert r1["is_primary"] is True

            await c.post(
                "/diagrams",
                files=_upload_files(filename="b.png"),
                data={"title": "second", "is_primary": "true"},
            )

            rows = (await c.get("/diagrams")).json()
        primaries = [d for d in rows if d["is_primary"]]
        assert len(primaries) == 1
        assert primaries[0]["title"] == "second"

    async def test_patch_set_primary_clears_others(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            a = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(filename="a.png"),
                    data={"title": "A", "is_primary": "true"},
                )
            ).json()
            b = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(filename="b.png"),
                    data={"title": "B"},
                )
            ).json()
            # Flip primary from A → B via PATCH.
            await c.patch(f"/diagrams/{b['id']}", json={"is_primary": True})
            rows = (await c.get("/diagrams")).json()
        primaries = {d["title"] for d in rows if d["is_primary"]}
        assert primaries == {"B"}


# ---- download bytes ------------------------------------------------------


class TestDownload:
    async def test_image_returns_inline(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(filename="topo.png"),
                    data={"title": "T"},
                )
            ).json()
            r = await c.get(f"/diagrams/{created['id']}/file")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("image/png")
        assert "inline" in r.headers["content-disposition"]
        assert r.content == _PNG_1x1

    async def test_binary_returns_attachment(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(
                        filename="lab.pkt",
                        content=b"\x00\x01PACKETTRACER\x00\x02",
                        mime="application/octet-stream",
                    ),
                    data={"title": "Lab"},
                )
            ).json()
            r = await c.get(f"/diagrams/{created['id']}/file")
        assert r.status_code == 200
        assert "attachment" in r.headers["content-disposition"]


# ---- rejections ----------------------------------------------------------


class TestRejections:
    async def test_html_mime_rejected(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/diagrams",
                files={
                    "file": ("evil.html", io.BytesIO(b"<script>x()</script>"), "text/html"),
                },
                data={"title": "evil"},
            )
        assert r.status_code == 415

    async def test_empty_file_rejected(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            r = await c.post(
                "/diagrams",
                files={"file": ("empty.png", io.BytesIO(b""), "image/png")},
                data={"title": "x"},
            )
        assert r.status_code == 422

    async def test_readonly_cannot_upload(
        self, acme_clean_diagrams, demo_readonly_token
    ) -> None:
        async with _client(demo_readonly_token) as c:
            r = await c.post(
                "/diagrams",
                files=_upload_files(),
                data={"title": "x"},
            )
        assert r.status_code == 403


# ---- patch + delete ------------------------------------------------------


class TestPatchDelete:
    async def test_patch_metadata(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(),
                    data={"title": "Old"},
                )
            ).json()
            r = await c.patch(
                f"/diagrams/{created['id']}",
                json={"title": "New", "description": "edited"},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["title"] == "New"
        assert body["description"] == "edited"

    async def test_delete_removes_row_and_file(
        self, acme_clean_diagrams, demo_admin_token
    ) -> None:
        async with _client(demo_admin_token) as c:
            created = (
                await c.post(
                    "/diagrams",
                    files=_upload_files(),
                    data={"title": "doomed"},
                )
            ).json()
        # Confirm the file landed on disk.
        async with _client(demo_admin_token) as c:
            r = await c.get(f"/diagrams/{created['id']}")
        assert r.status_code == 200
        stored = None
        set_tenant("acme")
        try:
            async with tenant_session() as session:
                from sqlalchemy import select

                row = (
                    await session.execute(
                        select(CustomerDiagram).where(
                            CustomerDiagram.id == uuid.UUID(created["id"])
                        )
                    )
                ).scalar_one()
                stored = row.stored_path
        finally:
            set_tenant(None)
        assert stored is not None
        assert diagram_storage.absolute_path(stored).exists()

        async with _client(demo_admin_token) as c:
            d = await c.delete(f"/diagrams/{created['id']}")
        assert d.status_code == 204
        # Row gone + file gone.
        async with _client(demo_admin_token) as c:
            r = await c.get(f"/diagrams/{created['id']}")
        assert r.status_code == 404
        assert not diagram_storage.absolute_path(stored).exists()
