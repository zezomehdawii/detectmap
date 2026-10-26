"""SigmaHQ sync integration tests.

Builds a tiny in-memory tarball that mimics the SigmaHQ repo layout
(`SigmaHQ-sigma-<sha>/rules/...`) and injects it as the fetcher.
"""
from __future__ import annotations

import io
import tarfile
import time
from typing import Awaitable, Callable

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from app.db.base import AsyncSessionLocal
from app.models.public import DefaultDetection, SigmaHQIngestRun
from app.services.sigmahq_sync import refresh


RULE_A = """
title: PowerShell EncodedCommand
id: aaaa1111-0000-0000-0000-000000000001
status: stable
tags:
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  s:
    Image|endswith: '\\powershell.exe'
  condition: s
level: high
"""

RULE_B = """
title: Valid Accounts (cloud)
id: bbbb2222-0000-0000-0000-000000000002
status: stable
tags:
  - attack.t1078.004
  - attack.defense_evasion
logsource:
  product: aws
  service: cloudtrail
detection:
  s:
    eventSource: signin.amazonaws.com
  condition: s
level: medium
"""

INVALID_RULE = """
title: only a title and nothing else
"""


def _build_tarball(files: dict[str, str], sha: str = "abc1234") -> bytes:
    """Build a SigmaHQ-style .tar.gz: SigmaHQ-sigma-<sha>/rules/<path>.yml."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"SigmaHQ-sigma-{sha}/rules/{path}")
            info.size = len(data)
            info.mtime = int(time.time())
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_fetcher(tarball: bytes, sha: str) -> Callable[[str], Awaitable[tuple[bytes, str]]]:
    async def _fetch(ref: str) -> tuple[bytes, str]:
        return tarball, sha

    return _fetch


@pytest_asyncio.fixture
async def clean_default_detections():
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(DefaultDetection))
            await session.execute(delete(SigmaHQIngestRun))
    yield
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(DefaultDetection))
            await session.execute(delete(SigmaHQIngestRun))


class TestSigmaHQRefresh:
    async def test_ingest_valid_skips_invalid(self, clean_default_detections) -> None:
        tarball = _build_tarball(
            {
                "a.yml": RULE_A,
                "b.yml": RULE_B,
                "broken.yml": INVALID_RULE,
            },
            sha="abc1234",
        )
        r = await refresh(ref="test", fetch_fn=make_fetcher(tarball, "abc1234"))
        assert r["no_op"] is False
        assert r["rule_count"] == 2
        assert r["skipped"] >= 1

        async with AsyncSessionLocal() as session:
            count = (
                await session.execute(select(func.count()).select_from(DefaultDetection))
            ).scalar_one()
            runs = (
                await session.execute(
                    select(SigmaHQIngestRun).order_by(SigmaHQIngestRun.ingested_at)
                )
            ).scalars().all()
        assert count == 2
        assert len(runs) == 1
        assert runs[0].is_current is True
        assert runs[0].ref == "test"
        assert runs[0].commit_sha == "abc1234"

    async def test_idempotent_on_same_commit(self, clean_default_detections) -> None:
        tarball = _build_tarball({"a.yml": RULE_A}, sha="abc1234")
        await refresh(ref="test", fetch_fn=make_fetcher(tarball, "abc1234"))
        r2 = await refresh(ref="test", fetch_fn=make_fetcher(tarball, "abc1234"))
        assert r2["no_op"] is True

        async with AsyncSessionLocal() as session:
            runs = (
                await session.execute(select(func.count()).select_from(SigmaHQIngestRun))
            ).scalar_one()
        assert runs == 1

    async def test_force_re_ingest(self, clean_default_detections) -> None:
        tarball = _build_tarball({"a.yml": RULE_A}, sha="abc1234")
        await refresh(ref="test", fetch_fn=make_fetcher(tarball, "abc1234"))
        r2 = await refresh(
            ref="test", force=True, fetch_fn=make_fetcher(tarball, "abc1234")
        )
        assert r2["no_op"] is False
