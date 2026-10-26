"""SigmaHQ ruleset sync into `public.default_detections`.

Fetches the GitHub tarball for `SigmaHQ/sigma` at a chosen ref, extracts to a
temp dir, walks the curated `rules/` subdirectory, and upserts every parseable
Sigma rule keyed on its `id:` UUID. Re-running the same `(ref, commit_sha)` is
a no-op unless `force=True`.
"""
from __future__ import annotations

import asyncio
import io
import logging
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Optional

import httpx
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import settings
from app.db.base import AsyncSessionLocal
from app.models.public import DefaultDetection, SigmaHQIngestRun
from app.services.sigma_validate import SigmaValidationError, parse_sigma_yaml

log = logging.getLogger(__name__)

FetchFn = Callable[[str], Awaitable[tuple[bytes, Optional[str]]]]


async def _http_fetch_tarball(ref: str) -> tuple[bytes, Optional[str]]:
    """Download the SigmaHQ tarball + return (bytes, commit_sha)."""
    api_url = f"https://api.github.com/repos/{settings.sigmahq_repo}/tarball/{ref}"
    log.info("downloading SigmaHQ tarball: %s", api_url)
    async with httpx.AsyncClient(
        timeout=settings.sigmahq_fetch_timeout, follow_redirects=True
    ) as client:
        resp = await client.get(api_url)
        resp.raise_for_status()
        commit_sha = None
        cd = resp.headers.get("content-disposition", "")
        # github tarball filename is <user>-<repo>-<sha7>.tar.gz
        if "filename=" in cd:
            fname = cd.split("filename=", 1)[1].strip().strip('"')
            parts = fname.removesuffix(".tar.gz").split("-")
            if parts:
                commit_sha = parts[-1]
        return resp.content, commit_sha


def _iter_rule_files(extract_root: Path) -> Iterable[Path]:
    """Yield .yml/.yaml files under the configured SigmaHQ subdir.

    The tarball expands to a single top-level dir like `SigmaHQ-sigma-<sha>/`.
    """
    children = [p for p in extract_root.iterdir() if p.is_dir()]
    if not children:
        return
    repo_root = children[0]
    rules_root = repo_root / settings.sigmahq_subdir
    if not rules_root.is_dir():
        log.warning("expected SigmaHQ subdir not found: %s", rules_root)
        return
    for ext in ("*.yml", "*.yaml"):
        yield from rules_root.rglob(ext)


def _parse_tarball(content: bytes) -> tuple[Path, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory(prefix="sigmahq-")
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
        tf.extractall(tmp.name)
    return Path(tmp.name), tmp


async def _parse_all_rules(extract_root: Path) -> tuple[list[dict], int, int]:
    """Walk the tarball; return (valid_rules, parsed_ok, parsed_skipped)."""
    rules: list[dict] = []
    seen_ids: set[str] = set()
    ok = 0
    skipped = 0
    for rule_path in _iter_rule_files(extract_root):
        try:
            yaml_text = rule_path.read_text(encoding="utf-8")
        except OSError as e:
            log.warning("could not read %s: %s", rule_path, e)
            skipped += 1
            continue
        try:
            row = parse_sigma_yaml(yaml_text)
        except SigmaValidationError as e:
            log.debug("skip %s: %s", rule_path.name, e)
            skipped += 1
            continue
        gid = row["global_id"]
        if gid in seen_ids:
            skipped += 1
            continue
        seen_ids.add(gid)
        try:
            row["source_path"] = str(rule_path.relative_to(extract_root.iterdir().__next__()))
        except (StopIteration, ValueError):
            row["source_path"] = rule_path.name
        rules.append(row)
        ok += 1
        if ok % 500 == 0:
            await asyncio.sleep(0)  # let the event loop breathe
    return rules, ok, skipped


_UPDATE_COLS = (
    "sigma_id",
    "title",
    "description",
    "sigma_status",
    "level",
    "author",
    "sigma_references",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "raw_yaml",
    "source_path",
)


async def _upsert_rules(session, rows: list[dict]) -> None:
    if not rows:
        return
    chunk = 500
    for start in range(0, len(rows), chunk):
        batch = rows[start : start + chunk]
        for r in batch:
            r.setdefault("id", uuid.uuid4())
        stmt = pg_insert(DefaultDetection.__table__).values(batch)
        stmt = stmt.on_conflict_do_update(
            index_elements=["global_id"],
            set_={c: stmt.excluded[c] for c in _UPDATE_COLS},
        )
        await session.execute(stmt)


async def refresh(
    ref: Optional[str] = None,
    *,
    force: bool = False,
    fetch_fn: Optional[FetchFn] = None,
) -> dict:
    """End-to-end SigmaHQ sync. Idempotent on (ref, commit_sha)."""
    ref = ref or settings.sigmahq_default_ref
    fetcher = fetch_fn or _http_fetch_tarball
    content, commit_sha = await fetcher(ref)
    log.info("SigmaHQ tarball: %s commit=%s bytes=%d", ref, commit_sha, len(content))

    async with AsyncSessionLocal() as session:
        async with session.begin():
            existing = None
            if commit_sha:
                existing = (
                    await session.execute(
                        select(SigmaHQIngestRun)
                        .where(
                            SigmaHQIngestRun.ref == ref,
                            SigmaHQIngestRun.commit_sha == commit_sha,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
            if existing is not None and not force:
                log.info("SigmaHQ %s@%s already ingested — no-op", ref, commit_sha)
                return {
                    "ref": ref,
                    "commit_sha": commit_sha,
                    "no_op": True,
                    "rule_count": int(existing.summary.get("rule_count", 0)),
                }

    extract_root, tmp_dir = _parse_tarball(content)
    try:
        rules, ok, skipped = await _parse_all_rules(extract_root)
        log.info("parsed SigmaHQ rules: ok=%d skipped=%d", ok, skipped)

        async with AsyncSessionLocal() as session:
            async with session.begin():
                await _upsert_rules(session, rules)

                summary = {"rule_count": ok, "skipped": skipped}
                if existing is None:
                    await session.execute(
                        update(SigmaHQIngestRun)
                        .where(SigmaHQIngestRun.is_current.is_(True))
                        .values(is_current=False)
                    )
                    session.add(
                        SigmaHQIngestRun(
                            id=uuid.uuid4(),
                            ref=ref,
                            commit_sha=commit_sha,
                            summary=summary,
                            is_current=True,
                        )
                    )
                else:
                    existing.summary = summary
                    if not existing.is_current:
                        await session.execute(
                            update(SigmaHQIngestRun)
                            .where(SigmaHQIngestRun.is_current.is_(True))
                            .values(is_current=False)
                        )
                        existing.is_current = True
    finally:
        tmp_dir.cleanup()

    return {
        "ref": ref,
        "commit_sha": commit_sha,
        "no_op": False,
        "rule_count": ok,
        "skipped": skipped,
    }


__all__ = ["FetchFn", "refresh"]
