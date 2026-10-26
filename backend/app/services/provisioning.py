"""Customer provisioning.

Steps:
  1. CREATE SCHEMA cust_<codename> IF NOT EXISTS
  2. Run the customer Alembic migration tree against that schema
  3. Copy `public.default_detections` into the tenant's `detections` table
     with source='global' and upstream_global_id set; parse ATT&CK tags into
     detection_techniques rows.

Why subprocess for Alembic? Alembic's offline/programmatic API is awkward
with async engines and two trees. Subprocess gives us a clean, deterministic
boundary, the same way operators would run migrations by hand.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import uuid
from pathlib import Path

from sqlalchemy import select, text

from app.config import settings
from app.db.base import AsyncSessionLocal, engine
from app.db.tenant import schema_for, set_tenant, tenant_session
from app.models.customer import Detection, DetectionTechnique
from app.models.public import DefaultDetection
from app.services.sigma_validate import techniques_from_tags

log = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parents[2]


async def _create_schema_if_missing(schema: str) -> None:
    async with engine.begin() as conn:
        # schema is validated by schema_for(); inline is safe.
        await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))


async def _run_customer_migrations(schema: str) -> None:
    """Apply the customer Alembic tree to a specific schema.

    We pass the target schema via an env var that the customer env.py reads
    (DETECTMAP_TARGET_SCHEMA) to set version_table_schema and search_path.
    """
    env = os.environ.copy()
    env["DETECTMAP_TARGET_SCHEMA"] = schema

    cmd = "alembic -n customer upgrade head"
    log.info("running customer migrations for schema=%s", schema)
    proc = await asyncio.create_subprocess_exec(
        *shlex.split(cmd),
        cwd=str(BACKEND_ROOT),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            f"customer migrations failed for {schema}: "
            f"{stderr.decode(errors='replace')}"
        )
    log.debug("customer migrations ok: %s", stdout.decode(errors="replace"))


async def _seed_default_catalog(codename: str) -> None:
    """Copy public.default_detections into the new tenant schema.

    Skip if the tenant already has any rows in `detections` (idempotent on
    re-provision).
    """
    async with AsyncSessionLocal() as session:
        defaults = (
            await session.execute(select(DefaultDetection))
        ).scalars().all()
    if not defaults:
        log.info("seed: no default_detections present (run SigmaHQ sync first)")
        return

    set_tenant(codename)
    try:
        async with tenant_session() as session:
            existing_count = (
                await session.execute(text("SELECT count(*) FROM detections"))
            ).scalar_one()
            if existing_count:
                log.info("seed: detections already populated (%d rows)", existing_count)
                return

            det_rows: list[dict] = []
            tech_rows: list[dict] = []
            for d in defaults:
                det_id = uuid.uuid4()
                det_rows.append(
                    {
                        "id": det_id,
                        "sigma_id": d.sigma_id,
                        "title": d.title,
                        "description": d.description,
                        "sigma_status": d.sigma_status,
                        "level": d.level,
                        "author": d.author,
                        "sigma_references": list(d.sigma_references or []),
                        "tags": list(d.tags or []),
                        "logsource": dict(d.logsource or {}),
                        "detection": dict(d.detection or {}),
                        "falsepositives": list(d.falsepositives or []),
                        "raw_yaml": d.raw_yaml,
                        "detection_status": "idea",
                        "source": "global",
                        "score_breadth": 0,
                        "score_depth": 0,
                        "upstream_global_id": d.global_id,
                    }
                )
                for tid in techniques_from_tags(list(d.tags or [])):
                    tech_rows.append(
                        {
                            "id": uuid.uuid4(),
                            "detection_id": det_id,
                            "technique_id": tid,
                            "domain": "enterprise",
                        }
                    )

            # Chunk to keep prepared-statement param count under Postgres's
            # 65535 limit (Detection has ~17 cols → ~3800-row safe ceiling).
            chunk = 500
            for start in range(0, len(det_rows), chunk):
                await session.execute(
                    Detection.__table__.insert(), det_rows[start : start + chunk]
                )
            for start in range(0, len(tech_rows), chunk):
                await session.execute(
                    DetectionTechnique.__table__.insert(),
                    tech_rows[start : start + chunk],
                )
            log.info(
                "seed: copied %d detections + %d technique mappings into %s",
                len(det_rows),
                len(tech_rows),
                codename,
            )
    finally:
        set_tenant(None)


async def provision_customer(codename: str) -> None:
    """End-to-end provisioning. Idempotent."""
    schema = schema_for(codename)
    await _create_schema_if_missing(schema)
    await _run_customer_migrations(schema)
    await _seed_default_catalog(codename)
    log.info("provisioned customer: %s -> %s", codename, schema)
