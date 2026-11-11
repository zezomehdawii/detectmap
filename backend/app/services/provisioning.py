"""Customer provisioning.

Steps:
  1. CREATE SCHEMA cust_<codename> IF NOT EXISTS
  2. Run the customer Alembic migration tree against that schema
  3. Copy `public.default_detections` into the tenant's `detections` table
     with source='global' and upstream_global_id set; parse ATT&CK tags into
     detection_techniques rows.

Provisioning can share the transaction that creates the customer record.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for
from app.models.customer import Detection, DetectionTechnique
from app.models.public import DefaultDetection
from app.services.sigma_validate import techniques_from_tags

log = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parents[2]


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


async def _seed_default_catalog(session: AsyncSession, codename: str) -> None:
    """Copy the shared catalog into an empty tenant schema."""
    defaults = (await session.execute(select(DefaultDetection))).scalars().all()
    if not defaults:
        log.info("seed: no default_detections present (run SigmaHQ sync first)")
        return

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


# Alembic's in-process context is module-global; serialize it across requests.
_migration_lock = asyncio.Lock()


def _migrate_in_transaction(connection, schema: str) -> None:
    config = Config(str(BACKEND_ROOT / "alembic.ini"), ini_section="customer")
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations" / "customer"))
    config.attributes.update(connection=connection, target_schema=schema)
    command.upgrade(config, "head")


@asynccontextmanager
async def provisioned_customer(session: AsyncSession, codename: str):
    """Apply migrations and seed data inside the caller's transaction.

    The session is scoped to the new workspace inside the context. An
    exception rolls back the schema, fixture data and customer record together.
    """
    schema = schema_for(codename)
    connection = await session.connection()
    previous_path = await connection.scalar(text("SELECT current_setting('search_path')"))
    async with _migration_lock:
        await connection.run_sync(_migrate_in_transaction, schema)
    await _seed_default_catalog(session, codename)
    yield
    await session.execute(text("SELECT set_config('search_path', :path, true)"), {"path": previous_path})
    log.info("provisioned customer: %s -> %s", codename, schema)


async def provision_customer(codename: str) -> None:
    """End-to-end provisioning. Idempotent."""
    async with AsyncSessionLocal() as session:
        async with session.begin():
            async with provisioned_customer(session, codename):
                pass
