"""Celerybeat-fired wrapper tasks.

Each wrapper:
  1. Loads the `app_settings` singleton row from the public schema.
  2. Returns early with `{"skipped": True}` if the corresponding
     `<job>_enabled` flag is False.
  3. Otherwise delegates to the real refresh task synchronously and
     records a stamp on `last_*_at` (best effort) so the Settings UI can
     show "last ran X minutes ago".

We don't try to interpret cron strings — celerybeat fires on a fixed
interval (see `worker.py`) and the enable flag is the only knob. The
existing cron columns in `app_settings` are kept as informational
metadata for the UI ("nominally weekly Monday 4am UTC") but are no
longer load-bearing.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy import or_, select

from app.db.base import AsyncSessionLocal, engine
from app.models.public import AppSettings, ScheduledJobRun
from app.services.attack_ingest import refresh_all as refresh_attack
from app.services.d3fend_ingest import refresh as refresh_d3fend_fn
from app.services.sigmahq_sync import refresh as refresh_sigmahq_fn
from app.worker import celery_app

log = logging.getLogger(__name__)


async def _enabled(session, flag: str) -> bool:
    row = (await session.execute(select(AppSettings))).scalar_one_or_none()
    if row is None:
        return False
    return bool(getattr(row, flag, False))


async def _record_run(session, job: str, status: str, detail: str | None = None) -> None:
    """Append a run-history row. Best-effort — never raises into the task."""
    try:
        session.add(
            ScheduledJobRun(
                id=uuid.uuid4(),
                job=job,
                status=status,
                detail=(detail or "")[:2000] or None,
            )
        )
        await session.commit()
    except Exception:  # noqa: BLE001
        log.exception("failed to record scheduled run for %s", job)


def _summarize(result) -> str:
    if isinstance(result, dict):
        return ", ".join(
            f"{k}={v}" for k, v in result.items() if not isinstance(v, (dict, list))
        )[:500]
    return str(result)[:500]


def _run_job(job: str, flag: str, refresh_coro_factory) -> dict:
    """Shared body, all on a SINGLE event loop.

    A fresh `asyncio.run` makes a new loop per Celery task; the shared
    asyncpg engine pins connections to whichever loop first used them, so
    every DB touch in this task must happen inside one loop after a single
    `engine.dispose()`. (Same hygiene as `tasks/catalog.py`.)
    """
    async def _flow() -> dict:
        await engine.dispose()
        async with AsyncSessionLocal() as session:
            enabled = await _enabled(session, flag)
        if not enabled:
            log.info("%s: disabled, skipping", job)
            async with AsyncSessionLocal() as session:
                await _record_run(session, job, "skipped", "schedule disabled")
            return {"skipped": True, "reason": "not enabled"}

        log.info("%s: running", job)
        try:
            result = await refresh_coro_factory()
        except Exception as e:  # noqa: BLE001
            async with AsyncSessionLocal() as session:
                await _record_run(session, job, "error", str(e))
            raise
        async with AsyncSessionLocal() as session:
            await _record_run(session, job, "ok", _summarize(result))
        return result

    return asyncio.run(_flow())


@celery_app.task(name="detectmap.scheduled_refresh_attack", bind=True)
def scheduled_refresh_attack(self) -> dict:
    return _run_job("attack", "attack_refresh_enabled", lambda: refresh_attack())


@celery_app.task(name="detectmap.scheduled_refresh_sigmahq", bind=True)
def scheduled_refresh_sigmahq(self) -> dict:
    return _run_job("sigmahq", "sigmahq_refresh_enabled", lambda: refresh_sigmahq_fn())


@celery_app.task(name="detectmap.scheduled_refresh_d3fend", bind=True)
def scheduled_refresh_d3fend(self) -> dict:
    return _run_job("d3fend", "d3fend_refresh_enabled", lambda: refresh_d3fend_fn())


@celery_app.task(name="detectmap.scheduled_snapshot", bind=True)
def scheduled_snapshot(self) -> dict:
    """Capture a coverage snapshot for every active customer (posture trend).

    Gated by `snapshot_refresh_enabled`. All DB work on a single event loop
    after one engine.dispose() (asyncpg loop-pinning hygiene)."""
    from app.db.tenant import set_tenant
    from app.models.public import Customer, CustomerStatus, MSSPOrg
    from app.services.coverage import DenominatorKind, save_snapshot

    async def _flow() -> dict:
        await engine.dispose()
        async with AsyncSessionLocal() as session:
            if not await _enabled(session, "snapshot_refresh_enabled"):
                await _record_run(session, "snapshot", "skipped", "schedule disabled")
                return {"skipped": True, "reason": "not enabled"}
            codenames = (
                await session.execute(
                    select(Customer.codename)
                    .join(MSSPOrg, MSSPOrg.id == Customer.mssp_org_id)
                    .where(
                        Customer.status == CustomerStatus.ACTIVE,
                        or_(MSSPOrg.sample_data_enabled, Customer.sample_dataset.is_(None)),
                        or_(MSSPOrg.deployment_mode != "single", MSSPOrg.single_customer == Customer.codename),
                    )
                )
            ).scalars().all()

        ok = 0
        errors: list[str] = []
        for codename in codenames:
            try:
                set_tenant(codename)
                await save_snapshot("enterprise", DenominatorKind.FULL, None, notes="scheduled")
                ok += 1
            except Exception as e:  # noqa: BLE001
                errors.append(f"{codename}: {type(e).__name__}")
            finally:
                set_tenant(None)

        status = "ok" if not errors else "error"
        detail = f"snapshotted {ok}/{len(codenames)}" + (
            f"; errors: {', '.join(errors)}" if errors else ""
        )
        async with AsyncSessionLocal() as session:
            await _record_run(session, "snapshot", status, detail)
        return {"snapshotted": ok, "total": len(codenames), "errors": errors}

    return asyncio.run(_flow())


__all__ = [
    "scheduled_refresh_attack",
    "scheduled_refresh_sigmahq",
    "scheduled_refresh_d3fend",
    "scheduled_snapshot",
]
