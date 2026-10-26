from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.db.base import engine
from app.services.attack_ingest import refresh_all
from app.worker import celery_app

log = logging.getLogger(__name__)


@celery_app.task(name="detectmap.refresh_attack_catalog", bind=True)
def refresh_attack_catalog(
    self,
    domains: Optional[list[str]] = None,
    force: bool = False,
) -> dict:
    log.info("refresh_attack_catalog: domains=%s force=%s", domains, force)

    async def _run() -> dict:
        # asyncio.run() makes a fresh event loop per task; the module-level
        # engine retains asyncpg connections bound to the previous task's
        # loop, which would surface as "Future attached to a different loop".
        await engine.dispose()
        return await refresh_all(domains, force=force)

    return asyncio.run(_run())


__all__ = ["refresh_attack_catalog"]
