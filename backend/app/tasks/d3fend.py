from __future__ import annotations

import asyncio
import logging

from app.db.base import engine
from app.services.d3fend_ingest import refresh
from app.worker import celery_app

log = logging.getLogger(__name__)


@celery_app.task(name="detectmap.refresh_d3fend", bind=True)
def refresh_d3fend(self, force: bool = False) -> dict:
    log.info("refresh_d3fend: force=%s", force)

    async def _run() -> dict:
        await engine.dispose()
        return await refresh(force=force)

    return asyncio.run(_run())


__all__ = ["refresh_d3fend"]
