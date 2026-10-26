"""Celery task for SigmaHQ catalog refresh."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.db.base import engine
from app.services.sigmahq_sync import refresh
from app.worker import celery_app

log = logging.getLogger(__name__)


@celery_app.task(name="detectmap.refresh_sigmahq_catalog", bind=True)
def refresh_sigmahq_catalog(
    self,
    ref: Optional[str] = None,
    force: bool = False,
) -> dict:
    log.info("refresh_sigmahq_catalog: ref=%s force=%s", ref, force)

    async def _run() -> dict:
        # Same event-loop hygiene as the ATT&CK task — fresh engine per run.
        await engine.dispose()
        return await refresh(ref, force=force)

    return asyncio.run(_run())


__all__ = ["refresh_sigmahq_catalog"]
