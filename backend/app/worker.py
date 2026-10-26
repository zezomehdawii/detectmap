"""Celery worker entrypoint."""
from __future__ import annotations

from celery import Celery

from app.config import settings

celery_app = Celery(
    "detectmap",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(name="detectmap.healthcheck")
def healthcheck() -> str:
    return "ok"


# Imported at module-bottom so celery_app is defined before app.tasks.*
# imports it back. Side-effect: registers @celery_app.task decorators.
from app.tasks import catalog as _catalog_tasks  # noqa: E402, F401
from app.tasks import sigmahq as _sigmahq_tasks  # noqa: E402, F401
from app.tasks import d3fend as _d3fend_tasks  # noqa: E402, F401
from app.tasks import scheduled as _scheduled_tasks  # noqa: E402, F401

# ---- celerybeat schedule -------------------------------------------------
# Phase 10: the beat fires `scheduled_*` wrapper tasks that read the
# `app_settings` singleton row, short-circuit if the corresponding
# `_enabled` flag is False, and otherwise delegate to the real refresh
# task. This keeps the schedule logic out of the celery config and the
# UI's enable-toggle one round-trip away from effect.
celery_app.conf.beat_schedule = {
    "scheduled-attack-refresh": {
        "task": "detectmap.scheduled_refresh_attack",
        "schedule": 24 * 3600.0,  # daily check; runs only if enabled
    },
    "scheduled-sigmahq-refresh": {
        "task": "detectmap.scheduled_refresh_sigmahq",
        "schedule": 24 * 3600.0,
    },
    "scheduled-d3fend-refresh": {
        "task": "detectmap.scheduled_refresh_d3fend",
        "schedule": 7 * 24 * 3600.0,  # weekly — D3FEND moves slowly
    },
    "scheduled-snapshot": {
        "task": "detectmap.scheduled_snapshot",
        "schedule": 24 * 3600.0,  # daily posture snapshot, runs only if enabled
    },
}
