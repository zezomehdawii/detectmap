"""FastAPI app entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import apt as apt_router
from app.api import assets as assets_router
from app.api import auth as auth_router
from app.api import catalog as catalog_router
from app.api import cmf as cmf_router
from app.api import cmf_plan as cmf_plan_router
from app.api import connectors as connectors_router
from app.api import coverage as coverage_router
from app.api import customers as customers_router
from app.api import detections as detections_router
from app.api import diagrams as diagrams_router
from app.api import gaps as gaps_router
from app.api import grc as grc_router
from app.api import portfolio as portfolio_router
from app.api import posture as posture_router
from app.api import reports as reports_router
from app.api import roles as roles_router
from app.api import saved_views as saved_views_router
from app.api import search as search_router
from app.api import settings as settings_router
from app.config import settings
from app.db.tenant import set_tenant

logging.basicConfig(
    level=logging.DEBUG if settings.app_debug else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("detectmap")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("starting %s (env=%s)", settings.app_name, settings.app_env)
    yield
    log.info("shutting down")


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Customer"],
)


@app.middleware("http")
async def clear_tenant_after_request(request: Request, call_next):
    """Ensure tenant context never bleeds between requests on the same worker."""
    try:
        response = await call_next(request)
        return response
    finally:
        set_tenant(None)


@app.exception_handler(PermissionError)
async def _permission_error(_: Request, exc: PermissionError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=403)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "app": settings.app_name}


app.include_router(auth_router.router)
app.include_router(customers_router.router)
app.include_router(catalog_router.router)
app.include_router(catalog_router.sigmahq_router)
app.include_router(catalog_router.d3fend_router)
app.include_router(detections_router.router)
app.include_router(coverage_router.router)
app.include_router(apt_router.router)
app.include_router(gaps_router.router)
app.include_router(posture_router.router)
app.include_router(reports_router.router)
app.include_router(grc_router.router)
app.include_router(connectors_router.router)
app.include_router(portfolio_router.router)
app.include_router(settings_router.router)
app.include_router(search_router.router)
app.include_router(saved_views_router.router)
app.include_router(roles_router.router)
app.include_router(assets_router.router)
app.include_router(cmf_router.router)
app.include_router(cmf_plan_router.router)
app.include_router(diagrams_router.router)
