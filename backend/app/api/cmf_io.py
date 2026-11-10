"""Tenant-scoped CMF submissions. Never export connector credentials."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import Asset, AssetDataSource, CollectionPlanItem, CollectionRequirement
from app.services.cmf_export import register_csv, submission_snapshot

router = APIRouter(prefix="/cmf", tags=["cmf"])


async def _snapshot(principal: TenantPrincipal) -> dict:
    async with tenant_session() as session:
        assets = (await session.execute(select(Asset).order_by(Asset.name, Asset.id))).scalars().all()
        sources = (await session.execute(select(AssetDataSource).order_by(AssetDataSource.asset_id, AssetDataSource.name))).scalars().all()
        requirements = (await session.execute(select(CollectionRequirement).order_by(CollectionRequirement.created_at, CollectionRequirement.id))).scalars().all()
        plan = (await session.execute(select(CollectionPlanItem).order_by(CollectionPlanItem.created_at, CollectionPlanItem.id))).scalars().all()
        return submission_snapshot(principal.customer.codename, assets, sources, requirements, plan)


@router.get("/export.json")
async def export_json(
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    _: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    snapshot = await _snapshot(principal)
    return Response(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="cmf-{principal.customer.codename}.json"'},
    )


@router.get("/export.csv")
async def export_csv(
    principal: TenantPrincipal = Depends(require_perm(Permission.ASSET_READ)),
    _: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    return Response(
        register_csv(await _snapshot(principal)),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cmf-register-{principal.customer.codename}.csv"'},
    )
