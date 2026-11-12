"""Tenant network inventory and explicit monitoring and detection mappings."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints, field_validator
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import TenantPrincipal, require_active_customer, require_perm
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import (
    Asset,
    AssetDataSource,
    Detection,
    Network,
    NetworkDataSource,
    NetworkDetection,
)
from app.services.network_coverage import NetworkCoverageOut, build_network_coverage
from app.services.roles import resolve_permissions

router = APIRouter(
    prefix="/networks",
    tags=["networks"],
    dependencies=[Depends(require_active_customer())],
)

_asset_read = Depends(require_perm(Permission.ASSET_READ))
_asset_write = Depends(require_perm(Permission.ASSET_WRITE))
_detection_read = Depends(require_perm(Permission.DETECTION_READ))


def _canonical_cidr(value: str) -> str:
    address, separator, prefix = value.partition("/")
    if not separator or not prefix.isascii() or not prefix.isdecimal() or "%" in address:
        raise ValueError("Enter an IPv4 or IPv6 network in CIDR notation, e.g. 192.0.2.0/24")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address and prefix length") from exc


NetworkName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
NetworkCIDR = Annotated[
    str, StringConstraints(strip_whitespace=True, max_length=64), AfterValidator(_canonical_cidr)
]
NetworkLocation = Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)]
NetworkDescription = Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000)]


class NetworkCreate(BaseModel):
    name: NetworkName
    cidr: NetworkCIDR
    description: NetworkDescription | None = None
    location: NetworkLocation | None = None


class NetworkPatch(BaseModel):
    name: NetworkName | None = None
    cidr: NetworkCIDR | None = None
    description: NetworkDescription | None = None
    location: NetworkLocation | None = None

    @field_validator("name", "cidr")
    @classmethod
    def required_when_supplied(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("This field cannot be null")
        return value


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    cidr: str
    description: str | None
    location: str | None
    created_at: datetime
    updated_at: datetime


class NetworkDataSourceOption(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    asset_id: uuid.UUID
    asset_name: str
    enabled: bool


async def _get_network(
    session: AsyncSession,
    network_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> Network:
    row = await session.get(Network, network_id, with_for_update=for_update)
    if row is None:
        raise HTTPException(404, "Network not found")
    return row


async def _save_network(session: AsyncSession, row: Network) -> NetworkOut:
    try:
        await session.flush()
    except IntegrityError as exc:
        if getattr(exc.orig.__cause__, "constraint_name", None) == "uq_networks_cidr":
            raise HTTPException(409, "A network with this CIDR is already registered") from exc
        raise
    await session.refresh(row)
    return NetworkOut.model_validate(row)


@router.get("", response_model=list[NetworkOut], dependencies=[_asset_read])
async def list_networks() -> list[NetworkOut]:
    async with tenant_session() as session:
        rows = await session.scalars(select(Network).order_by(func.lower(Network.name), Network.cidr))
        return [NetworkOut.model_validate(row) for row in rows]


@router.post("", status_code=201, response_model=NetworkOut, dependencies=[_asset_write])
async def create_network(payload: NetworkCreate) -> NetworkOut:
    async with tenant_session() as session:
        row = Network(**payload.model_dump())
        session.add(row)
        return await _save_network(session, row)


@router.get(
    "/data-source-options",
    response_model=list[NetworkDataSourceOption],
    dependencies=[_asset_read],
)
async def list_network_data_source_options(
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
) -> list[NetworkDataSourceOption]:
    stmt = (
        select(
            AssetDataSource.id,
            AssetDataSource.name,
            AssetDataSource.asset_id,
            Asset.name.label("asset_name"),
            AssetDataSource.enabled,
        )
        .join(Asset, Asset.id == AssetDataSource.asset_id)
        .order_by(func.lower(AssetDataSource.name), func.lower(Asset.name), AssetDataSource.id)
        .offset(offset)
        .limit(limit)
    )
    if q:
        stmt = stmt.where(or_(
            AssetDataSource.name.icontains(q, autoescape=True),
            Asset.name.icontains(q, autoescape=True),
        ))
    async with tenant_session() as session:
        rows = await session.execute(stmt)
        return [NetworkDataSourceOption.model_validate(row) for row in rows]


@router.get("/{network_id}", response_model=NetworkOut, dependencies=[_asset_read])
async def get_network(network_id: uuid.UUID) -> NetworkOut:
    async with tenant_session() as session:
        return NetworkOut.model_validate(await _get_network(session, network_id))


@router.get("/{network_id}/coverage", response_model=NetworkCoverageOut)
async def get_network_coverage(
    network_id: uuid.UUID,
    principal: TenantPrincipal = _asset_read,
) -> NetworkCoverageOut:
    permissions = await resolve_permissions(principal.user)
    async with tenant_session() as session:
        network = await _get_network(session, network_id)
        return await build_network_coverage(
            session,
            network,
            include_detections=Permission.DETECTION_READ in permissions,
            include_connectors=Permission.CONNECTOR_READ in permissions,
        )


@router.patch("/{network_id}", response_model=NetworkOut, dependencies=[_asset_write])
async def update_network(network_id: uuid.UUID, payload: NetworkPatch) -> NetworkOut:
    async with tenant_session() as session:
        row = await _get_network(session, network_id, for_update=True)
        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(row, field, value)
        return await _save_network(session, row)


@router.delete("/{network_id}", status_code=204, dependencies=[_asset_write])
async def delete_network(network_id: uuid.UUID) -> Response:
    async with tenant_session() as session:
        row = await _get_network(session, network_id, for_update=True)
        await session.delete(row)
    return Response(status_code=204)


@router.put(
    "/{network_id}/data-sources/{source_id}",
    status_code=204,
    dependencies=[_asset_write],
)
async def attach_network_data_source(network_id: uuid.UUID, source_id: uuid.UUID) -> Response:
    async with tenant_session() as session:
        await _get_network(session, network_id, for_update=True)
        source = await session.get(
            AssetDataSource, source_id, with_for_update={"read": True, "key_share": True}
        )
        if source is None:
            raise HTTPException(422, "Data source does not exist in this customer")
        await session.execute(
            pg_insert(NetworkDataSource)
            .values(network_id=network_id, asset_data_source_id=source_id)
            .on_conflict_do_nothing()
        )
    return Response(status_code=204)


@router.delete(
    "/{network_id}/data-sources/{source_id}",
    status_code=204,
    dependencies=[_asset_write],
)
async def detach_network_data_source(network_id: uuid.UUID, source_id: uuid.UUID) -> Response:
    async with tenant_session() as session:
        await _get_network(session, network_id, for_update=True)
        await session.execute(delete(NetworkDataSource).where(
            NetworkDataSource.network_id == network_id,
            NetworkDataSource.asset_data_source_id == source_id,
        ))
    return Response(status_code=204)


@router.put(
    "/{network_id}/detections/{detection_id}",
    status_code=204,
    dependencies=[_asset_write, _detection_read],
)
async def attach_network_detection(network_id: uuid.UUID, detection_id: uuid.UUID) -> Response:
    async with tenant_session() as session:
        await _get_network(session, network_id, for_update=True)
        rule = await session.get(
            Detection, detection_id, with_for_update={"read": True, "key_share": True}
        )
        if rule is None:
            raise HTTPException(422, "Detection rule does not exist in this customer")
        await session.execute(
            pg_insert(NetworkDetection)
            .values(network_id=network_id, detection_id=detection_id)
            .on_conflict_do_nothing()
        )
    return Response(status_code=204)


@router.delete(
    "/{network_id}/detections/{detection_id}",
    status_code=204,
    dependencies=[_asset_write, _detection_read],
)
async def detach_network_detection(network_id: uuid.UUID, detection_id: uuid.UUID) -> Response:
    async with tenant_session() as session:
        await _get_network(session, network_id, for_update=True)
        await session.execute(delete(NetworkDetection).where(
            NetworkDetection.network_id == network_id,
            NetworkDetection.detection_id == detection_id,
        ))
    return Response(status_code=204)
