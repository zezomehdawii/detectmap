"""Read the collection and SIEM evidence associated with a registered subnet."""
from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_interface, ip_network
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import and_, any_, func, literal, or_, select
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from app.models.customer import (
    Asset,
    AssetDataSource,
    AssetDetection,
    CollectionPlanItem,
    Connector,
    DeployedUseCase,
    Detection,
    DetectionDeploymentLink,
    Network,
    NetworkDataSource,
    NetworkDetection,
)

RuleEvidenceStatus = Literal[
    "mapped",
    "enabled_without_source",
    "enabled_with_source",
    "enabled_with_validated_source",
]
MonitoringStatus = Literal["no_sources", "configured", "partially_validated", "validated"]
AssetMonitoringStatus = Literal["no_assets", "no_sources", "configured", "partial", "validated"]
DetectionStatus = Literal["no_rules", "mapped", "partially_supported", "supported"]


class NetworkSourceEvidence(BaseModel):
    id: uuid.UUID
    name: str
    asset_id: uuid.UUID
    asset_name: str
    asset_status: str
    enabled: bool
    # This is the latest CMF validation record update, not a live event timestamp.
    validated_at: datetime | None
    connector_id: uuid.UUID | None
    connector_label: str | None
    storage_location: str | None


class NetworkDeploymentEvidence(BaseModel):
    id: uuid.UUID
    name: str
    connector_id: uuid.UUID
    connector_label: str
    enabled: bool
    import_source: str
    synced_at: datetime
    confirmed_at: datetime
    source_ids: list[uuid.UUID]
    validated_source_ids: list[uuid.UUID]


class NetworkRuleEvidence(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    evidence_status: RuleEvidenceStatus | None
    deployments: list[NetworkDeploymentEvidence]


class NetworkAssetEvidence(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    ip_address: str
    status: str
    data_sources: list[NetworkSourceEvidence] = Field(default_factory=list)
    rules: list[NetworkRuleEvidence] = Field(default_factory=list)


class NetworkCoverageOut(BaseModel):
    detection_evidence_available: bool
    connector_evidence_available: bool
    monitoring_status: MonitoringStatus
    detection_status: DetectionStatus | None
    data_sources: list[NetworkSourceEvidence]
    rules: list[NetworkRuleEvidence]
    asset_monitoring_status: AssetMonitoringStatus
    monitored_asset_count: int
    validated_asset_count: int
    assets: list[NetworkAssetEvidence]


def _asset_in_subnet(ip_address: str, subnet: IPv4Network | IPv6Network) -> bool:
    try:
        return ip_interface(ip_address.strip()).ip in subnet
    except ValueError:
        # Primary IP was historically stored as free text.
        return False


def _active_source(source: NetworkSourceEvidence) -> bool:
    return source.enabled and source.asset_status != "decommissioned"


def _any_id(ids: Iterable[uuid.UUID]):
    # One array parameter also works for subnets with large asset inventories.
    return any_(literal(list(ids), type_=ARRAY(UUID(as_uuid=True))))


def _monitoring_status(sources: list[NetworkSourceEvidence]) -> MonitoringStatus:
    enabled = [source for source in sources if _active_source(source)]
    if not enabled:
        return "no_sources"
    validated = sum(source.validated_at is not None for source in enabled)
    if validated == len(enabled):
        return "validated"
    if validated:
        return "partially_validated"
    return "configured"


def _asset_monitoring_status(
    asset_count: int, monitored_count: int, validated_count: int
) -> AssetMonitoringStatus:
    if not asset_count:
        return "no_assets"
    if not monitored_count:
        return "no_sources"
    if validated_count == asset_count:
        return "validated"
    if monitored_count == asset_count and not validated_count:
        return "configured"
    return "partial"


def _detection_status(rules: list[NetworkRuleEvidence]) -> DetectionStatus:
    if not rules:
        return "no_rules"
    if all(rule.evidence_status == "enabled_with_validated_source" for rule in rules):
        return "supported"
    if any(
        rule.evidence_status in {"enabled_with_source", "enabled_with_validated_source"}
        for rule in rules
    ):
        return "partially_supported"
    return "mapped"


async def _load_sources(
    session: AsyncSession,
    network_id: uuid.UUID,
    assets: dict[uuid.UUID, NetworkAssetEvidence],
    *,
    include_connectors: bool,
) -> list[NetworkSourceEvidence]:
    is_scoped = NetworkDataSource.network_id.is_not(None)
    validated = (
        select(func.max(CollectionPlanItem.updated_at))
        .where(
            CollectionPlanItem.asset_data_source_id == AssetDataSource.id,
            CollectionPlanItem.target_asset_id == AssetDataSource.asset_id,
            CollectionPlanItem.status == "validated",
            func.btrim(CollectionPlanItem.notes) != "",
        )
        .correlate(AssetDataSource)
        .scalar_subquery()
    )
    query = (
        select(AssetDataSource, Asset.name, Asset.status, is_scoped, validated)
        .options(load_only(
            AssetDataSource.id,
            AssetDataSource.name,
            AssetDataSource.asset_id,
            AssetDataSource.enabled,
            AssetDataSource.storage_connector_id,
            AssetDataSource.storage_location,
        ))
        .join(Asset, Asset.id == AssetDataSource.asset_id)
        .outerjoin(
            NetworkDataSource,
            and_(
                NetworkDataSource.asset_data_source_id == AssetDataSource.id,
                NetworkDataSource.network_id == network_id,
            ),
        )
        .where(or_(AssetDataSource.asset_id == _any_id(assets), is_scoped))
        .order_by(AssetDataSource.name, AssetDataSource.id)
    )
    if include_connectors:
        query = query.add_columns(Connector.label).outerjoin(
            Connector, Connector.id == AssetDataSource.storage_connector_id
        )

    network_sources: list[NetworkSourceEvidence] = []
    for row in await session.execute(query):
        source, asset_name, asset_status, network_scoped, validated_at = row[:5]
        evidence = NetworkSourceEvidence(
            id=source.id,
            name=source.name,
            asset_id=source.asset_id,
            asset_name=asset_name,
            asset_status=asset_status,
            enabled=source.enabled,
            validated_at=validated_at if source.enabled and asset_status != "decommissioned" else None,
            connector_id=source.storage_connector_id if include_connectors else None,
            connector_label=row[5] if include_connectors else None,
            storage_location=source.storage_location if include_connectors else None,
        )
        if network_scoped:
            network_sources.append(evidence)
        if source.asset_id in assets:
            assets[source.asset_id].data_sources.append(evidence)
    return network_sources


async def _load_confirmed_deployments(
    session: AsyncSession, detection_ids: set[uuid.UUID]
) -> dict[uuid.UUID, list[tuple[DeployedUseCase, str, datetime]]]:
    if not detection_ids:
        return {}
    query = (
        select(
            DetectionDeploymentLink.detection_id,
            DeployedUseCase,
            Connector.label,
            DetectionDeploymentLink.updated_at,
        )
        .options(load_only(
            DeployedUseCase.id,
            DeployedUseCase.name,
            DeployedUseCase.connector_id,
            DeployedUseCase.enabled,
            DeployedUseCase.import_source,
            DeployedUseCase.synced_at,
        ))
        .select_from(DetectionDeploymentLink)
        .join(DeployedUseCase, DeployedUseCase.id == DetectionDeploymentLink.deployed_use_case_id)
        .join(Connector, Connector.id == DeployedUseCase.connector_id)
        .where(
            DetectionDeploymentLink.detection_id == _any_id(detection_ids),
            DetectionDeploymentLink.status == "confirmed",
        )
        .order_by(Connector.label, DeployedUseCase.name, DeployedUseCase.id)
    )
    deployments = defaultdict(list)
    for detection_id, deployment, connector_label, confirmed_at in await session.execute(query):
        deployments[detection_id].append((deployment, connector_label, confirmed_at))
    return deployments


def _sources_by_connector(
    sources: list[NetworkSourceEvidence],
) -> dict[uuid.UUID, list[NetworkSourceEvidence]]:
    grouped = defaultdict(list)
    for source in sources:
        if _active_source(source) and source.connector_id is not None:
            grouped[source.connector_id].append(source)
    return grouped


def _rule_evidence(
    rule: Detection,
    deployments: list[tuple[DeployedUseCase, str, datetime]],
    sources_by_connector: dict[uuid.UUID, list[NetworkSourceEvidence]],
    *,
    include_connectors: bool,
) -> NetworkRuleEvidence:
    details: list[NetworkDeploymentEvidence] = []
    for deployment, label, confirmed_at in deployments:
        sources = sources_by_connector.get(deployment.connector_id, [])
        details.append(
            NetworkDeploymentEvidence(
                id=deployment.id,
                name=deployment.name,
                connector_id=deployment.connector_id,
                connector_label=label,
                enabled=deployment.enabled,
                import_source=deployment.import_source,
                synced_at=deployment.synced_at,
                confirmed_at=confirmed_at,
                source_ids=[source.id for source in sources],
                validated_source_ids=[source.id for source in sources if source.validated_at],
            )
        )

    status: RuleEvidenceStatus | None = None
    if include_connectors:
        enabled = [deployment for deployment in details if deployment.enabled]
        if any(deployment.validated_source_ids for deployment in enabled):
            status = "enabled_with_validated_source"
        elif any(deployment.source_ids for deployment in enabled):
            status = "enabled_with_source"
        elif enabled:
            status = "enabled_without_source"
        else:
            status = "mapped"
    return NetworkRuleEvidence(
        id=rule.id,
        title=rule.title,
        status=rule.detection_status.value,
        evidence_status=status,
        deployments=details,
    )


async def _load_rules(
    session: AsyncSession,
    network_id: uuid.UUID,
    network_sources: list[NetworkSourceEvidence],
    assets: dict[uuid.UUID, NetworkAssetEvidence],
    *,
    include_connectors: bool,
) -> list[NetworkRuleEvidence]:
    rule_columns = load_only(Detection.id, Detection.title, Detection.detection_status)
    network_rules = (
        await session.scalars(
            select(Detection)
            .options(rule_columns)
            .join(NetworkDetection, NetworkDetection.detection_id == Detection.id)
            .where(NetworkDetection.network_id == network_id)
            .order_by(Detection.title, Detection.id)
        )
    ).all()
    asset_rules = []
    if assets:
        asset_rules = (
            await session.execute(
                select(AssetDetection.asset_id, Detection)
                .options(rule_columns)
                .join(Detection, Detection.id == AssetDetection.detection_id)
                .where(AssetDetection.asset_id == _any_id(assets))
                .order_by(Detection.title, Detection.id)
            )
        ).all()

    deployments = {}
    if include_connectors:
        detection_ids = {rule.id for rule in network_rules}
        detection_ids.update(rule.id for _, rule in asset_rules)
        deployments = await _load_confirmed_deployments(session, detection_ids)

    asset_sources = {
        asset.id: _sources_by_connector(asset.data_sources)
        for asset in assets.values()
    }
    for asset_id, rule in asset_rules:
        assets[asset_id].rules.append(
            _rule_evidence(
                rule, deployments.get(rule.id, []), asset_sources[asset_id],
                include_connectors=include_connectors,
            )
        )

    network_routes = _sources_by_connector(network_sources)
    return [
        _rule_evidence(
            rule, deployments.get(rule.id, []), network_routes,
            include_connectors=include_connectors,
        )
        for rule in network_rules
    ]


async def build_network_coverage(
    session: AsyncSession,
    network: Network,
    *,
    include_detections: bool,
    include_connectors: bool,
) -> NetworkCoverageOut:
    """Use explicit scope at network level and show IP-matched assets separately.

    A connector route supports a configured scope. Its evidence cannot show
    what a SIEM query actually evaluates or whether every IP is visible.
    """
    subnet = ip_network(network.cidr)
    rows = await session.execute(
        select(Asset.id, Asset.name, Asset.kind, Asset.ip_address, Asset.status)
        .where(Asset.ip_address.is_not(None))
        .order_by(Asset.name, Asset.id)
    )
    assets = {
        asset.id: NetworkAssetEvidence.model_validate(asset._mapping)
        for asset in rows
        if _asset_in_subnet(asset.ip_address, subnet)
    }
    network_sources = await _load_sources(
        session, network.id, assets, include_connectors=include_connectors
    )
    network_rules = []
    if include_detections:
        network_rules = await _load_rules(
            session, network.id, network_sources, assets, include_connectors=include_connectors
        )

    asset_statuses = [
        _monitoring_status(asset.data_sources)
        for asset in assets.values()
        if asset.status != "decommissioned"
    ]
    monitored_count = sum(status != "no_sources" for status in asset_statuses)
    validated_count = sum(
        status in {"partially_validated", "validated"} for status in asset_statuses
    )
    return NetworkCoverageOut(
        detection_evidence_available=include_detections,
        connector_evidence_available=include_connectors,
        monitoring_status=_monitoring_status(network_sources),
        detection_status=(
            _detection_status(network_rules) if include_detections and include_connectors else None
        ),
        data_sources=network_sources,
        rules=network_rules,
        asset_monitoring_status=_asset_monitoring_status(
            len(asset_statuses), monitored_count, validated_count
        ),
        monitored_asset_count=monitored_count,
        validated_asset_count=validated_count,
        assets=list(assets.values()),
    )
