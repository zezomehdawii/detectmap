"""Exercise subnet membership and the network evidence view on PostgreSQL."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from ipaddress import ip_network

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import customer_metadata, engine
from app.models.customer import (
    Asset,
    AssetDataSource,
    AssetDetection,
    CollectionPlanItem,
    Connector,
    DeployedUseCase,
    Detection,
    DetectionDeploymentLink,
    DetectionStatus,
    Network,
    NetworkDataSource,
    NetworkDetection,
)
from app.services.network_coverage import _asset_in_subnet, build_network_coverage


@pytest.mark.parametrize(
    ("address", "cidr", "matches"),
    [
        ("192.0.2.10", "192.0.2.0/24", True),
        (" 192.0.2.10/32 ", "192.0.2.0/24", True),
        ("192.0.3.10", "192.0.2.0/24", False),
        ("2001:0DB8::10", "2001:db8::/64", True),
        ("2001:db8::10", "192.0.2.0/24", False),
        ("legacy asset label", "192.0.2.0/24", False),
    ],
)
def test_network_membership(address, cidr, matches):
    assert _asset_in_subnet(address, ip_network(cidr)) is matches


@pytest_asyncio.fixture
async def coverage_session():
    # DDL and test rows share a rollback-only transaction in a fresh schema.
    schema = f"network_test_{uuid.uuid4().hex}"
    async with engine.connect() as connection:
        transaction = await connection.begin()
        try:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            await connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            await connection.run_sync(lambda conn: customer_metadata.create_all(conn, checkfirst=False))
            async with AsyncSession(bind=connection, expire_on_commit=False) as session:
                yield session
        finally:
            await transaction.rollback()


@pytest.mark.asyncio
async def test_network_scope_requires_direct_links_and_evidence_on_the_same_connector(coverage_session):
    session = coverage_session
    network = Network(name="OT segment", cidr="192.0.2.0/24")
    other_network = Network(name="Sensor segment", cidr="198.51.100.0/24")
    empty_network = Network(name="Uninventoried segment", cidr="203.0.113.0/24")
    hmi = Asset(name="HMI", kind="workstation", ip_address="192.0.2.4")
    sensor = Asset(name="SPAN sensor", kind="network_device", ip_address="198.51.100.3")
    retired = Asset(
        name="Retired sensor", kind="network_device", ip_address="192.0.2.6",
        status="decommissioned",
    )
    siem = Connector(kind="splunk", label="OT SIEM")
    other_siem = Connector(kind="elastic", label="Other SIEM")
    rule = Detection(sigma_id="scoped", title="Unexpected remote access")
    unscoped = Detection(
        sigma_id="unscoped", title="Other environment rule",
        detection_status=DetectionStatus.DEPLOYED,
    )
    session.add_all([
        network, other_network, empty_network, hmi, sensor, retired,
        siem, other_siem, rule, unscoped,
    ])
    await session.flush()

    host_source = AssetDataSource(
        asset_id=hmi.id, name="Windows events", storage_connector_id=siem.id,
    )
    traffic = AssetDataSource(
        asset_id=sensor.id, name="SPAN traffic", storage_connector_id=siem.id,
        storage_location="ot_flow",
    )
    retired_source = AssetDataSource(
        asset_id=retired.id, name="Retired feed", storage_connector_id=other_siem.id,
    )
    observed = DeployedUseCase(
        connector_id=siem.id, external_id="01", name="OT remote access",
        enabled=False, import_source="csv",
    )
    other_observed = DeployedUseCase(
        connector_id=other_siem.id, external_id="01", name="Other SIEM remote access",
    )
    unconfirmed = DeployedUseCase(
        connector_id=siem.id, external_id=rule.sigma_id, name=rule.title,
    )
    session.add_all([host_source, traffic, retired_source, observed, other_observed, unconfirmed])
    await session.flush()

    recorded_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    session.add_all([
        AssetDetection(asset_id=hmi.id, detection_id=rule.id),
        NetworkDataSource(network_id=other_network.id, asset_data_source_id=traffic.id),
        NetworkDataSource(network_id=empty_network.id, asset_data_source_id=traffic.id),
        NetworkDetection(network_id=other_network.id, detection_id=unscoped.id),
        CollectionPlanItem(
            data_source=host_source.name, target_asset_id=hmi.id,
            asset_data_source_id=host_source.id, status="validated",
            notes="Observed expected Windows event", updated_at=recorded_at,
        ),
        # An invalid legacy plan link should never provide validation evidence.
        CollectionPlanItem(
            data_source=traffic.name, target_asset_id=hmi.id,
            asset_data_source_id=traffic.id, status="validated", notes="Different asset",
        ),
        DetectionDeploymentLink(
            detection_id=rule.id, deployed_use_case_id=observed.id,
            status="confirmed", updated_at=recorded_at,
        ),
        DetectionDeploymentLink(
            detection_id=rule.id, deployed_use_case_id=other_observed.id, status="confirmed",
        ),
    ])
    await session.flush()

    async def coverage(*, detections=True, connectors=True):
        await session.flush()
        return await build_network_coverage(
            session, network, include_detections=detections, include_connectors=connectors,
        )

    result = await coverage()
    assert result.monitoring_status == "no_sources"
    assert result.detection_status == "no_rules"
    assert [asset.id for asset in result.assets] == [hmi.id, retired.id]
    assert result.monitored_asset_count == result.validated_asset_count == 1
    assert result.assets[0].rules[0].evidence_status == "enabled_without_source"

    empty = await build_network_coverage(
        session, empty_network, include_detections=True, include_connectors=True,
    )
    assert not empty.assets
    assert empty.asset_monitoring_status == "no_assets"
    assert empty.monitoring_status == "configured"
    assert [source.id for source in empty.data_sources] == [traffic.id]

    session.add_all([
        NetworkDataSource(network_id=network.id, asset_data_source_id=traffic.id),
        NetworkDataSource(network_id=network.id, asset_data_source_id=retired_source.id),
        NetworkDetection(network_id=network.id, detection_id=rule.id),
    ])
    result = await coverage()
    assert result.monitoring_status == "configured"
    assert result.detection_status == "mapped"
    assert result.rules[0].evidence_status == "enabled_without_source"
    assert {item.id for item in result.rules[0].deployments} == {observed.id, other_observed.id}

    observed.enabled = True
    result = await coverage()
    assert result.detection_status == "partially_supported"
    assert result.rules[0].evidence_status == "enabled_with_source"
    deployment = next(item for item in result.rules[0].deployments if item.id == observed.id)
    assert deployment.source_ids == [traffic.id]
    assert deployment.validated_source_ids == []
    assert deployment.confirmed_at == recorded_at
    assert deployment.import_source == "csv"

    session.add(CollectionPlanItem(
        data_source=traffic.name, target_asset_id=sensor.id,
        asset_data_source_id=traffic.id, status="validated",
        notes="Observed expected SPAN traffic", updated_at=recorded_at,
    ))
    result = await coverage()
    assert result.monitoring_status == "validated"
    assert result.detection_status == "supported"
    deployment = next(item for item in result.rules[0].deployments if item.id == observed.id)
    assert deployment.validated_source_ids == [traffic.id]
    assert next(source for source in result.data_sources if source.id == traffic.id).validated_at == recorded_at

    result = await coverage(detections=False)
    assert result.monitoring_status == "validated"
    assert result.detection_status is None
    assert not result.detection_evidence_available
    assert not result.rules and not result.assets[0].rules

    result = await coverage(connectors=False)
    assert result.detection_status is None
    assert not result.connector_evidence_available
    assert result.rules[0].evidence_status is None
    assert not result.rules[0].deployments
    assert all(source.connector_id is None and source.storage_location is None for source in result.data_sources)

    traffic.enabled = False
    result = await coverage()
    assert result.monitoring_status == "no_sources"
    assert result.detection_status == "mapped"
