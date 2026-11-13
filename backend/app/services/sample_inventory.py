"""Populate the managed sample tenants with synthetic inventory and evidence."""
from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.customer import (
    Asset,
    AssetDataSource,
    AssetDetection,
    CollectionPlanItem,
    CollectionRequirement,
    Connector,
    DeployedUseCase,
    Detection,
    DetectionDeploymentLink,
    DetectionTechnique,
    GapComment,
    Network,
    NetworkDataSource,
    NetworkDetection,
)


_SAMPLES = {
    "acme": {
        "cidr": "192.0.2.0/24",
        "address": "192.0.2.10",
        "network": "Finance workstations",
        "asset": "ACME-FIN-01",
        "asset_kind": "workstation",
        "asset_category": "endpoint",
        "unmonitored_cidr": "198.51.100.0/24",
        "unmonitored_network": "Finance lab",
        "source": "Windows process creation",
        "component": "Process Creation",
        "kind": "splunk",
        "connector": "ACME prod Splunk Cloud",
        "detection": "acme-custom-001",
        "techniques": ["T1059.001", "T1027"],
        "gap": "T1078",
        "domain": "enterprise",
        "plan": "Collect identity audit records",
        "planned_source": "User Account Authentication",
    },
    "globex": {
        "cidr": "198.51.100.0/24",
        "address": "198.51.100.20",
        "network": "Substation control network",
        "asset": "GLOBEX-PLC-01",
        "asset_kind": "iot_ot",
        "asset_category": "ot",
        "unmonitored_cidr": "203.0.113.0/24",
        "unmonitored_network": "Maintenance bench",
        "source": "OT network traffic",
        "component": "Network Traffic Content",
        "kind": "splunk",
        "connector": "Globex OT Splunk",
        "detection": "globex-custom-001",
        "techniques": ["T1692.001", "T0855"],
        "gap": "T0843",
        "domain": "ics",
        "plan": "Collect controller program changes",
        "planned_source": "Application Log Content",
    },
}


async def seed_sample_inventory(session: AsyncSession, dataset: str) -> None:
    """Load examples into the caller's tenant schema without replacing rows."""
    spec = _SAMPLES[dataset]
    detection = await session.scalar(select(Detection).where(Detection.sigma_id == spec["detection"]))
    connector = await session.scalar(select(Connector).where(
        Connector.kind == spec["kind"], Connector.label == spec["connector"],
    ))

    async def seed(model, key, **fields):
        row_id = uuid5(NAMESPACE_URL, f"detectmap/sample/{dataset}/{key}")
        await session.execute(
            insert(model).values(id=row_id, **fields).on_conflict_do_nothing()
        )
        return row_id

    await seed(
        Network, "unmonitored-network", name=spec["unmonitored_network"], cidr=spec["unmonitored_cidr"],
        description="Sample network awaiting telemetry collection.",
    )
    network_id = await seed(
        Network, "network", name=spec["network"], cidr=spec["cidr"],
        description="Sample network for demonstrating collection and detection coverage.",
    )
    network_exists = await session.scalar(select(Network.id).where(Network.id == network_id))

    asset_id = await seed(
        Asset, "asset", name=spec["asset"], kind=spec["asset_kind"], cmf_category=spec["asset_category"],
        hostname=spec["asset"].lower(), ip_address=spec["address"], criticality="high", owner="Sample SOC",
    )
    source_id = await seed(
        AssetDataSource, "source", asset_id=asset_id, name=spec["source"], attack_data_source=spec["component"],
        storage_connector_id=connector.id if connector else None, retention_days=30,
        notes="Sample collection record.",
    )
    if network_exists:
        await session.execute(insert(NetworkDataSource).values(
            network_id=network_id, asset_data_source_id=source_id,
        ).on_conflict_do_nothing())
    if detection:
        # Old Globex samples still carry the retired mapping. Add its current
        # equivalent while leaving their existing use case and mappings intact.
        if dataset == "globex":
            await seed(
                DetectionTechnique, "command-message", detection_id=detection.id,
                technique_id="T1692.001", domain="ics",
            )
        await seed(AssetDetection, "asset-detection", asset_id=asset_id, detection_id=detection.id)
        if network_exists:
            await session.execute(insert(NetworkDetection).values(
                network_id=network_id, detection_id=detection.id,
            ).on_conflict_do_nothing())
        if connector:
            await seed(
                DeployedUseCase, "deployment", connector_id=connector.id, import_source="csv",
                external_id=f"sample-{spec['detection']}", name=detection.title,
                description="Example from a synthetic SIEM export.",
                severity="high", technique_ids=spec["techniques"], raw={"synthetic": True},
            )
            deployment_id = await session.scalar(select(DeployedUseCase.id).where(
                DeployedUseCase.connector_id == connector.id,
                DeployedUseCase.external_id == f"sample-{spec['detection']}",
            ))
            await seed(
                DetectionDeploymentLink, "deployment-link", detection_id=detection.id,
                deployed_use_case_id=deployment_id, status="confirmed",
                note="Example mapping verified against a synthetic SIEM export.",
            )

    await seed(
        GapComment, "gap-comment", technique_id=spec["gap"], domain=spec["domain"],
        body="Add telemetry for this technique and validate coverage in the next review.",
    )
    requirement_id = await seed(
        CollectionRequirement, "requirement", title=spec["plan"],
        attack_technique_ids=[spec["gap"]], driver="risk_management", priority="high", status="active",
    )
    await seed(
        CollectionPlanItem, "plan", requirement_id=requirement_id, title=spec["plan"],
        data_source=spec["planned_source"], priority="high", target_asset_id=asset_id,
        status="proposed", rationale="Sample plan item addressing the documented coverage gap.",
    )
    await seed(
        CollectionPlanItem, "validation", target_asset_id=asset_id, asset_data_source_id=source_id,
        data_source=spec["component"], title=f"Validate {spec['source']}",
        status="validated", rationale="Example record of validation in the sample tenant.",
        notes="Synthetic events were received from the sample asset with the expected fields.",
    )
