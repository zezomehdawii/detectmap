"""Seed dummy data so every dashboard feature has something to look at.

Idempotent — running it twice does not duplicate rows. Specifically it
populates:
  - per-customer branding (display name, primary color)
  - sample connectors (Splunk / Sentinel / Elastic) with Fernet-encrypted
    secret fields
  - hand-crafted CUSTOM detections + one CUSTOMIZED clone of a global rule,
    per tenant
  - a sprinkle of `gap` and `not_applicable` detection statuses for variety
  - user-source GRC mappings on a few seeded controls
  - sector-denominator coverage snapshots so the posture-trend filter has
    something other than `full` to draw

Run inside the backend container:

    docker compose exec backend python -m app.scripts.seed_dummy_data
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, select, text

from app.core.crypto import encrypt
from app.db.base import AsyncSessionLocal, engine
from app.db.tenant import set_tenant, tenant_session
from app.models.customer import (
    Connector,
    CoverageSnapshot,
    Detection,
    DetectionReviewStatus,
    DetectionSource,
    DetectionStatus,
    DetectionTechnique,
    SigmaLevel,
)
from app.models.public import (
    Customer,
    GRCControl,
    GRCFramework,
    GRCTechniqueMapping,
)
from app.services.coverage import DenominatorKind, save_snapshot


BRANDING = {
    "acme": {
        "display_name": "ACME Industries Security",
        "primary_color": "#26d4ee",
        "logo_url": "https://placehold.co/240x60/26d4ee/0b1020?text=ACME+Sec",
        "footer_note": "ACME confidential · Tier 1 SOC",
    },
    "globex": {
        "display_name": "Globex Energy SOC",
        "primary_color": "#9b6dff",
        "logo_url": "https://placehold.co/240x60/9b6dff/0b1020?text=Globex",
        "footer_note": "Globex internal · NERC-CIP scope",
    },
}

CONNECTORS = {
    "acme": [
        {
            "kind": "splunk",
            "label": "ACME prod Splunk Cloud",
            "description": "Primary SIEM, all corp + DMZ feeds",
            "config": {
                "host": "acme.splunkcloud.com",
                "port": "8088",
                "index": "main",
                "hec_token": "dummy-acme-splunk-hec-99887766aabbccddeeff",
            },
        },
        {
            "kind": "sentinel",
            "label": "ACME Azure Sentinel",
            "description": "M365 + Azure tenant telemetry",
            "config": {
                "workspace_id": "11111111-2222-3333-4444-555555555555",
                "tenant_id":    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "client_id":    "99999999-8888-7777-6666-555555555555",
                "workspace_key":  "dummy-acme-sentinel-ws-key-PLAINTEXT-DO-NOT-USE",
                "client_secret":  "dummy-acme-sentinel-client-secret-1234",
            },
        },
    ],
    "globex": [
        {
            "kind": "elastic",
            "label": "Globex Elastic Cloud",
            "description": "Primary SIEM (Elastic Security 8.x)",
            "config": {
                "host": "https://globex.es.us-east-1.aws.elastic-cloud.com:9243",
                "username": "detectmap-svc",
                "api_key": "dummy-globex-elastic-api-key-zzz1234yyy5678",
            },
        },
        {
            "kind": "splunk",
            "label": "Globex OT Splunk",
            "description": "Read-only into the OT/ICS Splunk cluster",
            "config": {
                "host": "ot-splunk.globex.internal",
                "port": "8089",
                "index": "ot_main",
                "hec_token": "dummy-globex-ot-splunk-hec-xx5544",
            },
        },
    ],
}

CONNECTOR_SECRET_FIELDS = {
    "splunk":   ("hec_token", "password"),
    "sentinel": ("workspace_key", "client_secret"),
    "elastic":  ("api_key", "password"),
}


def _custom_yaml(sigma_id: str, title: str, technique: str) -> str:
    return f"""title: {title}
id: {sigma_id}
status: experimental
description: |
  Internal detection authored by the customer SOC.
author: detectmap demo seed
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
falsepositives:
  - Legitimate scripted automation
level: high
tags:
  - attack.{technique.lower().replace('.', '_')}
"""


# Hand-crafted custom detections (written from scratch by the SOC).
CUSTOM_DETECTIONS = {
    "acme": [
        {
            "sigma_id": "acme-custom-001",
            "title": "ACME — PowerShell EncodedCommand from non-IT host",
            "techniques": ["T1059.001", "T1027"],
            "level": SigmaLevel.HIGH,
            "status": DetectionStatus.DEPLOYED,
            "depth": 4,
        },
        {
            "sigma_id": "acme-custom-002",
            "title": "ACME — Service binary path manipulation in HR OU",
            "techniques": ["T1543.003"],
            "level": SigmaLevel.MEDIUM,
            "status": DetectionStatus.TUNING,
            "depth": 2,
        },
    ],
    "globex": [
        {
            "sigma_id": "globex-custom-001",
            "title": "Globex OT — Modbus FC=43 anomaly on PLC ring",
            "techniques": ["T0855"],
            "level": SigmaLevel.HIGH,
            "status": DetectionStatus.DEPLOYED,
            "depth": 3,
        },
        {
            "sigma_id": "globex-custom-002",
            "title": "Globex — RDP from non-jumpbox IP into substation VLAN",
            "techniques": ["T1021.001"],
            "level": SigmaLevel.CRITICAL,
            "status": DetectionStatus.IN_DEVELOPMENT,
            "depth": 2,
        },
    ],
}


# Pick a real upstream global detection to fork into a customized variant
# (the chosen sigma_id pattern must exist after a SigmaHQ sync).
CUSTOMIZED_FORKS = {
    "acme": [
        {
            "match_title_ilike": "%credential%",
            "new_title_suffix": " (ACME-tuned)",
            "depth": 4,
            "status": DetectionStatus.DEPLOYED,
        },
    ],
    "globex": [
        {
            "match_title_ilike": "%rdp%",
            "new_title_suffix": " (Globex-tuned for OT VLANs)",
            "depth": 3,
            "status": DetectionStatus.DEPLOYED,
        },
    ],
}


# A pinch of `gap` / `not_applicable` status variety per tenant.
STATUS_VARIETY = {
    "acme":   {"gap": 12, "not_applicable": 8},
    "globex": {"gap": 20, "not_applicable": 5},
}


# User-source GRC mappings (added on top of seeded ones).
USER_GRC_MAPPINGS = [
    {
        "framework_key": "nist_csf",
        "control_id":   "PR.AC-1",
        "target_id":    "T1078",
        "rationale":    "Account-takeover detections close PR.AC-1 evidentially.",
    },
    {
        "framework_key": "iso_27001",
        "control_id":   "A.8.16",
        "target_id":    "T1059.001",
        "rationale":    "Logging suspicious PowerShell satisfies A.8.16 monitoring.",
    },
    {
        "framework_key": "nca_ecc",
        "control_id":   "2-3-2",
        "target_id":    "T1190",
        "rationale":    "Edge-exposed-asset detections demonstrate 2-3-2 hardening.",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _customer_ids() -> dict[str, uuid.UUID]:
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(Customer.codename, Customer.id).where(
                    Customer.codename.in_(list(BRANDING.keys()))
                )
            )
        ).all()
    if not rows:
        raise SystemExit("No demo customers found — run seed_demo first.")
    return {codename: cid for codename, cid in rows}


async def _set_branding() -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for codename, branding in BRANDING.items():
                await session.execute(
                    text(
                        "UPDATE public.customers SET branding = :b "
                        "WHERE codename = :c"
                    ),
                    {"b": __import__("json").dumps(branding), "c": codename},
                )
    print(f"branding: applied to {', '.join(BRANDING.keys())}")


def _encrypt_secrets(kind: str, config: dict) -> tuple[dict, dict]:
    secret_keys = set(CONNECTOR_SECRET_FIELDS.get(kind, ()))
    plain: dict = {}
    enc: dict = {}
    for k, v in config.items():
        if k in secret_keys:
            enc[k] = encrypt(str(v))
        else:
            plain[k] = v
    return plain, enc


async def _seed_connectors(codename: str) -> None:
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            for spec in CONNECTORS[codename]:
                existing = (
                    await session.execute(
                        select(Connector).where(
                            Connector.kind == spec["kind"],
                            Connector.label == spec["label"],
                        )
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    continue
                plain, enc = _encrypt_secrets(spec["kind"], spec["config"])
                session.add(
                    Connector(
                        id=uuid.uuid4(),
                        kind=spec["kind"],
                        label=spec["label"],
                        description=spec.get("description"),
                        config=plain,
                        encrypted_config=enc,
                        status="planned",
                    )
                )
        print(f"  {codename}: connectors ensured ({len(CONNECTORS[codename])})")
    finally:
        set_tenant(None)


async def _seed_custom_detections(codename: str) -> None:
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            for spec in CUSTOM_DETECTIONS[codename]:
                existing = (
                    await session.execute(
                        select(Detection).where(Detection.sigma_id == spec["sigma_id"])
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    continue
                det_id = uuid.uuid4()
                primary_tech = spec["techniques"][0]
                session.add(
                    Detection(
                        id=det_id,
                        sigma_id=spec["sigma_id"],
                        title=spec["title"],
                        description=f"Customer-authored detection covering {spec['techniques']}",
                        sigma_status="experimental",
                        level=spec["level"],
                        author="detectmap demo seed",
                        sigma_references=[],
                        tags=[f"attack.{t.lower().replace('.', '_')}" for t in spec["techniques"]],
                        logsource={"category": "process_creation", "product": "windows"},
                        detection={"selection": {"_": "_"}, "condition": "selection"},
                        falsepositives=["Legitimate automation"],
                        raw_yaml=_custom_yaml(spec["sigma_id"], spec["title"], primary_tech),
                        detection_status=spec["status"],
                        source=DetectionSource.CUSTOM,
                        score_breadth=2,
                        score_depth=spec["depth"],
                        review_status=(
                            DetectionReviewStatus.APPROVED.value
                            if spec["status"] == DetectionStatus.DEPLOYED
                            else DetectionReviewStatus.DRAFT.value
                        ),
                        reviewed_at=(
                            datetime.now(timezone.utc)
                            if spec["status"] == DetectionStatus.DEPLOYED
                            else None
                        ),
                    )
                )
                for t in spec["techniques"]:
                    session.add(
                        DetectionTechnique(
                            id=uuid.uuid4(),
                            detection_id=det_id,
                            technique_id=t,
                            domain="ics" if t.startswith("T0") else "enterprise",
                        )
                    )
        print(
            f"  {codename}: custom detections ensured "
            f"({len(CUSTOM_DETECTIONS[codename])})"
        )
    finally:
        set_tenant(None)


async def _seed_customized_forks(codename: str) -> None:
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            for fork in CUSTOMIZED_FORKS[codename]:
                # Skip if we've already created the fork (look for the suffix
                # in any existing customized row).
                suffix = fork["new_title_suffix"]
                already = (
                    await session.execute(
                        select(Detection).where(
                            Detection.source == DetectionSource.CUSTOMIZED,
                            Detection.title.ilike(f"%{suffix}%"),
                        )
                    )
                ).scalar_one_or_none()
                if already is not None:
                    continue

                upstream = (
                    await session.execute(
                        select(Detection)
                        .where(
                            Detection.source == DetectionSource.GLOBAL,
                            Detection.title.ilike(fork["match_title_ilike"]),
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if upstream is None:
                    print(
                        f"  {codename}: no upstream match for {fork['match_title_ilike']!r}; skipping fork"
                    )
                    continue

                clone_id = uuid.uuid4()
                session.add(
                    Detection(
                        id=clone_id,
                        sigma_id=f"{upstream.sigma_id}.customized",
                        title=f"{upstream.title}{suffix}",
                        description=upstream.description,
                        sigma_status=upstream.sigma_status,
                        level=upstream.level,
                        author="detectmap demo seed (forked)",
                        sigma_references=list(upstream.sigma_references or []),
                        tags=list(upstream.tags or []),
                        logsource=dict(upstream.logsource or {}),
                        detection=dict(upstream.detection or {}),
                        falsepositives=list(upstream.falsepositives or []),
                        raw_yaml=upstream.raw_yaml,
                        detection_status=fork["status"],
                        source=DetectionSource.CUSTOMIZED,
                        score_breadth=upstream.score_breadth,
                        score_depth=fork["depth"],
                        upstream_global_id=upstream.sigma_id,
                        review_status=(
                            DetectionReviewStatus.APPROVED.value
                            if fork["status"] == DetectionStatus.DEPLOYED
                            else DetectionReviewStatus.DRAFT.value
                        ),
                        reviewed_at=(
                            datetime.now(timezone.utc)
                            if fork["status"] == DetectionStatus.DEPLOYED
                            else None
                        ),
                    )
                )
                # Copy upstream's technique mappings onto the fork.
                techs = (
                    await session.execute(
                        select(DetectionTechnique).where(
                            DetectionTechnique.detection_id == upstream.id
                        )
                    )
                ).scalars().all()
                for t in techs:
                    session.add(
                        DetectionTechnique(
                            id=uuid.uuid4(),
                            detection_id=clone_id,
                            technique_id=t.technique_id,
                            domain=t.domain,
                        )
                    )
                print(
                    f"  {codename}: customized fork of '{upstream.title}' "
                    f"({len(techs)} techniques)"
                )
    finally:
        set_tenant(None)


async def _add_status_variety(codename: str) -> None:
    """Promote a sample of `idea` rows to `gap` and `not_applicable`.

    Idempotent in the sense that re-running tops up to the configured counts
    (it'll only flip more rows if the current `gap`/`not_applicable` counts
    are below the target).
    """
    targets = STATUS_VARIETY[codename]
    set_tenant(codename)
    try:
        async with tenant_session() as session:
            for status, target in targets.items():
                current = (
                    await session.execute(
                        select(text("count(*)")).where(text(
                            f"detection_status = '{status}'"
                        )).select_from(Detection)
                    )
                ).scalar() or 0
                need = max(0, target - current)
                if need == 0:
                    continue
                # Promote `need` random `idea` rows to the target status.
                await session.execute(
                    text(
                        "UPDATE detections SET detection_status = :s "
                        "WHERE id IN ("
                        "  SELECT id FROM detections "
                        "  WHERE detection_status = 'idea' AND source = 'global' "
                        "  ORDER BY random() LIMIT :n"
                        ")"
                    ),
                    {"s": status, "n": need},
                )
        print(f"  {codename}: status variety topped up to {targets}")
    finally:
        set_tenant(None)


async def _seed_user_grc_mappings(actor_email: str) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for m in USER_GRC_MAPPINGS:
                fw = (
                    await session.execute(
                        select(GRCFramework).where(GRCFramework.key == m["framework_key"])
                    )
                ).scalar_one_or_none()
                if fw is None:
                    continue
                ctrl = (
                    await session.execute(
                        select(GRCControl).where(
                            GRCControl.framework_id == fw.id,
                            GRCControl.control_id == m["control_id"],
                        )
                    )
                ).scalar_one_or_none()
                if ctrl is None:
                    continue
                exists = (
                    await session.execute(
                        select(GRCTechniqueMapping).where(
                            GRCTechniqueMapping.control_id == ctrl.id,
                            GRCTechniqueMapping.technique_id == m["target_id"],
                            GRCTechniqueMapping.source == "user",
                        )
                    )
                ).scalar_one_or_none()
                if exists is not None:
                    continue
                session.add(
                    GRCTechniqueMapping(
                        id=uuid.uuid4(),
                        control_id=ctrl.id,
                        domain="enterprise",
                        technique_id=m["target_id"],
                        source="user",
                        rationale=m["rationale"],
                        author=actor_email,
                    )
                )
    print(f"user GRC mappings ensured ({len(USER_GRC_MAPPINGS)} candidates)")


async def _seed_sector_snapshot(codename: str, sector_ref: str) -> None:
    set_tenant(codename)
    try:
        snap = await save_snapshot(
            "enterprise",
            DenominatorKind.SECTOR,
            sector_ref,
            notes="dummy seed: sector denominator",
        )
        print(
            f"  {codename}: sector snapshot ({sector_ref}) "
            f"posture={snap.posture_grade} breadth={snap.breadth_score}"
        )
    finally:
        set_tenant(None)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run() -> None:
    print("== resolving customers ==")
    cust = await _customer_ids()
    print(f"found: {', '.join(f'{k}={v}' for k, v in cust.items())}")

    print("\n== branding ==")
    await _set_branding()

    print("\n== connectors ==")
    for codename in cust:
        await _seed_connectors(codename)

    print("\n== custom detections ==")
    for codename in cust:
        await _seed_custom_detections(codename)

    print("\n== customized forks ==")
    for codename in cust:
        await _seed_customized_forks(codename)

    print("\n== status variety ==")
    for codename in cust:
        await _add_status_variety(codename)

    print("\n== user GRC mappings ==")
    await _seed_user_grc_mappings("admin@demo.local")

    print("\n== sector-denominator snapshots ==")
    sector_for = {"acme": "finance", "globex": "energy"}
    for codename, sector_ref in sector_for.items():
        try:
            await _seed_sector_snapshot(codename, sector_ref)
        except Exception as exc:  # snapshot is best-effort: never fail the seed
            print(f"  {codename}: sector snapshot failed: {exc}")

    print("\nseed complete.")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
