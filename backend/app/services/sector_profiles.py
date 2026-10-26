"""Curated sector → ATT&CK technique mappings for the 'sector' denominator.

These are starter sets derived from public ATT&CK industry guidance (the
techniques most commonly leveraged against each sector, per MITRE's own
threat intel write-ups, Verizon DBIR, and CISA advisories). Each set is
deliberately concise — a sector profile is a tighter lens than the full
catalog, not a copy of it. An MSSP admin can edit `sector_profiles` rows
in-DB to tune the lens for their deployment.
"""
from __future__ import annotations

import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.base import AsyncSessionLocal
from app.models.public import SectorProfile

SECTOR_PROFILES: list[dict] = [
    {
        "sector": "finance",
        "label": "Financial services",
        "description": (
            "Banking, payments, fintech. Heavy on credential theft, web app "
            "abuse, supply chain, and pre-ransomware staging."
        ),
        "technique_ids": [
            "T1566", "T1566.001", "T1566.002", "T1566.003",
            "T1190", "T1133", "T1078", "T1078.003", "T1078.004",
            "T1110", "T1110.001", "T1110.003", "T1110.004",
            "T1059", "T1059.001", "T1059.003", "T1059.007",
            "T1204", "T1204.001", "T1204.002",
            "T1027", "T1055", "T1112",
            "T1003", "T1003.001", "T1003.003",
            "T1083", "T1087", "T1087.002",
            "T1486", "T1490", "T1565", "T1657",
            "T1071", "T1071.001", "T1573", "T1573.002",
            "T1041", "T1567", "T1567.002",
            "T1098", "T1136", "T1098.001",
        ],
    },
    {
        "sector": "healthcare",
        "label": "Healthcare & life sciences",
        "description": (
            "Hospitals, payers, pharma. Ransomware-heavy with PHI/EMR theft "
            "via phishing + exposed remote services + commodity malware."
        ),
        "technique_ids": [
            "T1566", "T1566.001", "T1566.002",
            "T1190", "T1133", "T1078", "T1133",
            "T1059", "T1059.001", "T1059.003",
            "T1204.002", "T1027",
            "T1003", "T1003.001", "T1110",
            "T1486", "T1490", "T1485", "T1489",
            "T1071", "T1071.001", "T1041",
            "T1567", "T1567.002",
            "T1083", "T1087", "T1018",
            "T1543", "T1543.003", "T1547", "T1547.001",
        ],
    },
    {
        "sector": "energy",
        "label": "Energy & utilities",
        "description": (
            "Power, oil & gas, water. IT-side initial access then pivots "
            "toward OT/ICS. Maps to ATT&CK Enterprise + (separately) ICS."
        ),
        "technique_ids": [
            "T1566", "T1566.001", "T1566.002",
            "T1190", "T1133", "T1078", "T1199",
            "T1059", "T1059.001", "T1059.003", "T1059.006",
            "T1027", "T1055",
            "T1003", "T1003.001",
            "T1018", "T1083", "T1087", "T1046",
            "T1021", "T1021.001", "T1021.002", "T1021.004",
            "T1071", "T1071.001", "T1573",
            "T1486", "T1485", "T1490",
            "T1543", "T1547", "T1098",
        ],
    },
    {
        "sector": "retail",
        "label": "Retail & e-commerce",
        "description": (
            "POS, e-commerce, supply chain. Web-skimmers, BEC, PoS malware, "
            "credential abuse."
        ),
        "technique_ids": [
            "T1566", "T1566.001", "T1566.002",
            "T1190", "T1078", "T1133", "T1199",
            "T1110", "T1110.003",
            "T1059", "T1059.001", "T1059.007",
            "T1027", "T1071", "T1071.001", "T1573",
            "T1003", "T1003.001",
            "T1056", "T1056.001",
            "T1486", "T1041", "T1567", "T1567.002",
            "T1098", "T1136",
        ],
    },
    {
        "sector": "government",
        "label": "Government & public sector",
        "description": (
            "Federal, state/local, and agency tier. Espionage-heavy: spearphish, "
            "supply-chain compromise, long-dwell persistence."
        ),
        "technique_ids": [
            "T1566", "T1566.001", "T1566.002", "T1566.003",
            "T1190", "T1133", "T1195", "T1199",
            "T1078", "T1078.002", "T1078.004",
            "T1059", "T1059.001", "T1059.003", "T1059.006",
            "T1204", "T1204.001", "T1204.002",
            "T1027", "T1055", "T1112",
            "T1003", "T1003.001", "T1003.003",
            "T1018", "T1083", "T1087", "T1046", "T1057",
            "T1021", "T1021.001", "T1021.002",
            "T1071", "T1071.001", "T1573", "T1573.002",
            "T1041", "T1567", "T1567.002",
            "T1098", "T1136", "T1543", "T1547",
        ],
    },
]


async def seed_sector_profiles(*, force: bool = False) -> dict:
    """Upsert the starter sector→techniques map.

    Idempotent: re-runs without `force` only fill rows that don't already exist.
    With `force=True` the curated set overwrites whatever's there.
    """
    inserted = 0
    updated = 0
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for profile in SECTOR_PROFILES:
                stmt = pg_insert(SectorProfile.__table__).values(
                    id=uuid.uuid4(),
                    sector=profile["sector"],
                    label=profile["label"],
                    description=profile["description"],
                    technique_ids=profile["technique_ids"],
                )
                if force:
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["sector"],
                        set_={
                            "label": stmt.excluded.label,
                            "description": stmt.excluded.description,
                            "technique_ids": stmt.excluded.technique_ids,
                        },
                    )
                else:
                    stmt = stmt.on_conflict_do_nothing(index_elements=["sector"])
                result = await session.execute(stmt)
                if result.rowcount and result.rowcount > 0:
                    if force:
                        updated += 1
                    else:
                        inserted += 1
    return {"inserted": inserted, "updated": updated, "total": len(SECTOR_PROFILES)}


__all__ = ["SECTOR_PROFILES", "seed_sector_profiles"]
