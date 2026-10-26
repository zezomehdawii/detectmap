"""GRC framework + ATT&CK mapping seeder.

Three frameworks seeded with starter control sets and curated technique
mappings. Source for the mappings:
  - NIST CSF 2.0 (functions/categories/subcategories) — public draft.
  - ISO/IEC 27001:2022 Annex A — public abstract; abbreviated control names.
  - NCA ECC (KSA Essential Cybersecurity Controls) — public document.

The mapping picks are the same ones a security analyst would write on a
whiteboard: which controls obviously cover which TTPs. They are starting
points — analysts edit them in the UI and those edits land with
`source='user'` so re-running the seeder never overwrites them.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.base import AsyncSessionLocal
from app.models.public import (
    GRCControl,
    GRCFramework,
    GRCMitigationMapping,
    GRCTechniqueMapping,
)
from app.services.grc_seed_nca import (
    NCA_CONTROLS_BY_FW,
    NCA_FRAMEWORKS,
    NCA_MITIGATION_MAPPINGS,
    NCA_TECHNIQUE_MAPPINGS,
)

log = logging.getLogger(__name__)


# -- Frameworks ------------------------------------------------------------

FRAMEWORKS: list[dict] = [
    {
        "key": "nist_csf",
        "label": "NIST Cybersecurity Framework",
        "version": "2.0",
        "description": (
            "NIST CSF 2.0 — risk-based framework organised around six functions: "
            "Govern, Identify, Protect, Detect, Respond, Recover."
        ),
    },
    {
        "key": "iso_27001",
        "label": "ISO/IEC 27001",
        "version": "2022",
        "description": (
            "ISO/IEC 27001:2022 Annex A controls. Organisational, people, "
            "physical, and technological controls for an ISMS."
        ),
    },
    # NCA framework family (ECC-2:2024, CSCC, CCC CSP+CST, OTCC) is defined in
    # grc_seed_nca and appended below — keeps the heavy KSA catalog isolated.
    *NCA_FRAMEWORKS,
]


# -- Controls --------------------------------------------------------------
# Format: (control_id, parent or None, family, name, description, sort_order)

NIST_CSF: list[tuple] = [
    # Govern
    ("GV", None, "Govern", "Govern (function)", "Strategy, policy, oversight.", 1),
    ("GV.RM", "GV", "Govern", "Risk management strategy", "Establish, communicate, monitor risk strategy.", 2),
    ("GV.SC", "GV", "Govern", "Cybersecurity supply chain risk management", "Identify and manage supply-chain risk.", 3),
    # Identify
    ("ID", None, "Identify", "Identify (function)", "Understand assets, risks, business context.", 10),
    ("ID.AM", "ID", "Identify", "Asset management", "Identify and manage assets consistent with risk.", 11),
    ("ID.RA", "ID", "Identify", "Risk assessment", "Understand cybersecurity risk to operations.", 12),
    # Protect
    ("PR", None, "Protect", "Protect (function)", "Safeguard delivery of critical services.", 20),
    ("PR.AA", "PR", "Protect", "Identity, authentication, access management", "Limit access to authorized users, processes, devices.", 21),
    ("PR.AT", "PR", "Protect", "Awareness and training", "Train people to do their cybersecurity duties.", 22),
    ("PR.DS", "PR", "Protect", "Data security", "Protect data confidentiality, integrity, availability.", 23),
    ("PR.PS", "PR", "Protect", "Platform security", "Harden hardware/software/firmware/services.", 24),
    ("PR.PS-04", "PR.PS", "Protect", "Log records are generated and made available for monitoring", "Endpoint and application logging.", 25),
    ("PR.PS-05", "PR.PS", "Protect", "Installation and execution of unauthorized software is prevented", "Allow-listing, EDR.", 26),
    ("PR.IR", "PR", "Protect", "Technology infrastructure resilience", "Capacity, segmentation, hardening.", 27),
    # Detect
    ("DE", None, "Detect", "Detect (function)", "Identify cybersecurity events.", 30),
    ("DE.CM", "DE", "Detect", "Continuous monitoring", "Networks/users/devices/services monitored for anomalies.", 31),
    ("DE.AE", "DE", "Detect", "Adverse event analysis", "Anomalies and events are triaged.", 32),
    # Respond
    ("RS", None, "Respond", "Respond (function)", "Take action on detected incidents.", 40),
    ("RS.MA", "RS", "Respond", "Incident management", "Detect, triage, respond, recover.", 41),
    ("RS.AN", "RS", "Respond", "Incident analysis", "Analyse to ensure effective response and support recovery.", 42),
    ("RS.MI", "RS", "Respond", "Incident mitigation", "Contain and eradicate.", 43),
    # Recover
    ("RC", None, "Recover", "Recover (function)", "Restore capabilities or services impaired by an incident.", 50),
    ("RC.RP", "RC", "Recover", "Incident recovery plan execution", "Backups, restoration playbooks.", 51),
    ("RC.CO", "RC", "Recover", "Incident recovery communications", "Coordinate stakeholders during recovery.", 52),
]

ISO_27001: list[tuple] = [
    # 5 Organisational controls
    ("A.5.1",  None, "Organisational",  "Policies for information security",                                       "Define, approve, publish, communicate ISMS policies.", 10),
    ("A.5.7",  None, "Organisational",  "Threat intelligence",                                                     "Collect and analyse information about threats.", 11),
    ("A.5.10", None, "Organisational",  "Acceptable use of information and other associated assets",               "Rules for acceptable use of assets.", 12),
    ("A.5.15", None, "Organisational",  "Access control",                                                          "Establish rules for access control based on business needs.", 13),
    ("A.5.23", None, "Organisational",  "Information security for use of cloud services",                          "Manage cloud security obligations.", 14),
    ("A.5.24", None, "Organisational",  "Information security incident management planning and preparation",        "Plan, prepare, and assign roles for incident response.", 15),
    ("A.5.30", None, "Organisational",  "ICT readiness for business continuity",                                   "ICT-side resilience to support BC.", 16),
    # 6 People controls
    ("A.6.3",  None, "People",          "Information security awareness, education and training",                  "Awareness, education, and training programmes.", 20),
    # 8 Technological controls
    ("A.8.5",  None, "Technological",   "Secure authentication",                                                   "Authentication mechanisms must be secure.", 30),
    ("A.8.7",  None, "Technological",   "Protection against malware",                                              "EDR/AV, secure configurations.", 31),
    ("A.8.9",  None, "Technological",   "Configuration management",                                                "Establish, document, monitor configurations.", 32),
    ("A.8.13", None, "Technological",   "Information backup",                                                      "Maintain backups consistent with the policy.", 33),
    ("A.8.15", None, "Technological",   "Logging",                                                                 "Logs of activities, exceptions, faults.", 34),
    ("A.8.16", None, "Technological",   "Monitoring activities",                                                   "Networks/systems/applications monitored for anomalous behaviour.", 35),
    ("A.8.20", None, "Technological",   "Networks security",                                                       "Protect networks from threats.", 36),
    ("A.8.23", None, "Technological",   "Web filtering",                                                           "Manage access to external websites.", 37),
    ("A.8.24", None, "Technological",   "Use of cryptography",                                                     "Effective use of cryptography.", 38),
    ("A.8.25", None, "Technological",   "Secure development life cycle",                                           "Establish secure SDLC.", 39),
    ("A.8.28", None, "Technological",   "Secure coding",                                                           "Secure coding principles applied to software development.", 40),
]

# NCA framework catalogs (ECC-2:2024, CSCC, CCC CSP+CST, OTCC) live in
# grc_seed_nca and are wired into CONTROLS_BY_FW below. Replacing the old
# inline 1:2018 sketch keeps the seed source of truth in one place.


# -- Technique mappings: (framework_key, control_id, technique_id, rationale) --

TECHNIQUE_MAPPINGS: list[tuple[str, str, str, str]] = [
    # NIST CSF 2.0 — Protect / Detect / Respond / Recover
    ("nist_csf", "PR.AA", "T1078", "Valid Accounts → MFA, least privilege"),
    ("nist_csf", "PR.AA", "T1078.004", "Cloud Accounts → conditional access"),
    ("nist_csf", "PR.AA", "T1098", "Account Manipulation → privileged account governance"),
    ("nist_csf", "PR.AA", "T1110", "Brute Force → MFA, account lockout"),
    ("nist_csf", "PR.AT", "T1566", "Phishing → user awareness training"),
    ("nist_csf", "PR.AT", "T1566.001", "Spearphishing Attachment → security awareness"),
    ("nist_csf", "PR.DS", "T1486", "Data Encrypted for Impact → data backups, integrity monitoring"),
    ("nist_csf", "PR.PS-04", "T1059", "Cmd & Scripting Interpreter → endpoint/process logging"),
    ("nist_csf", "PR.PS-04", "T1059.001", "PowerShell → script block / module logging"),
    ("nist_csf", "PR.PS-05", "T1204", "User Execution → app control / allow-listing"),
    ("nist_csf", "PR.PS-05", "T1027", "Obfuscated Files or Information → script content scanning"),
    ("nist_csf", "PR.IR", "T1190", "Exploit Public-Facing App → patching, WAF, segmentation"),
    ("nist_csf", "DE.CM", "T1071", "Application Layer Protocol → network anomaly detection"),
    ("nist_csf", "DE.CM", "T1573", "Encrypted Channel → TLS decryption + DPI where lawful"),
    ("nist_csf", "DE.CM", "T1041", "Exfil over C2 → egress monitoring"),
    ("nist_csf", "DE.AE", "T1003", "OS Credential Dumping → SIEM hunts for LSASS access"),
    ("nist_csf", "DE.AE", "T1218", "System Binary Proxy Execution → behavioural rules"),
    ("nist_csf", "RS.MI", "T1486", "Ransomware → containment + recovery"),
    ("nist_csf", "RS.MI", "T1490", "Inhibit System Recovery → kill VSS/backup tampering"),
    ("nist_csf", "RC.RP", "T1486", "Ransomware → restore from backups"),
    ("nist_csf", "ID.AM", "T1133", "External Remote Services → inventory of exposed services"),

    # ISO 27001:2022 Annex A
    ("iso_27001", "A.5.7",  "T1566",     "Threat intel feeds inform phishing defences"),
    ("iso_27001", "A.5.7",  "T1190",     "Threat intel on exploited public apps"),
    ("iso_27001", "A.5.15", "T1078",     "Access control covers valid-account abuse"),
    ("iso_27001", "A.5.24", "T1486",     "Ransomware → incident response readiness"),
    ("iso_27001", "A.6.3",  "T1566",     "Awareness training reduces phishing success"),
    ("iso_27001", "A.6.3",  "T1204",     "Awareness training reduces user-executed malware"),
    ("iso_27001", "A.8.5",  "T1110",     "Secure auth prevents brute force"),
    ("iso_27001", "A.8.5",  "T1110.003", "Secure auth prevents password spraying"),
    ("iso_27001", "A.8.7",  "T1059",     "Anti-malware controls execution interpreters"),
    ("iso_27001", "A.8.7",  "T1204",     "Anti-malware blocks user-launched malware"),
    ("iso_27001", "A.8.13", "T1486",     "Backups support ransomware recovery"),
    ("iso_27001", "A.8.15", "T1059",     "Logging captures script execution"),
    ("iso_27001", "A.8.16", "T1071",     "Monitoring catches anomalous C2"),
    ("iso_27001", "A.8.16", "T1003",     "Monitoring catches credential-dumping attempts"),
    ("iso_27001", "A.8.20", "T1071",     "Network security limits C2"),
    ("iso_27001", "A.8.23", "T1566.002", "Web filtering blocks phishing links"),
    ("iso_27001", "A.8.24", "T1573",     "Use of cryptography vs encrypted-channel abuse"),
    ("iso_27001", "A.8.28", "T1190",     "Secure coding mitigates exploitable public apps"),

    # NCA family (ECC-2:2024, CSCC, CCC CSP+CST, OTCC) — sourced from grc_seed_nca.
    *NCA_TECHNIQUE_MAPPINGS,
]

# Mitigation mappings — illustrative starter set against widely-applicable mitigations.
# (framework_key, control_id, mitigation_id, rationale)
MITIGATION_MAPPINGS: list[tuple[str, str, str, str]] = [
    ("nist_csf",  "PR.AA",    "M1032", "MFA"),
    ("nist_csf",  "PR.PS-05", "M1038", "Execution Prevention (app control)"),
    ("nist_csf",  "PR.AT",    "M1017", "User Training"),
    ("nist_csf",  "DE.CM",    "M1031", "Network Intrusion Prevention"),
    ("iso_27001", "A.8.5",    "M1032", "Multi-factor authentication"),
    ("iso_27001", "A.8.7",    "M1049", "Antivirus / Antimalware"),
    ("iso_27001", "A.8.13",   "M1053", "Data Backup"),
    *NCA_MITIGATION_MAPPINGS,
]


CONTROLS_BY_FW: dict[str, list[tuple]] = {
    "nist_csf": NIST_CSF,
    "iso_27001": ISO_27001,
    **NCA_CONTROLS_BY_FW,
}


async def _upsert_framework(session, spec: dict) -> uuid.UUID:
    existing = (
        await session.execute(
            select(GRCFramework).where(GRCFramework.key == spec["key"])
        )
    ).scalar_one_or_none()
    if existing is None:
        row = GRCFramework(
            id=uuid.uuid4(),
            key=spec["key"],
            label=spec["label"],
            version=spec["version"],
            description=spec["description"],
        )
        session.add(row)
        await session.flush()
        return row.id
    # Refresh metadata in case the seeder updates label/version/description.
    existing.label = spec["label"]
    existing.version = spec["version"]
    existing.description = spec["description"]
    return existing.id


async def _upsert_controls(session, framework_id: uuid.UUID, rows: list[tuple]) -> None:
    payload = [
        {
            "id": uuid.uuid4(),
            "framework_id": framework_id,
            "control_id": cid,
            "parent_control_id": parent,
            "family": family,
            "name": name,
            "description": desc,
            "sort_order": order,
        }
        for (cid, parent, family, name, desc, order) in rows
    ]
    if not payload:
        return
    stmt = pg_insert(GRCControl.__table__).values(payload)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_grc_framework_control",
        set_={
            "parent_control_id": stmt.excluded.parent_control_id,
            "family": stmt.excluded.family,
            "name": stmt.excluded.name,
            "description": stmt.excluded.description,
            "sort_order": stmt.excluded.sort_order,
        },
    )
    await session.execute(stmt)


async def _resolve_control_ids(session) -> dict[tuple[str, str], uuid.UUID]:
    """Map (framework_key, control_id) → control UUID for fast lookup."""
    rows = (
        await session.execute(
            select(GRCFramework.key, GRCControl.control_id, GRCControl.id)
            .join(GRCControl, GRCControl.framework_id == GRCFramework.id)
        )
    ).all()
    return {(r.key, r.control_id): r.id for r in rows}


async def _seed_technique_mappings(
    session, resolver: dict[tuple[str, str], uuid.UUID]
) -> int:
    inserted = 0
    for fw_key, ctrl, tid, rationale in TECHNIQUE_MAPPINGS:
        ctrl_uuid = resolver.get((fw_key, ctrl))
        if ctrl_uuid is None:
            log.warning("seed: control %s/%s not found, skipping", fw_key, ctrl)
            continue
        stmt = (
            pg_insert(GRCTechniqueMapping.__table__)
            .values(
                id=uuid.uuid4(),
                control_id=ctrl_uuid,
                domain="enterprise",
                technique_id=tid,
                source="seeded",
                rationale=rationale,
                author="seeder",
            )
            .on_conflict_do_update(
                constraint="uq_grc_control_technique",
                # Only refresh rationale on seeded rows — never overwrite user-owned mappings.
                set_={"rationale": rationale},
                where=GRCTechniqueMapping.__table__.c.source == "seeded",
            )
        )
        result = await session.execute(stmt)
        if result.rowcount and result.rowcount > 0:
            inserted += 1
    return inserted


async def _seed_mitigation_mappings(
    session, resolver: dict[tuple[str, str], uuid.UUID]
) -> int:
    inserted = 0
    for fw_key, ctrl, mid, rationale in MITIGATION_MAPPINGS:
        ctrl_uuid = resolver.get((fw_key, ctrl))
        if ctrl_uuid is None:
            continue
        stmt = (
            pg_insert(GRCMitigationMapping.__table__)
            .values(
                id=uuid.uuid4(),
                control_id=ctrl_uuid,
                domain="enterprise",
                mitigation_id=mid,
                source="seeded",
                rationale=rationale,
                author="seeder",
            )
            .on_conflict_do_update(
                constraint="uq_grc_control_mitigation",
                set_={"rationale": rationale},
                where=GRCMitigationMapping.__table__.c.source == "seeded",
            )
        )
        result = await session.execute(stmt)
        if result.rowcount and result.rowcount > 0:
            inserted += 1
    return inserted


async def _purge_seeded_mappings_for_framework(session, fw_id: uuid.UUID) -> None:
    """Drop all source='seeded' mappings for a framework before re-seeding.

    Without this, when a control's intent changes between framework versions
    (e.g. ECC `1-3` shifts from "Awareness" to "Policies and Procedures" in
    2:2024) the old seeded mapping lingers on the renamed control with a
    stale rationale. User-owned mappings (source='user') are never touched.
    """
    control_ids_subq = select(GRCControl.id).where(GRCControl.framework_id == fw_id)
    await session.execute(
        delete(GRCTechniqueMapping).where(
            and_(
                GRCTechniqueMapping.control_id.in_(control_ids_subq),
                GRCTechniqueMapping.source == "seeded",
            )
        )
    )
    await session.execute(
        delete(GRCMitigationMapping).where(
            and_(
                GRCMitigationMapping.control_id.in_(control_ids_subq),
                GRCMitigationMapping.source == "seeded",
            )
        )
    )


async def seed_grc(*, only: Optional[list[str]] = None) -> dict:
    """Idempotent: upserts frameworks + controls; refreshes 'seeded' mappings.

    `source='user'` mappings are NEVER touched by the seeder.
    """
    keys = set(only) if only else {f["key"] for f in FRAMEWORKS}
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for fw in FRAMEWORKS:
                if fw["key"] not in keys:
                    continue
                fw_id = await _upsert_framework(session, fw)
                await _upsert_controls(session, fw_id, CONTROLS_BY_FW[fw["key"]])
                # Wipe stale seeded mappings before the upsert loop re-creates
                # them — prevents old rationales lingering after a framework
                # version refresh (e.g. ECC-1:2018 → ECC-2:2024).
                await _purge_seeded_mappings_for_framework(session, fw_id)
            resolver = await _resolve_control_ids(session)
            techs = await _seed_technique_mappings(session, resolver)
            mits = await _seed_mitigation_mappings(session, resolver)
    return {
        "frameworks": len(keys),
        "technique_mappings_upserted": techs,
        "mitigation_mappings_upserted": mits,
    }


__all__ = [
    "FRAMEWORKS",
    "CONTROLS_BY_FW",
    "TECHNIQUE_MAPPINGS",
    "MITIGATION_MAPPINGS",
    "seed_grc",
]
