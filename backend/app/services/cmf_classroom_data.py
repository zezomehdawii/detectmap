"""Deterministic, synthetic ICS starter records; no database side effects."""
from __future__ import annotations

import re
import uuid

MARKER = "cmf-classroom-v1"
AUTHOR = "cmf-classroom@training.invalid"
NAMESPACE = uuid.UUID("9d877858-197c-4d34-998e-124f8a9d6a26")


def record_id(customer: str, kind: str, key: str) -> uuid.UUID:
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", customer):
        raise ValueError("invalid customer codename")
    return uuid.uuid5(NAMESPACE, f"{customer}:{MARKER}:{kind}:{key}")


def starter_records(customer: str) -> dict[str, list[dict]]:
    """Retention mirrors the theory example; notes make the deliberate gaps explicit.

    Names/mappings are teaching data, not measured telemetry or historical
    incident evidence. Quality remains unscored until a student tests it.
    """
    assets = []
    specs = (
        ("hmi", "Windows HMI", "workstation", "Control Center", "endpoint"),
        ("monitor", "Network Monitoring Appliance", "network_device", "Data Center", "network"),
        ("rtu", "RTU", "iot_ot", "Transmission Substation", "ot"),
    )
    for key, name, kind, location, category in specs:
        assets.append({
            "id": record_id(customer, "asset", key), "name": name,
            "kind": kind, "location": location, "cmf_category": category,
            "environment": "production", "criticality": "high", "status": "active",
            "tags": [MARKER, "synthetic-training"], "compliance_scope": [],
            "external_id": f"{MARKER}:{key}",
            "notes": "Synthetic CMF classroom asset. No live device or actual telemetry is connected.",
            "created_by_email": AUTHOR, "updated_by_email": AUTHOR,
        })
    source_specs = (
        ("hmi", "Windows Event Logs", "windows/security", "Process", "Process Creation", 60,
         "Enterprise SIEM / windows-security", "Exploration; Installation; Actions on Objectives", "Registry Keys"),
        ("monitor", "Alerts", "network/alerts", "Network Traffic", "Network Traffic Content", 30,
         "Enterprise SIEM / ics-alerts", "Internal Reconnaissance; Command and Control; Delivery; Actions on Objectives", "Packet Capture"),
        ("rtu", "Syslog", "ot/syslog", "Application Log", "Application Log Content", 7,
         "Local / RTU ring buffer", "Installation; Actions on Objectives", "Controller Logic"),
    )
    sources = []
    for key, name, log_source, source, component, days, storage, phase, follow in source_specs:
        sources.append({
            "id": record_id(customer, "source", key),
            "asset_id": record_id(customer, "asset", key),
            "name": name, "log_source": log_source,
            "attack_data_source": source, "attack_data_component": component,
            "retention_days": days, "storage_location": storage,
            "kill_chain_phase": phase, "follow_on_collection": follow,
            "enabled": True, "created_by_email": AUTHOR, "updated_by_email": AUTHOR,
            "notes": "Starter inventory assertion only. Validate availability, fields, timeliness, and retention before scoring quality.",
        })
    req_id = record_id(customer, "requirement", "controller-change")
    requirements = [{
        "id": req_id,
        "title": "Investigate unauthorized controller changes",
        "description": "A synthetic tabletop requires 30 days of RTU Syslog and controller-logic evidence. The inventory declares only 7 days of local Syslog and no controller-logic collection. Determine what can be answered and plan the missing collection.",
        "driver": "ttx", "priority": "high", "status": "active",
        "attack_technique_ids": [], "author_email": AUTHOR,
    }]
    plan = [{
        "id": record_id(customer, "plan", "rtu-retention"),
        "data_source": "Application Log: Application Log Content",
        "title": "Extend RTU Syslog retention",
        "rationale": "Requirement needs 30 days; current local inventory states 7. Plan a safe forwarding/storage change and test actual retention.",
        "requirement_id": req_id,
        "target_asset_id": record_id(customer, "asset", "rtu"),
        "asset_data_source_id": record_id(customer, "source", "rtu"),
        "priority": "high", "status": "proposed", "source_kind": "classroom",
        "notes": "Not yet implemented or tested.", "author_email": AUTHOR,
    }, {
        "id": record_id(customer, "plan", "controller-logic"),
        "data_source": "Controller Logic",
        "title": "Arrange controller-logic follow-on collection",
        "rationale": "Syslog alone does not establish which logic changed. Define an approved evidence collection procedure and test on supplied sample evidence.",
        "requirement_id": req_id,
        "target_asset_id": record_id(customer, "asset", "rtu"),
        "priority": "high", "status": "proposed", "source_kind": "classroom",
        "notes": "Use supplied training evidence; do not query a production controller.",
        "author_email": AUTHOR,
    }]
    return {"assets": assets, "data_sources": sources, "requirements": requirements, "plan": plan}


def owns_record(kind: str, row: object, spec: dict) -> bool:
    """Refuse collisions even when a UUID matches our deterministic IDs."""
    if getattr(row, "id", None) != spec["id"]:
        return False
    if kind == "assets":
        return getattr(row, "external_id", None) == spec["external_id"] and MARKER in (getattr(row, "tags", None) or [])
    if kind == "data_sources":
        return getattr(row, "asset_id", None) == spec["asset_id"] and getattr(row, "created_by_email", None) == AUTHOR
    return getattr(row, "author_email", None) == AUTHOR and (
        kind != "plan" or getattr(row, "source_kind", None) == "classroom"
    )
