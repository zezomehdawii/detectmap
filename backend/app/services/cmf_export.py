"""Explicit, secret-free CMF submission serialization."""
from __future__ import annotations

import csv
import io
from datetime import date, datetime, timezone
from typing import Any, Iterable
from uuid import UUID


ASSET_FIELDS = (
    "id", "name", "kind", "hostname", "ip_address", "os", "environment",
    "location", "owner", "business_function", "cmf_category", "criticality",
    "status", "tags", "notes", "external_id",
)
SOURCE_FIELDS = (
    "id", "asset_id", "name", "attack_data_source", "attack_data_component",
    "log_source", "description", "kill_chain_phase", "follow_on_collection",
    "storage_connector_id", "storage_location", "retention_days",
    "device_completeness_q", "data_field_completeness_q", "timeliness_q",
    "consistency_q", "retention_q", "enabled", "notes",
)
REQUIREMENT_FIELDS = (
    "id", "title", "description", "driver", "priority", "status",
    "attack_technique_ids", "apt_group_id", "created_at", "updated_at",
)
PLAN_FIELDS = (
    "id", "data_source", "title", "rationale", "requirement_id",
    "target_asset_id", "asset_data_source_id", "priority", "status",
    "assigned_to", "due_date", "technique_count", "source_kind", "notes",
    "created_at", "updated_at",
)


def _value(value: Any) -> Any:
    if isinstance(value, (UUID, date, datetime)):
        return value.isoformat() if hasattr(value, "isoformat") else str(value)
    return value


def _record(row: Any, fields: tuple[str, ...]) -> dict:
    # Never serialize ORM __dict__ or connector configuration. Unknown new
    # fields require an explicit decision before appearing in submissions.
    return {name: _value(getattr(row, name, None)) for name in fields}


def submission_snapshot(
    customer: str,
    assets: Iterable[Any],
    sources: Iterable[Any],
    requirements: Iterable[Any],
    plan: Iterable[Any],
) -> dict:
    return {
        "format": "detectmap-cmf-submission",
        "schema_version": 1,
        "customer": customer,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "assets": [_record(row, ASSET_FIELDS) for row in assets],
        "data_sources": [_record(row, SOURCE_FIELDS) for row in sources],
        "requirements": [_record(row, REQUIREMENT_FIELDS) for row in requirements],
        "plan": [_record(row, PLAN_FIELDS) for row in plan],
    }


def _csv_safe(value: Any) -> Any:
    # Student labels/notes can begin with spreadsheet formula characters.
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return "" if value is None else value


def register_csv(snapshot: dict) -> str:
    by_id = {row["id"]: row for row in snapshot["assets"]}
    columns = (
        "asset_id", "source_id", "site", "asset_name", "asset_type", "source_name", "attack_data_source",
        "attack_data_component", "log_source", "kill_chain_phase",
        "follow_on_collection", "storage_location", "retention_days", "enabled",
        "device_completeness_q", "data_field_completeness_q", "timeliness_q",
        "consistency_q", "retention_q", "description", "notes",
    )
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=columns)
    writer.writeheader()
    sources = list(snapshot["data_sources"])
    has_sources = {row["asset_id"] for row in sources}
    sources.extend({"asset_id": asset_id} for asset_id in by_id if asset_id not in has_sources)
    for source in sources:
        asset = by_id.get(source["asset_id"], {})
        row = {name: source.get(name) for name in columns}
        row.update(
            source_id=source.get("id"), site=asset.get("location"), asset_name=asset.get("name"),
            asset_type=asset.get("kind"), source_name=source.get("name"),
        )
        writer.writerow({name: _csv_safe(value) for name, value in row.items()})
    return out.getvalue()
