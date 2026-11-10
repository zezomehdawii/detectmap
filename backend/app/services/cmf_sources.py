"""Canonical CMF collection-source mapping and PATCH semantics."""
from __future__ import annotations


def normalize_source_fields(values: dict) -> dict:
    """Accept a combined picker label, but persist separate canonical fields.

    An explicit source change without a component clears the previous component.
    An omitted source is left alone so PATCH can update a component independently.
    """
    result = dict(values)
    if "attack_data_source" not in result:
        component = result.get("attack_data_component")
        if isinstance(component, str):
            result["attack_data_component"] = component.strip() or None
        return result
    source = result["attack_data_source"]
    if source is not None and not isinstance(source, str):
        return result  # Let the request schema report the type error.
    source = (source or "").strip() or None
    if source and ":" in source:
        source, component = source.split(":", 1)
        source = source.strip() or None
        result["attack_data_component"] = component.strip() or None
    elif "attack_data_component" not in result or source is None:
        result["attack_data_component"] = None
    result["attack_data_source"] = source
    component = result.get("attack_data_component")
    if isinstance(component, str):
        result["attack_data_component"] = component.strip() or None
    return result


def source_patch_changes(payload, current) -> dict:
    """Return explicit changes, preserving omitted fields and accepting nulls."""
    changes = normalize_source_fields(payload.model_dump(exclude_unset=True))
    for required in ("name", "enabled"):
        if required in changes and changes[required] is None:
            raise ValueError(f"{required} cannot be null")
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise ValueError("name cannot be blank")
    source = changes.get("attack_data_source", current.attack_data_source)
    component = changes.get("attack_data_component", current.attack_data_component)
    if component and not source:
        raise ValueError("attack_data_component requires attack_data_source")
    return changes


# Changes to these fields invalidate a previously completed implementation test.
# Narrative notes and theory annotations do not alter the collected telemetry.
MATERIAL_COLLECTION_FIELDS = frozenset({
    "name", "attack_data_source", "attack_data_component", "log_source",
    "storage_connector_id", "storage_location", "retention_days", "enabled",
    "device_completeness_q", "data_field_completeness_q", "timeliness_q",
    "consistency_q", "retention_q",
})


def material_source_changes(changes: dict, current) -> list[str]:
    return sorted(
        field for field, value in changes.items()
        if field in MATERIAL_COLLECTION_FIELDS and getattr(current, field) != value
    )
