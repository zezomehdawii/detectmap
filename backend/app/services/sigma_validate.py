"""Validate Sigma rule YAML via pySigma + extract fields for DB storage."""
from __future__ import annotations

from typing import Any

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule


class SigmaValidationError(ValueError):
    """Raised when a Sigma rule YAML fails parsing or validation."""


def _coerce_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def parse_sigma_yaml(yaml_text: str) -> dict[str, Any]:
    """Validate a single Sigma rule YAML and return DB-shaped fields.

    Raises SigmaValidationError on:
      - malformed YAML
      - non-mapping root
      - missing required Sigma fields (id, title, logsource, detection)
      - pySigma rejection
    """
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise SigmaValidationError(f"invalid YAML: {e}") from e

    if not isinstance(raw, dict):
        raise SigmaValidationError("Sigma rule YAML root must be a mapping")

    for required in ("id", "title", "logsource", "detection"):
        if required not in raw or raw[required] in (None, ""):
            raise SigmaValidationError(f"missing required field: {required!r}")

    try:
        SigmaRule.from_dict(raw)
    except SigmaError as e:
        raise SigmaValidationError(f"pySigma rejected rule: {e}") from e

    return {
        "global_id": str(raw["id"]),
        "sigma_id": str(raw["id"]),
        "title": str(raw.get("title") or "")[:500],
        "description": raw.get("description"),
        "sigma_status": raw.get("status"),
        "level": raw.get("level"),
        "author": raw.get("author"),
        "sigma_references": _coerce_list(raw.get("references")),
        "tags": _coerce_list(raw.get("tags")),
        "logsource": raw.get("logsource") or {},
        "detection": raw.get("detection") or {},
        "falsepositives": _coerce_list(raw.get("falsepositives")),
        "raw_yaml": yaml_text,
    }


def techniques_from_tags(tags: list[str]) -> list[str]:
    """Extract ATT&CK technique IDs from Sigma `tags` (e.g. `attack.t1059.001`)."""
    out: list[str] = []
    for t in tags or []:
        if not isinstance(t, str):
            continue
        lower = t.lower()
        if not lower.startswith("attack.t"):
            continue
        tid = lower.removeprefix("attack.").upper()
        if not tid.startswith("T"):
            continue
        rest = tid[1:]
        if not rest or not rest[0].isdigit():
            continue
        out.append(tid)
    return out


__all__ = [
    "SigmaValidationError",
    "parse_sigma_yaml",
    "techniques_from_tags",
]
