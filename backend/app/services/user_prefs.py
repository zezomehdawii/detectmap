"""Per-user UI preference allow-list, defaults, and merge.

Same shape as `customer_features`: a frozen catalog of keys with
defaults and a `normalise(overrides)` that merges defaults + stored
values and drops unknown keys. The endpoints under `/me/preferences`
read/write through here so the UI and validation stay in lockstep.

Add a new preference: extend `CATALOG`. No migration needed — the
column is JSONB.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PrefMeta:
    key: str
    label: str
    description: str
    # Either a literal default value (any JSON scalar) or for enums:
    # the first value in `choices` is the default.
    default: Any
    # When set, the value must be one of these — string enum semantics.
    # Use [] for free-form scalars validated only by type.
    choices: tuple[str, ...] = ()
    # Python type the value must coerce to. Supports bool, str, int.
    value_type: type = str


CATALOG: tuple[PrefMeta, ...] = (
    PrefMeta(
        key="color_mode",
        label="Color mode",
        description="Light or dark theme for the dashboard.",
        default="dark",
        choices=("dark", "light"),
        value_type=str,
    ),
    PrefMeta(
        key="density",
        label="Table density",
        description="Compact tables show more rows; comfortable is roomier.",
        default="comfortable",
        choices=("comfortable", "compact"),
        value_type=str,
    ),
    PrefMeta(
        key="sidebar_collapsed",
        label="Collapse the sidebar by default",
        description="Hides the sidebar labels and keeps only the icons.",
        default=False,
        value_type=bool,
    ),
    PrefMeta(
        key="default_coverage_domain",
        label="Default ATT&CK domain",
        description="Which ATT&CK domain to open the coverage matrix on.",
        default="enterprise",
        choices=("enterprise", "ics", "mobile"),
        value_type=str,
    ),
)

_BY_KEY: dict[str, PrefMeta] = {p.key: p for p in CATALOG}


def catalog() -> list[dict]:
    """Front-end-friendly payload describing every preference."""
    return [
        {
            "key": p.key,
            "label": p.label,
            "description": p.description,
            "default": p.default,
            "choices": list(p.choices),
            "value_type": p.value_type.__name__,
        }
        for p in CATALOG
    ]


def defaults() -> dict[str, Any]:
    return {p.key: p.default for p in CATALOG}


def normalise(overrides: dict | None) -> dict[str, Any]:
    """Effective state: defaults merged with stored overrides.

    Unknown keys are silently dropped (the catalog may shrink between
    releases). Values that fail validation fall back to the default —
    this is the read path, not the write path; a corrupt value should
    not break the UI.
    """
    out: dict[str, Any] = defaults()
    if not overrides:
        return out
    for k, v in overrides.items():
        meta = _BY_KEY.get(k)
        if meta is None:
            continue
        try:
            coerced = _coerce(meta, v)
        except ValueError:
            continue
        out[k] = coerced
    return out


def validate_patch(patch: dict) -> dict[str, Any]:
    """Strict validation of a write. Raises ValueError on unknown keys,
    bad types, or out-of-range enum values. Returns the cleaned dict."""
    if not isinstance(patch, dict):
        raise ValueError("preferences must be a JSON object")
    cleaned: dict[str, Any] = {}
    for k, v in patch.items():
        meta = _BY_KEY.get(k)
        if meta is None:
            raise ValueError(f"unknown preference key: {k}")
        cleaned[k] = _coerce(meta, v)
    return cleaned


def _coerce(meta: PrefMeta, v: Any) -> Any:
    if meta.value_type is bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower() == "true"
        raise ValueError(f"{meta.key} must be a boolean")
    if meta.value_type is int:
        try:
            return int(v)
        except (TypeError, ValueError) as e:
            raise ValueError(f"{meta.key} must be an integer") from e
    # String / enum
    if not isinstance(v, str):
        raise ValueError(f"{meta.key} must be a string")
    if meta.choices and v not in meta.choices:
        raise ValueError(
            f"{meta.key} must be one of {sorted(meta.choices)}"
        )
    return v


__all__ = ["CATALOG", "PrefMeta", "catalog", "defaults", "normalise", "validate_patch"]
