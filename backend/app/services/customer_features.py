"""Per-customer feature toggles.

Single source of truth for the keys, labels, defaults, and validation of
the `customers.features` JSONB map. Endpoints under /customers/{cn}/features
read/write through here so the allow-list and the UI stay in lockstep.

Add a new toggle by extending `CATALOG` — no migration needed (the column
is JSONB). Enforcement points (services / routers that gate behaviour on
a toggle) should import `is_enabled()` rather than reading `features`
directly so the default fallback is consistent.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FeatureMeta:
    key: str
    label: str
    description: str
    default: bool
    category: str


# Conservative defaults: the destructive / risky features (AI authoring,
# bulk export, live connector tests) start ON so existing customers keep
# their current behaviour. Flip a default to False only if you also
# backfill the column for active rows.
CATALOG: tuple[FeatureMeta, ...] = (
    FeatureMeta(
        key="detection_editing",
        label="Detection editing",
        description="Allow analysts to create, edit, and customise Sigma "
        "detections for this customer. Turn off for view-only tenants.",
        default=True,
        category="Detections",
    ),
    FeatureMeta(
        key="ai_authoring",
        label="AI-assisted Sigma drafting",
        description="Show the AI authoring panel in the detection drawer. "
        "Independent of the MSSP-wide AI key configuration.",
        default=True,
        category="Detections",
    ),
    FeatureMeta(
        key="detection_promotion",
        label="Cross-customer rule promotion",
        description="Let analysts pull custom/customised rules from sibling "
        "tenants into this one.",
        default=True,
        category="Detections",
    ),
    FeatureMeta(
        key="bulk_export",
        label="Bulk export (Navigator / Sigma packs / PDF)",
        description="Allow exporting coverage layers, Sigma rule packs, and "
        "branded PDF reports for this customer.",
        default=True,
        category="Reports",
    ),
    FeatureMeta(
        key="connector_tests",
        label="Live connector tests",
        description="Permit read-only connector ping tests "
        "(Splunk / Elastic / Sentinel) from this customer's settings.",
        default=True,
        category="Integrations",
    ),
    FeatureMeta(
        key="grc_editing",
        label="GRC mapping edits",
        description="Allow editing control ↔ technique mappings within this "
        "customer's GRC view. Read-only when off.",
        default=True,
        category="GRC",
    ),
    FeatureMeta(
        key="customer_portal",
        label="Customer portal access",
        description="Allow customer-pinned users to log in to the customer "
        "portal. Turn off to disable tenant logins without deleting "
        "their accounts.",
        default=True,
        category="Access",
    ),
)

_BY_KEY: dict[str, FeatureMeta] = {f.key: f for f in CATALOG}


def catalog() -> list[dict]:
    """Front-end catalog payload."""
    return [
        {
            "key": f.key,
            "label": f.label,
            "description": f.description,
            "default": f.default,
            "category": f.category,
        }
        for f in CATALOG
    ]


def defaults() -> dict[str, bool]:
    return {f.key: f.default for f in CATALOG}


def normalise(overrides: dict | None) -> dict[str, bool]:
    """Merge defaults with the saved overrides, dropping unknown keys.

    Returns the *effective* per-feature boolean state — i.e. the dict
    the API hands to the UI and that `is_enabled()` consults.
    """
    out = defaults()
    if not overrides:
        return out
    for k, v in overrides.items():
        if k in _BY_KEY:
            out[k] = bool(v)
    return out


def validate_patch(patch: dict) -> dict[str, bool]:
    """Reject unknown keys, coerce values to bool. Returns the cleaned patch."""
    if not isinstance(patch, dict):
        raise ValueError("features must be a JSON object")
    cleaned: dict[str, bool] = {}
    for k, v in patch.items():
        if k not in _BY_KEY:
            raise ValueError(f"unknown feature key: {k}")
        cleaned[k] = bool(v)
    return cleaned


def is_enabled(customer_features: dict | None, key: str) -> bool:
    """Convenience accessor for enforcement points: merge then look up.

    `customer_features` is `Customer.features` as stored. Defaults to the
    catalog default when the customer hasn't overridden the toggle.
    """
    if key not in _BY_KEY:
        # Defensive: if a caller asks about a key we removed, behave like
        # the feature is off rather than crashing the request path.
        return False
    if customer_features and key in customer_features:
        return bool(customer_features[key])
    return _BY_KEY[key].default


__all__ = [
    "CATALOG",
    "FeatureMeta",
    "catalog",
    "defaults",
    "is_enabled",
    "normalise",
    "validate_patch",
]
