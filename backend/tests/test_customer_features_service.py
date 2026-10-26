"""Unit tests for `app.services.customer_features`.

The service is the single source of truth for the per-customer feature
toggle catalog: defaults, allow-list validation, the effective-state
merge, and the `is_enabled()` accessor used by both the require_feature
dependency and the customer-portal login gate. Pure-Python tests, no DB.
"""
from __future__ import annotations

import pytest

from app.services import customer_features as cf


def test_catalog_shape() -> None:
    cat = cf.catalog()
    assert len(cat) >= 7
    keys = {m["key"] for m in cat}
    # All seven shipped toggles must be in the catalog.
    assert {
        "detection_editing",
        "ai_authoring",
        "detection_promotion",
        "bulk_export",
        "connector_tests",
        "grc_editing",
        "customer_portal",
    }.issubset(keys)
    # Every entry has the metadata fields the UI consumes.
    for m in cat:
        for field in ("key", "label", "description", "default", "category"):
            assert field in m, m


def test_defaults_all_on() -> None:
    d = cf.defaults()
    # The shipped policy is "open by default" — existing customers keep
    # working when a new toggle is added. If a toggle is ever introduced
    # with `default=False`, update this assertion intentionally.
    assert all(d.values()), d


def test_normalise_with_no_overrides_returns_defaults() -> None:
    assert cf.normalise(None) == cf.defaults()
    assert cf.normalise({}) == cf.defaults()


def test_normalise_applies_overrides() -> None:
    out = cf.normalise({"ai_authoring": False, "bulk_export": False})
    assert out["ai_authoring"] is False
    assert out["bulk_export"] is False
    # Other keys keep their defaults.
    assert out["detection_editing"] is True


def test_normalise_drops_unknown_keys() -> None:
    out = cf.normalise({"bogus_key": True, "ai_authoring": False})
    assert "bogus_key" not in out
    assert out["ai_authoring"] is False


def test_normalise_coerces_to_bool() -> None:
    # JSONB will sometimes hand back ints / strings depending on the
    # source — normalise() must coerce so downstream `if` branches behave.
    out = cf.normalise({"ai_authoring": 0, "bulk_export": 1, "grc_editing": "yes"})
    assert out["ai_authoring"] is False
    assert out["bulk_export"] is True
    assert out["grc_editing"] is True


def test_validate_patch_accepts_known_keys() -> None:
    cleaned = cf.validate_patch({"ai_authoring": False, "bulk_export": True})
    assert cleaned == {"ai_authoring": False, "bulk_export": True}


def test_validate_patch_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError, match="unknown feature key"):
        cf.validate_patch({"bogus": True})


def test_validate_patch_rejects_non_dict() -> None:
    with pytest.raises(ValueError):
        cf.validate_patch(["ai_authoring"])  # type: ignore[arg-type]


def test_validate_patch_coerces_to_bool() -> None:
    # The patch entrypoint also coerces (defence in depth — a buggy
    # caller can't shove "true" strings into JSONB unchanged).
    cleaned = cf.validate_patch({"ai_authoring": "no"})
    assert cleaned["ai_authoring"] is True  # non-empty string is truthy
    cleaned = cf.validate_patch({"ai_authoring": ""})
    assert cleaned["ai_authoring"] is False


def test_is_enabled_default_when_no_override() -> None:
    assert cf.is_enabled({}, "ai_authoring") is True
    assert cf.is_enabled(None, "ai_authoring") is True


def test_is_enabled_uses_override_when_set() -> None:
    assert cf.is_enabled({"ai_authoring": False}, "ai_authoring") is False
    assert cf.is_enabled({"ai_authoring": True}, "ai_authoring") is True


def test_is_enabled_unknown_key_is_off() -> None:
    # Defensive: a caller asking about a key we removed should not crash
    # the request path — `is_enabled` returns False (treat as disabled).
    assert cf.is_enabled({}, "deleted_feature") is False
    assert cf.is_enabled({"deleted_feature": True}, "deleted_feature") is False
