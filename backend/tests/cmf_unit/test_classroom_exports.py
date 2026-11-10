"""Pure CMF submission/starter checks, requiring no app or database fixtures."""
import csv
import io
from types import SimpleNamespace

import pytest

from app.services.cmf_classroom_data import AUTHOR, MARKER, owns_record, record_id, starter_records
from app.services.cmf_export import register_csv, submission_snapshot


def test_starter_ids_are_deterministic_and_tenant_specific():
    assert starter_records("lab01") == starter_records("lab01")
    assert record_id("lab01", "asset", "rtu") != record_id("lab02", "asset", "rtu")
    with pytest.raises(ValueError):
        starter_records('lab01";drop schema public')


def test_starter_matches_theory_and_keeps_quality_unscored():
    records = starter_records("lab01")
    assert [row["retention_days"] for row in records["data_sources"]] == [60, 30, 7]
    assert [row["location"] for row in records["assets"]] == ["Control Center", "Data Center", "Transmission Substation"]
    assert all(row["kill_chain_phase"] and row["follow_on_collection"] for row in records["data_sources"])
    assert not any(key.endswith("_q") for row in records["data_sources"] for key in row)
    ids = {row["id"] for row in records["assets"]}
    assert all(row["asset_id"] in ids for row in records["data_sources"])
    assert all(row["status"] == "proposed" for row in records["plan"])


def test_restore_ownership_requires_markers_not_only_ids():
    records = starter_records("lab01")
    spec = records["assets"][0]
    assert owns_record("assets", SimpleNamespace(**spec), spec)
    assert not owns_record("assets", SimpleNamespace(**{**spec, "external_id": "real-asset"}), spec)
    assert not owns_record("assets", SimpleNamespace(**{**spec, "tags": []}), spec)
    plan = records["plan"][0]
    assert owns_record("plan", SimpleNamespace(**plan), plan)
    assert not owns_record("plan", SimpleNamespace(**{**plan, "author_email": "other@example.test"}), plan)


def test_submission_is_explicit_and_preserves_links_without_connector_secrets():
    records = starter_records("lab01")
    args = []
    for key in ("assets", "data_sources", "requirements", "plan"):
        args.append([SimpleNamespace(**row, secret_config={"password": "never-export"}) for row in records[key]])
    snapshot = submission_snapshot("lab01", *args)
    assert snapshot["schema_version"] == 1
    assert snapshot["plan"][0]["target_asset_id"] == snapshot["assets"][2]["id"]
    assert snapshot["plan"][0]["asset_data_source_id"] == snapshot["data_sources"][2]["id"]
    assert "secret_config" not in str(snapshot)
    assert "never-export" not in str(snapshot)
    assert snapshot["data_sources"][0]["kill_chain_phase"]


def test_csv_preserves_multiline_evidence_and_neutralizes_formulas():
    snapshot = submission_snapshot(
        "lab01", [SimpleNamespace(id="a", name="=HYPERLINK(1)", location="Site", kind="iot_ot")],
        [SimpleNamespace(id="s", asset_id="a", name="Syslog", notes="line 1\nline 2", retention_days=7)], [], [],
    )
    rows = list(csv.DictReader(io.StringIO(register_csv(snapshot))))
    assert rows[0]["asset_name"].startswith("'=HYPERLINK")
    assert rows[0]["notes"] == "line 1\nline 2"
    assert rows[0]["retention_days"] == "7"


def test_csv_includes_assets_without_collection_sources():
    snapshot = submission_snapshot("lab01", [SimpleNamespace(id="a", name="RTU", kind="iot_ot")], [], [], [])
    rows = list(csv.DictReader(io.StringIO(register_csv(snapshot))))
    assert rows[0]["asset_name"] == "RTU"
    assert rows[0]["asset_id"] == "a"
    assert rows[0]["source_name"] == ""
