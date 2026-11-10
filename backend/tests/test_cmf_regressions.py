"""CMF regression tests that never connect to or alter a database.

The repository conftest disposes its configured pool but these tests use only
request schemas, pure transforms, and in-memory query adapters.
"""
from contextlib import asynccontextmanager
from types import SimpleNamespace
import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api import assets as assets_api
from app.api.assets import AssetDataSourceCreate, AssetDataSourcePatch, _invalidate_source_plans
from app.api.cmf_plan import (
    PlanItemPatch, RequirementPatch, _reject_nulls, _validate_plan_links,
)
from app.services.cmf_sources import normalize_source_fields, source_patch_changes, material_source_changes
from app.services.cmf_visibility import _assess, _fetch_collected, VisibilityState


def test_combined_picker_source_is_canonical_on_create():
    value = AssetDataSourceCreate(
        name="NIDS", attack_data_source=" Network Traffic: Network Traffic Content "
    )
    assert value.attack_data_source == "Network Traffic"
    assert value.attack_data_component == "Network Traffic Content"


def test_combined_source_replaces_stale_component():
    value = normalize_source_fields({
        "attack_data_source": "Process: Process Termination",
        "attack_data_component": "Process Creation",
    })
    assert value == {"attack_data_source": "Process", "attack_data_component": "Process Termination"}


def test_source_change_clears_previous_component():
    row = SimpleNamespace(attack_data_source="Process", attack_data_component="Process Creation")
    changes = source_patch_changes(AssetDataSourcePatch(attack_data_source="File"), row)
    assert changes == {"attack_data_source": "File", "attack_data_component": None}


def test_patch_clears_explicit_nulls_and_preserves_omitted_fields():
    row = SimpleNamespace(attack_data_source="Process", attack_data_component="Process Creation")
    payload = AssetDataSourcePatch(retention_days=None, timeliness_q=None, storage_connector_id=None)
    changes = source_patch_changes(payload, row)
    assert changes == {"retention_days": None, "timeliness_q": None, "storage_connector_id": None}
    assert "attack_data_source" not in changes


def test_clearing_source_also_clears_component():
    row = SimpleNamespace(attack_data_source="Process", attack_data_component="Process Creation")
    changes = source_patch_changes(AssetDataSourcePatch(attack_data_source=None), row)
    assert changes == {"attack_data_source": None, "attack_data_component": None}


@pytest.mark.parametrize("field", ["name", "enabled"])
def test_required_source_fields_reject_null(field):
    row = SimpleNamespace(attack_data_source=None, attack_data_component=None)
    with pytest.raises(ValueError, match="cannot be null"):
        source_patch_changes(AssetDataSourcePatch(**{field: None}), row)


@pytest.mark.parametrize("value", [-1, 1.5, True])
def test_retention_requires_nonnegative_integer(value):
    with pytest.raises(ValidationError):
        AssetDataSourceCreate(name="HMI logs", retention_days=value)


def test_theory_fields_round_trip_in_request_schema():
    source = AssetDataSourceCreate(
        name="HMI logs", kill_chain_phase="Installation",
        follow_on_collection="Registry keys", storage_location="Enterprise SIEM",
        retention_days=60,
    )
    assert source.model_dump()["follow_on_collection"] == "Registry keys"
    assert source.model_dump()["kill_chain_phase"] == "Installation"


@pytest.mark.parametrize("payload,required", [
    (RequirementPatch(title=None), ("title", "driver", "status")),
    (RequirementPatch(attack_technique_ids=None), ("attack_technique_ids",)),
    (PlanItemPatch(data_source=None), ("data_source",)),
    (PlanItemPatch(status=None), ("status",)),
])
def test_nonnullable_lifecycle_fields_reject_explicit_null(payload, required):
    with pytest.raises(HTTPException) as caught:
        _reject_nulls(payload, required)
    assert caught.value.status_code == 422


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


class Session:
    def __init__(self, *results):
        self.results = iter(results)

    async def execute(self, statement):
        return Result(next(self.results))


@pytest.mark.asyncio
async def test_canonical_source_becomes_visible_but_sibling_does_not():
    row = SimpleNamespace(
        attack_data_source="Process", attack_data_component="Process Creation",
        device_completeness_q=5, data_field_completeness_q=5, timeliness_q=5,
        consistency_q=5, retention_q=5,
    )
    collected = await _fetch_collected(Session([row]))
    assert _assess(["Process: Process Creation"], collected).state == VisibilityState.VISIBLE
    sibling = _assess(["Process: Process Termination"], collected)
    assert sibling.state == VisibilityState.NOT_COLLECTED
    assert sibling.quality_avg is None


@pytest.mark.asyncio
async def test_bare_parent_source_still_indicates_partial_visibility():
    row = SimpleNamespace(
        attack_data_source="Process", attack_data_component=None,
        device_completeness_q=None, data_field_completeness_q=None, timeliness_q=None,
        consistency_q=None, retention_q=None,
    )
    collected = await _fetch_collected(Session([row]))
    assert _assess(["Process: Process Creation"], collected).state == VisibilityState.PARTIAL


@pytest.mark.asyncio
async def test_unknown_plan_requirement_is_a_clean_422():
    with pytest.raises(HTTPException) as caught:
        await _validate_plan_links(
            Session(None), requirement_id=uuid.uuid4(), target_asset_id=None,
            asset_data_source_id=None, status="proposed", notes=None, data_source="HMI logs",
        )
    assert caught.value.status_code == 422


@pytest.mark.asyncio
async def test_source_from_different_asset_cannot_validate_plan():
    target = uuid.uuid4()
    source = SimpleNamespace(asset_id=uuid.uuid4(), enabled=True)
    with pytest.raises(HTTPException) as caught:
        await _validate_plan_links(
            Session(target, source), requirement_id=None, target_asset_id=target,
            asset_data_source_id=uuid.uuid4(), status="validated", notes="Sample checked", data_source="HMI logs",
        )
    assert caught.value.status_code == 422
    assert "target asset" in caught.value.detail


@pytest.mark.asyncio
async def test_validated_plan_requires_evidence_and_enabled_source():
    target = uuid.uuid4()
    for enabled, notes in [(False, "Sample checked"), (True, " ")]:
        with pytest.raises(HTTPException) as caught:
            await _validate_plan_links(
                Session(target, SimpleNamespace(asset_id=target, enabled=enabled, name="HMI logs", attack_data_source=None, attack_data_component=None)),
                requirement_id=None, target_asset_id=target,
                asset_data_source_id=uuid.uuid4(), status="validated", notes=notes, data_source="HMI logs",
            )
        assert caught.value.status_code == 422
    await _validate_plan_links(
        Session(target, SimpleNamespace(asset_id=target, enabled=True, name="HMI logs", attack_data_source=None, attack_data_component=None)),
        requirement_id=None, target_asset_id=target, asset_data_source_id=uuid.uuid4(),
        status="validated", notes="2026-11-10: expected HMI event found in SIEM sample", data_source="HMI logs",
    )


@pytest.mark.asyncio
async def test_unrelated_collection_source_cannot_satisfy_plan():
    target = uuid.uuid4()
    source = SimpleNamespace(
        asset_id=target, enabled=True, name="Syslog", attack_data_source=None,
        attack_data_component=None,
    )
    with pytest.raises(HTTPException) as caught:
        await _validate_plan_links(
            Session(target, source), requirement_id=None, target_asset_id=target,
            asset_data_source_id=uuid.uuid4(), status="validated", notes="checked",
            data_source="Process: Process Creation",
        )
    assert caught.value.status_code == 422
    assert "does not match" in caught.value.detail


@pytest.mark.asyncio
async def test_mapped_plan_matches_canonical_component_not_friendly_name():
    target = uuid.uuid4()
    source = SimpleNamespace(
        asset_id=target, enabled=True, name="Sysmon event 1", attack_data_source="Process",
        attack_data_component="Process Creation",
    )
    await _validate_plan_links(
        Session(target, source), requirement_id=None, target_asset_id=target,
        asset_data_source_id=uuid.uuid4(), status="collected", notes=None,
        data_source="Process: Process Creation",
    )


@pytest.mark.asyncio
async def test_partial_parent_quality_does_not_inherit_scored_sibling():
    bare = SimpleNamespace(
        attack_data_source="Process", attack_data_component=None,
        device_completeness_q=None, data_field_completeness_q=None, timeliness_q=None,
        consistency_q=None, retention_q=None,
    )
    specific = SimpleNamespace(
        attack_data_source="Process", attack_data_component="Process Creation",
        device_completeness_q=5, data_field_completeness_q=5, timeliness_q=5,
        consistency_q=5, retention_q=5,
    )
    collected = await _fetch_collected(Session([bare, specific]))
    sibling = _assess(["Process: Process Termination"], collected)
    assert sibling.state == VisibilityState.PARTIAL
    assert sibling.quality_avg is None


def test_patch_preserves_zero_retention_and_disabled_boolean():
    row = SimpleNamespace(attack_data_source=None, attack_data_component=None)
    assert source_patch_changes(AssetDataSourcePatch(retention_days=0, enabled=False), row) == {
        "retention_days": 0, "enabled": False,
    }


def test_component_without_source_is_rejected():
    row = SimpleNamespace(attack_data_source=None, attack_data_component=None)
    with pytest.raises(ValueError, match="requires attack_data_source"):
        source_patch_changes(AssetDataSourcePatch(attack_data_component="Process Creation"), row)


@pytest.mark.asyncio
async def test_status_alone_cannot_establish_collection():
    with pytest.raises(HTTPException) as caught:
        await _validate_plan_links(
            Session(), requirement_id=None, target_asset_id=None, asset_data_source_id=None,
            status="collected", notes=None, data_source="Process: Process Creation",
        )
    assert caught.value.status_code == 422


@pytest.mark.parametrize("field,old,new", [
    ("name", "old", "new"),
    ("enabled", True, False),
    ("attack_data_component", "Process Creation", "Process Termination"),
    ("log_source", "Security", "Sysmon"),
    ("storage_location", "siem-a", "siem-b"),
    ("retention_days", 90, 7),
    ("timeliness_q", 5, 1),
])
def test_material_collection_changes_require_revalidation(field, old, new):
    current = SimpleNamespace(**{field: old})
    assert material_source_changes({field: new}, current) == [field]
    assert material_source_changes({field: old}, current) == []


def test_narrative_edit_does_not_invalidate_collection_test():
    assert material_source_changes({"notes": "New context", "kill_chain_phase": "Installation"}, object()) == []


@pytest.mark.asyncio
async def test_invalidation_preserves_evidence_and_only_queries_linked_completed_plans():
    source_id = uuid.uuid4()
    plans = [
        SimpleNamespace(status="validated", notes="2026-11-10: event 4624 confirmed"),
        SimpleNamespace(status="collected", notes=None),
    ]
    class TrackingSession(Session):
        async def execute(self, statement):
            self.statement = statement
            return await super().execute(statement)
    session = TrackingSession(plans)
    assert await _invalidate_source_plans(session, [source_id], "retention changed") == 2
    assert all(p.status == "in_progress" for p in plans)
    assert plans[0].notes.startswith("2026-11-10: event 4624 confirmed")
    assert "Revalidation required: retention changed" in plans[0].notes
    params = session.statement.compile().params
    assert [source_id] in params.values()
    assert ["collected", "validated"] in params.values()
    sql = str(session.statement)
    assert "asset_data_source_id IN" in sql and "status IN" in sql


@pytest.mark.asyncio
async def test_patch_invalidates_completed_plan_in_same_source_transaction(monkeypatch):
    events = []
    source_id, asset_id = uuid.uuid4(), uuid.uuid4()
    row = SimpleNamespace(
        id=source_id, asset_id=asset_id, attack_data_source="Process",
        attack_data_component="Process Creation", retention_days=90,
    )
    class PatchSession(Session):
        async def flush(self): events.append("flush")
        async def refresh(self, _): pass
    session = PatchSession(row)
    @asynccontextmanager
    async def tenant():
        yield session
    async def invalidate(actual_session, source_ids, reason):
        assert actual_session is session and source_ids == [source_id]
        assert "retention_days" in reason
        events.append("invalidate")
    monkeypatch.setattr(assets_api, "tenant_session", tenant)
    monkeypatch.setattr(assets_api, "_invalidate_source_plans", invalidate)
    monkeypatch.setattr(assets_api, "_serialise_data_source", lambda value: value)
    result = await assets_api.patch_asset_data_source(
        asset_id, source_id, AssetDataSourcePatch(retention_days=7),
        SimpleNamespace(user=SimpleNamespace(email="student@example.test")),
    )
    assert result.retention_days == 7
    assert events == ["invalidate", "flush"]


@pytest.mark.asyncio
async def test_source_deletion_invalidates_before_foreign_key_link_is_cleared(monkeypatch):
    events = []
    source_id, asset_id = uuid.uuid4(), uuid.uuid4()
    row = SimpleNamespace(id=source_id, asset_id=asset_id)
    class DeleteSession(Session):
        async def delete(self, value):
            assert value is row
            events.append("delete")
    session = DeleteSession(row)
    @asynccontextmanager
    async def tenant():
        yield session
    async def invalidate(actual_session, source_ids, reason):
        assert actual_session is session and source_ids == [source_id]
        assert "deleted" in reason
        events.append("invalidate")
    monkeypatch.setattr(assets_api, "tenant_session", tenant)
    monkeypatch.setattr(assets_api, "_invalidate_source_plans", invalidate)
    response = await assets_api.delete_asset_data_source(asset_id, source_id)
    assert response.status_code == 204
    assert events == ["invalidate", "delete"]
