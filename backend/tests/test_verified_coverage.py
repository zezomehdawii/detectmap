"""Tests for the verified-coverage evidence ladder.

Most of this file is pure logic: the ladder is built from plain dataclasses
and the matching/telemetry helpers take small objects, so the important
semantics can be tested without the shared dev database. The API section is
read-only and simply proves the endpoint/permission wiring.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.api.deps import CUSTOMER_SELECTION_REQUIRED_MESSAGE
from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant
from app.main import app
from app.services.cmf_visibility import VisibilityCell, VisibilityState
from app.services.verified_coverage import (
    LEVEL_LABELS,
    _build_detection_evidence,
    _has_logsource,
    _match_deployment,
    _next_action,
    _normalize_text,
    _telemetry_for,
    compute_verified_coverage,
)


def _detection(**overrides):
    values = {
        "id": uuid.uuid4(),
        "title": "Suspicious PowerShell Encoded Command",
        "sigma_id": "0f0d6a5e-1111-2222-3333-444455556666",
        "detection_status": SimpleNamespace(value="idea"),
        "source": SimpleNamespace(value="custom"),
        "score_depth": 3,
        "logsource": {"product": "windows", "category": "process_creation"},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _deployment(**overrides):
    values = {
        "id": uuid.uuid4(),
        "name": "Suspicious PowerShell Encoded Command",
        "connector_id": uuid.uuid4(),
        "enabled": True,
        "external_id": "",
        "raw": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _sample(passed: bool | None):
    return SimpleNamespace(last_run_pass=passed)


def _outcome(kind: str):
    return SimpleNamespace(kind=kind)


def _cell(tid: str, state: VisibilityState, missing: list[str] | None = None) -> VisibilityCell:
    return VisibilityCell(
        technique_id=tid,
        name="Command and Scripting Interpreter",
        parent_technique_id=None,
        is_subtechnique=False,
        tactics=["execution"],
        state=state,
        required=[],
        missing=missing or [],
        quality_avg=None,
    )


def _evidence(
    *,
    detection=None,
    technique_ids=None,
    samples=None,
    outcomes=None,
    deployments=None,
    visibility=None,
    connector_names=None,
    deployment_decisions=None,
):
    return _build_detection_evidence(
        detection=detection or _detection(),
        technique_ids=["T1059"] if technique_ids is None else technique_ids,
        samples=samples or [],
        outcomes=outcomes or [],
        deployments=deployments or [],
        connector_names=connector_names or {},
        visibility_by_tid=visibility or {},
        deployment_decisions=deployment_decisions or {},
    )


# ---- text and matching helpers -------------------------------------------


class TestMatchingHelpers:
    def test_normalize_text_strips_punctuation(self) -> None:
        assert _normalize_text("  PowerShell: Encoded-Command!  ") == "powershell encoded command"

    def test_has_logsource_accepts_any_sigma_field(self) -> None:
        assert _has_logsource({"product": "windows"})
        assert _has_logsource({"category": "process_creation"})
        assert _has_logsource({"service": "security"})
        assert not _has_logsource({})
        assert not _has_logsource({"product": "  "})
        assert not _has_logsource(None)

    def test_sigma_id_matches_external_id(self) -> None:
        detection = _detection(sigma_id="ABC-123")
        deployment = _deployment(
            external_id="abc-123", name="Unrelated SIEM Rule Name"
        )
        assert _match_deployment(detection, deployment) == ["sigma_id"]

    def test_sigma_id_matches_siem_metadata(self) -> None:
        detection = _detection(sigma_id="abc-123")
        deployment = _deployment(
            external_id="siem-rule-9",
            name="Unrelated SIEM Rule Name",
            raw={"description": "derived from ABC-123"},
        )
        assert _match_deployment(detection, deployment) == ["sigma_id in SIEM metadata"]

    def test_exact_title_requires_eight_characters(self) -> None:
        detection = _detection(title="Short")
        deployment = _deployment(name="Short")
        assert _match_deployment(detection, deployment) == []

        detection = _detection(title="Longer title")
        deployment = _deployment(name="longer-title")
        assert _match_deployment(detection, deployment) == ["title"]

    def test_partial_title_requires_sixteen_characters(self) -> None:
        detection = _detection(title="Suspicious PowerShell")
        deployment = _deployment(name="Suspicious PowerShell Encoded Command")
        # 20 normalized characters -> partial match allowed.
        assert _match_deployment(detection, deployment) == ["title partial"]

        detection = _detection(title="Suspicious")
        deployment = _deployment(name="Suspicious PowerShell Encoded Command")
        assert _match_deployment(detection, deployment) == []

    def test_title_mismatch_is_not_a_match(self) -> None:
        detection = _detection(title="Credential Dumping via LSASS")
        deployment = _deployment(name="Encoded PowerShell Download")
        assert _match_deployment(detection, deployment) == []


# ---- telemetry aggregation ------------------------------------------------


class TestTelemetry:
    def test_visible_wins_over_partial(self) -> None:
        cells = {
            "T1059": _cell("T1059", VisibilityState.VISIBLE, []),
            "T1059.001": _cell("T1059.001", VisibilityState.PARTIAL, ["Process: Creation"]),
        }
        state, missing = _telemetry_for(["T1059", "T1059.001"], cells)
        assert state == "visible"
        assert missing == ["Process: Creation"]

    def test_partial_when_no_fully_visible_technique(self) -> None:
        cells = {"T1059": _cell("T1059", VisibilityState.PARTIAL, ["Process: Creation"])}
        assert _telemetry_for(["T1059"], cells) == ("partial", ["Process: Creation"])

    def test_no_data_source_when_every_cell_has_none(self) -> None:
        cells = {
            "T1059": _cell("T1059", VisibilityState.NO_DATA_SOURCE),
            "T1059.001": _cell("T1059.001", VisibilityState.NO_DATA_SOURCE),
        }
        assert _telemetry_for(["T1059", "T1059.001"], cells) == ("no_data_source", [])

    def test_not_collected_when_nothing_is_seen(self) -> None:
        cells = {"T1059": _cell("T1059", VisibilityState.NOT_COLLECTED, ["Process: Creation"])}
        assert _telemetry_for(["T1059"], cells) == ("not_collected", ["Process: Creation"])

    def test_unknown_without_any_cell(self) -> None:
        assert _telemetry_for(["T9999"], {}) == ("unknown", [])


# ---- evidence ladder -------------------------------------------------------


class TestEvidenceLadder:
    def test_designed_only_without_mapping_or_logsource(self) -> None:
        evidence = _evidence(technique_ids=[], detection=_detection(logsource={}))
        assert evidence.level == 1
        assert evidence.level_label == LEVEL_LABELS[1]
        assert "No ATT&CK technique mapping" in evidence.blockers
        assert "No Sigma logsource defined" in evidence.blockers

    def test_mapped_needs_both_mapping_and_logsource(self) -> None:
        evidence = _evidence(technique_ids=["T1059"], detection=_detection(logsource={}))
        assert evidence.level == 1
        assert "No Sigma logsource defined" in evidence.blockers

    def test_mapped_with_no_samples(self) -> None:
        evidence = _evidence()
        assert evidence.level == 2
        assert "No positive/negative event samples" in evidence.blockers
        assert evidence.next_action == "Add and run positive/negative event samples"

    def test_failing_sample_blocks_testing(self) -> None:
        evidence = _evidence(samples=[_sample(True), _sample(False)])
        assert evidence.level == 2
        assert evidence.samples_passed == 1
        assert evidence.samples_failed == 1
        assert "1 event sample(s) failing" in evidence.blockers

    def test_pending_sample_blocks_testing(self) -> None:
        evidence = _evidence(samples=[_sample(True), _sample(None)])
        assert evidence.level == 2
        assert evidence.samples_pending == 1
        assert "1 event sample(s) not run" in evidence.blockers

    def test_all_samples_passing_is_tested(self) -> None:
        evidence = _evidence(samples=[_sample(True), _sample(True)])
        assert evidence.level == 3
        assert evidence.samples_passed == 2
        assert evidence.samples_failed == 0
        assert evidence.samples_pending == 0
        assert "No enabled matching SIEM rule" in evidence.blockers

    def test_deployed_claim_without_enabled_match_is_called_out(self) -> None:
        detection = _detection(detection_status=SimpleNamespace(value="deployed"))
        evidence = _evidence(detection=detection, samples=[_sample(True)])
        assert evidence.level == 3
        assert (
            "Marked deployed, but no enabled matching SIEM rule was found"
            in evidence.blockers
        )

    def test_disabled_match_does_not_verify_deployment(self) -> None:
        deployment = _deployment(enabled=False, external_id="0f0d6a5e-1111-2222-3333-444455556666")
        evidence = _evidence(
            samples=[_sample(True)],
            deployments=[deployment],
            connector_names={deployment.connector_id: "Sentinel"},
        )
        assert evidence.level == 3
        assert evidence.deployed_matches[0].enabled is False

    def test_enabled_match_verifies_deployment(self) -> None:
        deployment = _deployment(external_id="0f0d6a5e-1111-2222-3333-444455556666")
        evidence = _evidence(
            samples=[_sample(True)],
            deployments=[deployment],
            connector_names={deployment.connector_id: "Sentinel"},
        )
        assert evidence.level == 4
        assert evidence.deployed_matches[0].connector == "Sentinel"
        assert "Required telemetry is not collected" in evidence.blockers

    def test_collected_telemetry_moves_to_effective(self) -> None:
        deployment = _deployment(external_id="0f0d6a5e-1111-2222-3333-444455556666")
        visibility = {
            "T1059": _cell("T1059", VisibilityState.VISIBLE),
        }
        evidence = _evidence(
            samples=[_sample(True)],
            deployments=[deployment],
            visibility=visibility,
        )
        assert evidence.level == 5
        assert evidence.telemetry_state == "visible"
        assert "No validated true-positive outcome yet" in evidence.blockers

    def test_true_positive_proves_the_detection(self) -> None:
        deployment = _deployment(external_id="0f0d6a5e-1111-2222-3333-444455556666")
        visibility = {
            "T1059": _cell("T1059", VisibilityState.VISIBLE),
        }
        evidence = _evidence(
            samples=[_sample(True)],
            deployments=[deployment],
            outcomes=[_outcome("tp"), _outcome("fp")],
            visibility=visibility,
        )
        assert evidence.level == 6
        assert evidence.tp_count == 1
        assert evidence.fp_count == 1
        assert evidence.next_action == "Keep validating on a schedule"

    def test_false_positive_alone_does_not_prove(self) -> None:
        deployment = _deployment(external_id="0f0d6a5e-1111-2222-3333-444455556666")
        visibility = {
            "T1059": _cell("T1059", VisibilityState.VISIBLE),
        }
        evidence = _evidence(
            samples=[_sample(True)],
            deployments=[deployment],
            outcomes=[_outcome("fp")],
            visibility=visibility,
        )
        assert evidence.level == 5
        assert evidence.tp_count == 0


class TestDeploymentDecisions:
    def test_confirmed_pair_is_evidence_without_heuristic(self) -> None:
        detection = _detection(title="Encoded PowerShell", sigma_id="sigma-1")
        deployment = _deployment(name="SIEM Rule 17", external_id="siem-17")
        evidence = _evidence(
            detection=detection,
            samples=[_sample(True)],
            deployments=[deployment],
            deployment_decisions={(detection.id, deployment.id): "confirmed"},
        )
        assert evidence.level == 4
        match = evidence.deployed_matches[0]
        assert match.id == str(deployment.id)
        assert match.decision == "confirmed"
        assert "confirmed" in match.match_reason

    def test_rejected_pair_suppresses_heuristic(self) -> None:
        detection = _detection()
        deployment = _deployment()  # matching title and sigma id
        evidence = _evidence(
            detection=detection,
            samples=[_sample(True)],
            deployments=[deployment],
            deployment_decisions={(detection.id, deployment.id): "rejected"},
        )
        assert evidence.level == 3
        assert evidence.deployed_matches[0].decision == "rejected"
        assert "rejected" in evidence.deployed_matches[0].match_reason
        assert "No enabled matching SIEM rule" in evidence.blockers

    def test_rejected_pair_without_heuristic_is_not_listed(self) -> None:
        detection = _detection(title="Encoded PowerShell", sigma_id="sigma-1")
        deployment = _deployment(name="SIEM Rule 17", external_id="siem-17")
        evidence = _evidence(
            detection=detection,
            samples=[_sample(True)],
            deployments=[deployment],
            deployment_decisions={(detection.id, deployment.id): "rejected"},
        )
        assert evidence.level == 3
        assert evidence.deployed_matches == []

    def test_disabled_confirmed_pair_does_not_verify(self) -> None:
        detection = _detection(title="Encoded PowerShell", sigma_id="sigma-1")
        deployment = _deployment(
            name="SIEM Rule 17", external_id="siem-17", enabled=False
        )
        evidence = _evidence(
            detection=detection,
            samples=[_sample(True)],
            deployments=[deployment],
            deployment_decisions={(detection.id, deployment.id): "confirmed"},
        )
        assert evidence.level == 3
        assert evidence.deployed_matches[0].decision == "confirmed"
        assert evidence.deployed_matches[0].enabled is False


class TestNextAction:
    def test_mapping_action_is_preferred_when_mapping_is_missing(self) -> None:
        action = _next_action(1, "idea", ["No ATT&CK technique mapping"])
        assert action == "Map the rule to an ATT&CK technique"

    def test_deployed_status_points_at_reconciliation(self) -> None:
        action = _next_action(3, "deployed", ["No enabled matching SIEM rule"])
        assert action == "Reconcile the SIEM rule or correct the deployed status"


# ---- API wiring ------------------------------------------------------------


def _client(token: str, customer: str = "acme") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}", "X-Customer": customer},
    )


async def _acme_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_acme'")
        )
        return row.scalar_one_or_none() is not None


@pytest.mark.asyncio
class TestVerifiedCoverageEndpoint:
    async def test_coverage_returns_consistent_summary(self, demo_admin_token) -> None:
        if not await _acme_exists():
            pytest.skip("cust_acme schema not provisioned — run seed_demo first")
        async with _client(demo_admin_token) as c:
            response = await c.get(
                "/verified/coverage",
                params={"domain": "enterprise", "include_details": "false"},
            )
            assert response.status_code == 200, response.text
            body = response.json()

            technique_id = body["techniques"][0]["technique_id"]
            detail = await c.get(
                f"/verified/techniques/{technique_id}",
                params={"domain": "enterprise"},
            )
            assert detail.status_code == 200, detail.text
            detail_body = detail.json()
            assert detail_body["technique_id"] == technique_id
            assert isinstance(detail_body["detections"], list)

            missing = await c.get(
                "/verified/techniques/T9999.999",
                params={"domain": "enterprise"},
            )
            assert missing.status_code == 404

        assert body["domain"] == "enterprise"
        assert body["total_techniques"] == len(body["techniques"])
        assert all(technique["detections"] == [] for technique in body["techniques"])
        assert sum(body["level_counts"].values()) == body["total_techniques"]
        assert body["designed_count"] <= body["total_techniques"]
        assert body["verified_deployed_count"] <= body["designed_count"]
        assert body["effective_count"] <= body["verified_deployed_count"]
        assert body["proven_count"] <= body["effective_count"]
        for technique in body["techniques"][:20]:
            assert technique["level_label"]
            assert 0 <= technique["level"] <= 6

    async def test_coverage_requires_a_customer(self, demo_admin_token) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {demo_admin_token}"},
        ) as c:
            response = await c.get("/verified/coverage")
        assert response.status_code == 400
        assert response.json()["detail"] == CUSTOMER_SELECTION_REQUIRED_MESSAGE

    async def test_readonly_role_gets_readonly_coverage(
        self, demo_readonly_token
    ) -> None:
        if not await _acme_exists():
            pytest.skip("cust_acme schema not provisioned — run seed_demo first")
        async with _client(demo_readonly_token) as c:
            response = await c.get(
                "/verified/coverage",
                params={"domain": "enterprise", "include_details": "false"},
            )
        assert response.status_code == 200, response.text
        assert response.json()["can_edit"] is False


async def _globex_exists() -> bool:
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name='cust_globex'")
        )
        return row.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_live_tenant_ladder_is_consistent() -> None:
    """Read-only smoke test against the demo tenant when it is provisioned."""
    if not await _globex_exists():
        pytest.skip("cust_globex schema not provisioned")
    set_tenant("globex")
    try:
        result = await compute_verified_coverage("enterprise")
    finally:
        set_tenant(None)

    assert result.total_techniques == sum(result.level_counts.values())
    assert result.total_techniques > 0
    assert result.designed_count == sum(
        1 for item in result.techniques if item.level >= 1
    )
    assert result.verified_deployed_count == sum(
        1 for item in result.techniques if item.level >= 4
    )
    for item in result.techniques:
        assert 0 <= item.level <= 6
        assert item.detections == sorted(
            item.detections,
            key=lambda d: (-d.level, -d.score_depth, d.title),
        )
