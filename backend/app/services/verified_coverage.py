"""Evidence-based detection coverage ("verified coverage").

The existing coverage engine answers *what has an analyst claimed?* by
aggregating the tenant's `Detection.detection_status`. This service answers
the stricter question a detection-engineering team actually needs:

    What evidence proves the detection is mapped, tested, deployed, fed by
    telemetry, and effective?

Each detection is assigned a level on the evidence ladder:

    0  no detection
    1  designed (a Sigma rule exists)
    2  mapped (ATT&CK technique + Sigma logsource)
    3  tested (all event samples pass)
    4  deployed (a matching, enabled SIEM rule was imported)
    5  observable (the technique has collected telemetry)
    6  proven (a true-positive outcome has been recorded)

Technique-level evidence is the best level among its covering detections.
Nothing here mutates the curated detection library; everything is computed
from the existing tables so the feature can ship without a migration.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from app.db.tenant import tenant_session
from app.models.customer import (
    Connector,
    DeployedUseCase,
    Detection,
    DetectionDeploymentLink,
    DetectionEventSample,
    DetectionOutcome,
    DetectionTechnique,
)
from app.services.cmf_visibility import (
    VisibilityCell,
    VisibilityState,
    compute_visibility_matrix,
)
from app.services.coverage import (
    CoverageState,
    DenominatorKind,
    TechniqueCell,
    compute_matrix,
)

LEVEL_LABELS: dict[int, str] = {
    0: "No detection",
    1: "Designed",
    2: "Mapped",
    3: "Tested",
    4: "Deployed verified",
    5: "Telemetry ready",
    6: "Proven",
}

_TELEMETRY_READY_STATES = (VisibilityState.VISIBLE, VisibilityState.PARTIAL)


@dataclass
class DeploymentMatch:
    id: str
    name: str
    connector: str
    enabled: bool
    match_reason: str
    decision: Optional[str] = None  # None=heuristic, confirmed, rejected


@dataclass
class DetectionEvidence:
    id: str
    title: str
    sigma_id: str
    status: str
    source: str
    score_depth: int
    technique_ids: list[str]
    level: int
    level_label: str
    blockers: list[str]
    next_action: str
    deployed_matches: list[DeploymentMatch]
    samples_total: int
    samples_passed: int
    samples_failed: int
    samples_pending: int
    tp_count: int
    fp_count: int
    telemetry_state: str
    missing_data_sources: list[str]


@dataclass
class TechniqueEvidence:
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    claimed_state: str
    visibility_state: str
    detection_count: int
    level: int
    level_label: str
    blockers: list[str]
    next_action: str
    detections: list[DetectionEvidence] = field(default_factory=list)


@dataclass
class VerifiedCoverage:
    domain: str
    generated_at: str
    total_techniques: int
    not_applicable_count: int
    designed_count: int
    claimed_deployed_count: int
    verified_deployed_count: int
    effective_count: int
    proven_count: int
    level_counts: dict[str, int]
    detections_total: int
    detection_level_counts: dict[str, int]
    techniques: list[TechniqueEvidence]


# ---- text / matching helpers ---------------------------------------------

def _normalize_text(value: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def _has_logsource(logsource: dict | None) -> bool:
    return any(
        str((logsource or {}).get(key) or "").strip()
        for key in ("category", "product", "service")
    )


def _match_deployment(
    detection: Detection,
    deployment: DeployedUseCase,
) -> list[str]:
    """Return human-readable reasons a SIEM rule matches a library rule.

    This is deliberately conservative. It is a read-time heuristic, not a
    persisted identity link: the operator can still confirm the match later
    when the full reconciliation feature lands.
    """
    reasons: list[str] = []

    sigma_id = (detection.sigma_id or "").strip().lower()
    if sigma_id:
        if sigma_id == (deployment.external_id or "").strip().lower():
            reasons.append("sigma_id")
        try:
            raw_text = json.dumps(deployment.raw or {}, default=str).lower()
        except (TypeError, ValueError):
            raw_text = ""
        if sigma_id in raw_text:
            reasons.append("sigma_id in SIEM metadata")

    wanted = _normalize_text(detection.title)
    actual = _normalize_text(deployment.name)
    if wanted and actual:
        if wanted == actual and len(wanted) >= 8:
            reasons.append("title")
        elif len(wanted) >= 16 and (wanted in actual or actual in wanted):
            reasons.append("title partial")

    return reasons


def _telemetry_for(
    technique_ids: list[str],
    visibility_by_tid: dict[str, VisibilityCell],
) -> tuple[str, list[str]]:
    states: list[VisibilityState] = []
    missing: set[str] = set()
    for tid in technique_ids:
        cell = visibility_by_tid.get(tid)
        if cell is None:
            continue
        states.append(cell.state)
        missing.update(cell.missing or [])

    if not states:
        return "unknown", []
    if any(state == VisibilityState.VISIBLE for state in states):
        return "visible", sorted(missing)
    if any(state == VisibilityState.PARTIAL for state in states):
        return "partial", sorted(missing)
    if all(state == VisibilityState.NO_DATA_SOURCE for state in states):
        return "no_data_source", sorted(missing)
    return "not_collected", sorted(missing)


def _next_action(level: int, status: str, blockers: list[str]) -> str:
    if any("approved review" in b for b in blockers):
        return "Complete the detection review or roll back the deployment"
    if level >= 6:
        return "Keep validating on a schedule"
    if level == 1:
        if any("technique mapping" in b for b in blockers):
            return "Map the rule to an ATT&CK technique"
        return "Define the Sigma logsource"
    if level == 2:
        if any("sample" in b.lower() for b in blockers):
            return "Add and run positive/negative event samples"
        return "Define the Sigma logsource"
    if level == 3:
        if status == "deployed":
            return "Reconcile the SIEM rule or correct the deployed status"
        return "Link or deploy the matching SIEM rule"
    if level == 4:
        return "Collect the missing data source"
    if level == 5:
        return "Validate with a true-positive outcome or emulation"
    return "Add the next evidence layer"


def _build_detection_evidence(
    *,
    detection: Detection,
    technique_ids: list[str],
    samples: list[DetectionEventSample],
    outcomes: list[DetectionOutcome],
    deployments: list[DeployedUseCase],
    connector_names: dict,
    visibility_by_tid: dict[str, VisibilityCell],
    deployment_decisions: Optional[dict[tuple, str]] = None,
) -> DetectionEvidence:
    status = (
        detection.detection_status.value
        if hasattr(detection.detection_status, "value")
        else str(detection.detection_status)
    )
    decisions = deployment_decisions or {}
    matches: list[DeploymentMatch] = []
    for deployment in deployments:
        decision = decisions.get((detection.id, deployment.id))
        reasons = _match_deployment(detection, deployment)

        # A rejection only suppresses a pair that the heuristic considered
        # plausible in the first place. A confirmed pair is evidence even when
        # the SIEM renamed the rule beyond the heuristic's reach.
        if decision == "rejected" and not reasons:
            continue
        if decision != "confirmed" and not reasons:
            continue
        if decision == "confirmed" and "confirmed" not in reasons:
            reasons.append("confirmed")
        if decision == "rejected":
            reasons.append("rejected")

        matches.append(
            DeploymentMatch(
                id=str(deployment.id),
                name=deployment.name,
                connector=connector_names.get(deployment.connector_id, "unknown"),
                enabled=bool(deployment.enabled),
                match_reason=", ".join(reasons),
                decision=decision,
            )
        )

    enabled_matches = [
        match for match in matches if match.enabled and match.decision != "rejected"
    ]
    samples_total = len(samples)
    samples_passed = sum(1 for sample in samples if sample.last_run_pass is True)
    samples_failed = sum(1 for sample in samples if sample.last_run_pass is False)
    samples_pending = samples_total - samples_passed - samples_failed
    tp_count = sum(1 for outcome in outcomes if (outcome.kind or "").lower() == "tp")
    fp_count = sum(1 for outcome in outcomes if (outcome.kind or "").lower() == "fp")
    telemetry_state, missing_data_sources = _telemetry_for(
        technique_ids, visibility_by_tid
    )

    level = 1
    blockers: list[str] = []

    if not technique_ids:
        blockers.append("No ATT&CK technique mapping")
    if not _has_logsource(detection.logsource):
        blockers.append("No Sigma logsource defined")
    if technique_ids and _has_logsource(detection.logsource):
        level = 2

    if level >= 2:
        if samples_total == 0:
            blockers.append("No positive/negative event samples")
        elif samples_failed:
            blockers.append(f"{samples_failed} event sample(s) failing")
        elif samples_pending:
            blockers.append(f"{samples_pending} event sample(s) not run")
        else:
            level = 3

    if level >= 3:
        if enabled_matches:
            level = 4
        elif status == "deployed":
            blockers.append("Marked deployed, but no enabled matching SIEM rule was found")
        else:
            blockers.append("No enabled matching SIEM rule")

    review_status = getattr(detection, "review_status", None)
    if hasattr(review_status, "value"):
        review_status = review_status.value
    if status == "deployed" and review_status not in (None, "approved"):
        blockers.append("Deployed without an approved review")

    if level >= 4:
        if telemetry_state in {state.value for state in _TELEMETRY_READY_STATES}:
            level = 5
        else:
            blockers.append("Required telemetry is not collected")

    if level >= 5:
        if tp_count > 0:
            level = 6
        else:
            blockers.append("No validated true-positive outcome yet")

    return DetectionEvidence(
        id=str(detection.id),
        title=detection.title,
        sigma_id=detection.sigma_id,
        status=status,
        source=(
            detection.source.value
            if hasattr(detection.source, "value")
            else str(detection.source)
        ),
        score_depth=int(detection.score_depth or 0),
        technique_ids=sorted(set(technique_ids)),
        level=level,
        level_label=LEVEL_LABELS[level],
        blockers=blockers,
        next_action=_next_action(level, status, blockers),
        deployed_matches=matches,
        samples_total=samples_total,
        samples_passed=samples_passed,
        samples_failed=samples_failed,
        samples_pending=samples_pending,
        tp_count=tp_count,
        fp_count=fp_count,
        telemetry_state=telemetry_state,
        missing_data_sources=missing_data_sources,
    )


async def compute_verified_coverage(
    domain: str = "enterprise",
) -> VerifiedCoverage:
    """Compute the evidence ladder for the active tenant.

    Caller must be inside an active tenant context (the API dependency does
    this). Two existing read models are reused: the DeTT&CT coverage matrix
    for claimed state/technique metadata, and the CMF visibility matrix for
    telemetry readiness.
    """
    coverage_matrix = await compute_matrix(domain, DenominatorKind.FULL, None)
    visibility_matrix = await compute_visibility_matrix(
        domain, DenominatorKind.FULL, None
    )

    cells_by_tid: dict[str, TechniqueCell] = {}
    for cells in coverage_matrix.by_tactic.values():
        for cell in cells:
            cells_by_tid[cell.technique_id] = cell

    visibility_by_tid: dict[str, VisibilityCell] = {}
    for cells in visibility_matrix.by_tactic.values():
        for cell in cells:
            visibility_by_tid[cell.technique_id] = cell

    async with tenant_session() as session:
        detections = (await session.execute(select(Detection))).scalars().all()
        mappings = (
            await session.execute(select(DetectionTechnique))
        ).scalars().all()
        samples = (
            await session.execute(select(DetectionEventSample))
        ).scalars().all()
        outcomes = (
            await session.execute(select(DetectionOutcome))
        ).scalars().all()
        deployments = (
            await session.execute(select(DeployedUseCase))
        ).scalars().all()
        connector_rows = (
            await session.execute(select(Connector.id, Connector.label))
        ).all()
        link_rows = (
            await session.execute(select(DetectionDeploymentLink))
        ).scalars().all()

    connector_names = {row[0]: row[1] for row in connector_rows}
    deployment_decisions = {
        (link.detection_id, link.deployed_use_case_id): link.status
        for link in link_rows
    }
    techniques_by_detection: dict = defaultdict(set)
    for mapping in mappings:
        techniques_by_detection[mapping.detection_id].add(mapping.technique_id)

    samples_by_detection: dict = defaultdict(list)
    for sample in samples:
        samples_by_detection[sample.detection_id].append(sample)

    outcomes_by_detection: dict = defaultdict(list)
    for outcome in outcomes:
        outcomes_by_detection[outcome.detection_id].append(outcome)

    detection_evidence: list[DetectionEvidence] = []
    evidence_by_technique: dict[str, list[DetectionEvidence]] = defaultdict(list)

    deployment_rows = list(deployments)
    for detection in detections:
        status = (
            detection.detection_status.value
            if hasattr(detection.detection_status, "value")
            else str(detection.detection_status)
        )
        # Gaps are explicit "we don't have this" markers, and not-applicable
        # detections are intentional exclusions. Neither is evidence of a
        # designed detection.
        if status in {"gap", "not_applicable"}:
            continue

        technique_ids = sorted(techniques_by_detection.get(detection.id, set()))
        evidence = _build_detection_evidence(
            detection=detection,
            technique_ids=technique_ids,
            samples=samples_by_detection.get(detection.id, []),
            outcomes=outcomes_by_detection.get(detection.id, []),
            deployments=deployment_rows,
            connector_names=connector_names,
            visibility_by_tid=visibility_by_tid,
            deployment_decisions=deployment_decisions,
        )
        detection_evidence.append(evidence)
        for tid in technique_ids:
            evidence_by_technique[tid].append(evidence)

    techniques: list[TechniqueEvidence] = []
    not_applicable_count = 0

    for tid, cell in cells_by_tid.items():
        if cell.state == CoverageState.NOT_APPLICABLE:
            not_applicable_count += 1
            continue

        dets = sorted(
            evidence_by_technique.get(tid, []),
            key=lambda item: (-item.level, -item.score_depth, item.title),
        )
        visibility = visibility_by_tid.get(tid)
        visibility_state = (
            visibility.state.value if visibility is not None else "unknown"
        )

        if not dets:
            level = 0
            blockers = ["No detection"]
            next_action = "Create a detection"
        else:
            best = dets[0]
            level = best.level
            blockers = list(best.blockers)
            next_action = best.next_action
            # Surface the telemetry issue at technique level too, even when
            # the best detection has already stopped at deployment.
            if (
                visibility is not None
                and visibility.state in _TELEMETRY_READY_STATES
                and level < 5
            ):
                blockers.append("Telemetry exists, but the detection is not yet verified")

        techniques.append(
            TechniqueEvidence(
                technique_id=tid,
                name=cell.name,
                tactics=list(cell.tactics or []),
                is_subtechnique=bool(cell.is_subtechnique),
                claimed_state=cell.state.value,
                visibility_state=visibility_state,
                detection_count=len(dets),
                level=level,
                level_label=LEVEL_LABELS[level],
                blockers=list(dict.fromkeys(blockers)),
                next_action=next_action,
                detections=dets,
            )
        )

    techniques.sort(key=lambda item: (item.level, item.technique_id))

    level_counts = Counter(item.level for item in techniques)
    detection_level_counts = Counter(item.level for item in detection_evidence)
    total = len(techniques)

    return VerifiedCoverage(
        domain=domain,
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_techniques=total,
        not_applicable_count=not_applicable_count,
        designed_count=sum(1 for item in techniques if item.level >= 1),
        claimed_deployed_count=sum(
            1 for item in techniques if item.claimed_state == CoverageState.DEPLOYED.value
        ),
        verified_deployed_count=sum(1 for item in techniques if item.level >= 4),
        effective_count=sum(1 for item in techniques if item.level >= 5),
        proven_count=sum(1 for item in techniques if item.level >= 6),
        level_counts={str(level): level_counts.get(level, 0) for level in range(7)},
        detections_total=len(detection_evidence),
        detection_level_counts={
            str(level): detection_level_counts.get(level, 0) for level in range(7)
        },
        techniques=techniques,
    )
