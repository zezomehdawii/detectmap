"""Per-tenant (customer-schema) models.

Bound to CustomerBase / customer_metadata which carry no schema qualifier.
At query time these tables resolve against whatever schema search_path
points to (cust_<codename>), which is set per request by tenant_session().
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import CustomerBase, enum_values, uuid_pk


class DetectionStatus(str, enum.Enum):
    IDEA = "idea"
    IN_DEVELOPMENT = "in_development"
    TUNING = "tuning"
    DEPLOYED = "deployed"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


class DetectionSource(str, enum.Enum):
    GLOBAL = "global"          # synced from SigmaHQ catalog, untouched
    CUSTOMIZED = "customized"  # SigmaHQ rule that the customer has edited
    CUSTOM = "custom"          # customer-authored from scratch


class SigmaLevel(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionReviewStatus(str, enum.Enum):
    """Editorial state that gates promotion to `deployed`.

    The lifecycle is deliberately separate from `DetectionStatus`: a rule can
    be deployed in production and still need re-review after an edit, so
    status and review state are not the same axis.
    """
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"


class Detection(CustomerBase):
    """A Sigma rule + operational overlay (status, scoring, source provenance).

    The 'sigma_*' columns mirror the Sigma spec 1:1 so a rule can round-trip
    to/from YAML without lossy transformation. Operational columns (status,
    breadth/depth scores, source) sit alongside but never serialize into the
    exported YAML.
    """
    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = uuid_pk()

    # --- Sigma spec fields ---
    sigma_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    sigma_status: Mapped[Optional[str]] = mapped_column(String(32))  # stable/test/experimental/deprecated
    level: Mapped[Optional[SigmaLevel]] = mapped_column(
        SAEnum(SigmaLevel, name="sigma_level", values_callable=enum_values),
    )
    author: Mapped[Optional[str]] = mapped_column(String(200))
    sigma_references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    logsource: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    detection: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    falsepositives: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    raw_yaml: Mapped[Optional[str]] = mapped_column(Text)  # canonical YAML for round-trip

    # --- Operational overlay ---
    detection_status: Mapped[DetectionStatus] = mapped_column(
        SAEnum(DetectionStatus, name="detection_status", values_callable=enum_values),
        default=DetectionStatus.IDEA,
        nullable=False,
        index=True,
    )
    source: Mapped[DetectionSource] = mapped_column(
        SAEnum(DetectionSource, name="detection_source", values_callable=enum_values),
        default=DetectionSource.CUSTOM,
        nullable=False,
        index=True,
    )
    # DeTT&CT-style scoring on a 0-5 integer scale per dimension.
    score_breadth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # A-B
    score_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)    # A-D

    # Origin tracking for global-rule overrides (lets us reset to upstream).
    upstream_global_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    # --- Review lifecycle ---
    # `review_status` gates transitions into DetectionStatus.DEPLOYED. The
    # remaining columns are the current review assignment/decision. The full
    # history lives in DetectionReviewEvent so a rule can be audited after
    # several review cycles without replaying the detection row.
    owner: Mapped[Optional[str]] = mapped_column(String(200))
    review_status: Mapped[str] = mapped_column(
        String(20),
        default=DetectionReviewStatus.DRAFT.value,
        nullable=False,
        index=True,
    )
    reviewer_email: Mapped[Optional[str]] = mapped_column(String(320))
    review_requested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    review_due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[Optional[str]] = mapped_column(Text)

    version: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    last_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    technique_mappings: Mapped[list["DetectionTechnique"]] = relationship(
        back_populates="detection", cascade="all, delete-orphan"
    )


class DetectionVersion(CustomerBase):
    """An immutable revision of a rule's configuration within its tenant."""

    __tablename__ = "detection_versions"

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    changed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    changed_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    changed_by_name: Mapped[Optional[str]] = mapped_column(String(200))
    change_reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    changes: Mapped[dict] = mapped_column(JSONB, nullable=False)


class DetectionTechnique(CustomerBase):
    """Many-to-many: a detection covers one or more ATT&CK techniques.

    technique_id is the bare string (e.g. T1059.001) — we don't FK into the
    public attack_techniques table because customer schemas should be
    self-contained for portability. The catalog is treated as a reference
    universe, not a constraint.
    """
    __tablename__ = "detection_techniques"
    __table_args__ = (
        UniqueConstraint("detection_id", "technique_id", name="uq_det_tech"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")

    detection: Mapped[Detection] = relationship(back_populates="technique_mappings")


class DetectionReviewEvent(CustomerBase):
    """Append-only audit trail for the detection review lifecycle.

    Kept separate from the detection row so a rule that cycles through
    draft -> in review -> changes requested -> in review -> approved keeps
    every decision and note. `action` is string-validated by the service,
    matching the forward-compatible pattern used by the CMF tables.
    """
    __tablename__ = "detection_review_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    from_status: Mapped[str] = mapped_column(String(20), nullable=False)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text)
    actor_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Connector(CustomerBase):
    """A SIEM/EDR connector configuration. Credentials in `encrypted_config`
    are Fernet-encrypted at the application layer — never plain text on disk.
    Live sync is explicit Phase-8+ future work; `status` defaults to
    'planned' and `test` is a stub that says so."""
    __tablename__ = "connectors"
    __table_args__ = (
        UniqueConstraint("kind", "label", name="uq_connector_kind_label"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    encrypted_config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="planned", nullable=False)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_test_message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class DeployedUseCase(CustomerBase):
    """A detection use-case actually deployed in the customer's SIEM.

    Distinct from `detections` (analyst-authored / SigmaHQ-derived rules):
    these are read-only snapshots of what is *running in production*, pulled
    either live from the connector's API or from an uploaded CSV export. We
    keep them in their own table so SIEM reality never mutates the curated
    Sigma catalog or its source-provenance semantics.

    `external_id` is the SIEM's own rule identifier; the (connector_id,
    external_id) uniqueness makes re-import idempotent — a second sync
    updates rows in place rather than duplicating them.
    """
    __tablename__ = "deployed_use_cases"
    __table_args__ = (
        UniqueConstraint("connector_id", "external_id", name="uq_deployed_uc_conn_ext"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # How this row arrived: 'api' (live fetch) or 'csv' (uploaded export).
    import_source: Mapped[str] = mapped_column(String(10), nullable=False, default="api")
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    query: Mapped[Optional[str]] = mapped_column(Text)
    # ATT&CK technique IDs parsed out of the rule (tags / annotations / text).
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class DetectionDeploymentLink(CustomerBase):
    """Analyst decision linking a curated detection to a deployed SIEM rule.

    The verified-coverage engine infers matches from Sigma IDs and titles at
    read time. That heuristic is useful but deliberately conservative; this
    table lets an analyst confirm a match (including one the heuristic would
    miss) or reject a false positive without mutating either source row.
    """
    __tablename__ = "detection_deployment_links"
    __table_args__ = (
        UniqueConstraint(
            "detection_id",
            "deployed_use_case_id",
            name="uq_detection_deployment_link",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    deployed_use_case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("deployed_use_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # 'confirmed' counts the pair as verified evidence; 'rejected' suppresses
    # a heuristic match. No row means "use the automatic heuristic".
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text)
    created_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    updated_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class CoverageSnapshot(CustomerBase):
    """Point-in-time roll-up of coverage posture for audit history & reports."""
    __tablename__ = "coverage_snapshots"

    id: Mapped[uuid.UUID] = uuid_pk()
    taken_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    denominator_kind: Mapped[str] = mapped_column(String(20), nullable=False)  # full/sector/apt
    denominator_ref: Mapped[Optional[str]] = mapped_column(String(80))  # e.g. apt29, finance
    breadth_score: Mapped[str] = mapped_column(String(2), nullable=False)  # A..B
    depth_score: Mapped[str] = mapped_column(String(2), nullable=False)    # A..D
    posture_grade: Mapped[str] = mapped_column(String(2), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)


class SavedView(CustomerBase):
    """Persisted filter/denominator preset for matrix or detections pages.

    `kind` namespaces views by page so two pages can each have a "default"
    view without colliding. `payload` is opaque JSON the frontend round-trips.
    """
    __tablename__ = "saved_views"
    __table_args__ = (
        UniqueConstraint("kind", "name", name="uq_saved_view_kind_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class DetectionOutcome(CustomerBase):
    """An analyst-reported event outcome for a detection (FP/TP/unsure).

    The aggregate of these rows feeds the detection effectiveness ratio
    shown next to score_depth in the detection drawer.
    """
    __tablename__ = "detection_outcomes"

    id: Mapped[uuid.UUID] = uuid_pk()
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # tp|fp|unsure
    summary: Mapped[Optional[str]] = mapped_column(Text)
    reference_url: Mapped[Optional[str]] = mapped_column(String(500))
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DetectionEventSample(CustomerBase):
    """A unit-test event for a Sigma detection.

    `kind` is positive (event SHOULD match) or negative (should NOT). The
    test runner re-evaluates samples on rule save and stores last result on
    the row so the UI can show pass/fail per sample.
    """
    __tablename__ = "detection_event_samples"

    id: Mapped[uuid.UUID] = uuid_pk()
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # positive|negative
    event: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    expected_match: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_run_pass: Mapped[Optional[bool]] = mapped_column(Boolean)
    last_run_message: Mapped[Optional[str]] = mapped_column(Text)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TechniqueNote(CustomerBase):
    """Per-tenant free-text annotation against an ATT&CK technique.

    One note per (technique_id, domain). Used by the coverage-matrix drawer
    for analyst notes — rationale for `not_applicable`, references to
    compensating controls, etc.
    """
    __tablename__ = "technique_notes"
    __table_args__ = (
        UniqueConstraint("technique_id", "domain", name="uq_tech_note_id_domain"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class GapComment(CustomerBase):
    """Thread of analyst comments on a gap (uncovered ATT&CK technique).

    Multiple rows per (technique_id, domain) so analysts can pile on
    observations during a triage. Distinct from `technique_notes` (one
    canonical note per technique) — comments are conversational, notes are
    declarative state about the technique.
    """
    __tablename__ = "gap_comments"

    id: Mapped[uuid.UUID] = uuid_pk()
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class GapIgnore(CustomerBase):
    """Documented decision to accept a gap and suppress it from the ranking.

    One active row per (technique_id, domain). The default top-gaps view
    filters these out so the analyst's daily backlog isn't cluttered by
    decisions already taken. If `ignored_until` is set, the ignore expires
    at that date and the gap re-surfaces — handy for "deferred to Q3"
    decisions that need a re-review.
    """
    __tablename__ = "gap_ignores"
    __table_args__ = (
        UniqueConstraint(
            "technique_id", "domain", name="uq_gap_ignores_technique_domain"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    ignored_until: Mapped[Optional[datetime]] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# ---- Customer profile (Stage 1: assets + contacts + linkage) -------------


class Asset(CustomerBase):
    """A tenant asset: server, workstation, cloud resource, app, etc.

    Flat for v1 — no parent/child relations. Coverage roll-up per asset
    is computed at read time by joining through `asset_detections` →
    `detection_techniques` (no denormalised counter column to keep stale).
    """
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = uuid_pk()

    # Identity
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    os: Mapped[Optional[str]] = mapped_column(String(120))
    environment: Mapped[str] = mapped_column(
        String(20), default="production", nullable=False, index=True
    )
    location: Mapped[Optional[str]] = mapped_column(String(200))

    # Business context
    owner: Mapped[Optional[str]] = mapped_column(String(200))
    business_function: Mapped[Optional[str]] = mapped_column(String(200))
    # Collection Management Framework: functional/data-domain grouping
    # (endpoint, network, identity, cloud, …). Distinct from
    # `business_function` (free-text business unit). String for forward compat.
    cmf_category: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    criticality: Mapped[str] = mapped_column(
        String(12), default="medium", nullable=False, index=True
    )
    data_classification: Mapped[Optional[str]] = mapped_column(String(20))
    compliance_scope: Mapped[list] = mapped_column(
        JSONB, default=list, nullable=False
    )

    # Operational
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False, index=True
    )
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # Future CMDB import dedupe — unused today.
    external_id: Mapped[Optional[str]] = mapped_column(String(120))

    created_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    updated_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AssetDetection(CustomerBase):
    """Many-to-many: asset ↔ detection.

    Explicit linkage so an analyst can answer "what's covered for asset X?"
    against a curated map, not a tag-match heuristic. Cascade on either
    side cleans up the row.
    """
    __tablename__ = "asset_detections"
    __table_args__ = (
        UniqueConstraint("asset_id", "detection_id", name="uq_asset_detection"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetDataSource(CustomerBase):
    """A collection source attached to an asset — the Collection Management
    Framework (CMF) row.

    An asset (a host) emits *many* data sources (Security event logs,
    Sysmon, PowerShell logs, …), each with its own storage, retention, and
    quality. That's why this hangs off the asset rather than living on the
    asset row: one DC's three log feeds have three different retentions.

    `attack_data_source` + `attack_data_component` mirror ATT&CK's data-
    source vocabulary ("Process" / "Process Creation"); joined as
    "Source: Component" they match the strings in
    `public.attack_techniques.data_sources`, which is what lets Phase B
    compute visibility coverage (DeTT&CT). The five `*_q` columns are the
    DeTT&CT data-quality dimensions (0–5, NULL = unscored).

    Intelligence requirements ("what questions does this answer") and the
    IR-usage log ("where it was used in past incidents") are deliberately
    NOT here — they're their own tables in a later slice.
    """
    __tablename__ = "asset_data_sources"
    __table_args__ = (
        UniqueConstraint("asset_id", "name", name="uq_asset_data_source_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # What it is
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    attack_data_source: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    attack_data_component: Mapped[Optional[str]] = mapped_column(String(120))
    log_source: Mapped[Optional[str]] = mapped_column(
        String(200), comment="Sigma-style logsource, e.g. windows/security."
    )
    description: Mapped[Optional[str]] = mapped_column(Text)
    kill_chain_phase: Mapped[Optional[str]] = mapped_column(Text)
    follow_on_collection: Mapped[Optional[str]] = mapped_column(Text)

    # Where / how long it's stored
    storage_connector_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connectors.id", ondelete="SET NULL"),
        index=True,
    )
    storage_location: Mapped[Optional[str]] = mapped_column(
        String(200), comment="Index / table / path within the platform."
    )
    retention_days: Mapped[Optional[int]] = mapped_column(Integer)

    # DeTT&CT data-quality dimensions (0–5; NULL = unscored)
    device_completeness_q: Mapped[Optional[int]] = mapped_column(Integer)
    data_field_completeness_q: Mapped[Optional[int]] = mapped_column(Integer)
    timeliness_q: Mapped[Optional[int]] = mapped_column(Integer)
    consistency_q: Mapped[Optional[int]] = mapped_column(Integer)
    retention_q: Mapped[Optional[int]] = mapped_column(Integer)

    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)

    created_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    updated_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class CustomerContact(CustomerBase):
    """Emergency contact for the customer (security ops, exec sponsor,
    on-call rotation, …). Surfaced in the customer profile."""
    __tablename__ = "customer_contacts"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    role: Mapped[Optional[str]] = mapped_column(String(120))
    email: Mapped[Optional[str]] = mapped_column(String(320))
    phone: Mapped[Optional[str]] = mapped_column(String(60))
    office_address: Mapped[Optional[str]] = mapped_column(Text)
    is_primary: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class CustomerDiagram(CustomerBase):
    """A network / topology diagram attached to the customer profile.

    Bytes live on the filesystem under `DIAGRAM_STORAGE_ROOT`; the row
    holds only metadata + the relative `stored_path`. `kind` is
    denormalised from `mime_type` at upload time so the frontend can
    pick an inline renderer (`image` / `pdf`) or fall back to a
    download link (`binary`) without re-parsing.
    """
    __tablename__ = "customer_diagrams"

    id: Mapped[uuid.UUID] = uuid_pk()
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(500), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    is_primary: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    uploaded_by_email: Mapped[Optional[str]] = mapped_column(String(320))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ---- Collection Management Framework: lifecycle (requirements → plan) -----
#
# The CMF is built the way an MSSP actually runs it:
#   1. Requirements — the *why*: collection/intel requirements developed from
#      TTX, risk management, threat modeling, incidents, compliance.
#   2. Collection plan — the *what*: the data sources to start collecting,
#      seeded (inherited) from gap/visibility analysis or added by hand.
#   3. Implementation — the *tracker*: each plan item walks an onboarding
#      status from proposed → validated. Plan + implementation are two views
#      of `collection_plan_items` (status is the tracker).
#
# String-validated (not DB enums) for forward compat, matching the asset
# module's convention.


class CollectionRequirement(CustomerBase):
    """A collection / intelligence requirement — the driver behind collection.

    Optionally scoped to ATT&CK techniques (or an APT group) so the plan can
    reason about which data sources would satisfy it.
    """
    __tablename__ = "collection_requirements"

    id: Mapped[uuid.UUID] = uuid_pk()
    title: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    # ttx | risk_management | threat_modeling | threat_intel | incident |
    # compliance | other
    driver: Mapped[str] = mapped_column(
        String(40), default="other", server_default="other", nullable=False, index=True
    )
    priority: Mapped[str] = mapped_column(
        String(12), default="medium", server_default="medium", nullable=False, index=True
    )
    # proposed | active | satisfied | archived
    status: Mapped[str] = mapped_column(
        String(20), default="proposed", server_default="proposed", nullable=False, index=True
    )
    attack_technique_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    apt_group_id: Mapped[Optional[str]] = mapped_column(String(20))
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class CollectionPlanItem(CustomerBase):
    """A planned data source to collect — the Collection Plan row and the
    Implementation tracker in one. Seeded from gap analysis (`source_kind=
    gap_seed`) or added manually; `status` walks the onboarding lifecycle.
    """
    __tablename__ = "collection_plan_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    # The ATT&CK data source / component to start collecting, e.g.
    # "Process Creation". Matches the `attack_techniques.data_sources` vocab.
    data_source: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    title: Mapped[Optional[str]] = mapped_column(String(200))
    rationale: Mapped[Optional[str]] = mapped_column(Text)
    requirement_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collection_requirements.id", ondelete="SET NULL"),
        index=True,
    )
    target_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(12), default="medium", server_default="medium", nullable=False, index=True
    )
    # Actual implemented source; status alone never establishes collection.
    asset_data_source_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asset_data_sources.id", ondelete="SET NULL"),
        index=True,
    )
    # proposed | approved | in_progress | collected | validated | deferred
    status: Mapped[str] = mapped_column(
        String(20), default="proposed", server_default="proposed", nullable=False, index=True
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(String(200))
    due_date: Mapped[Optional[datetime]] = mapped_column(Date)
    # Snapshot of how many in-scope techniques this source would illuminate,
    # captured at seed time so the plan stays meaningful without recomputing.
    technique_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # gap_seed | manual
    source_kind: Mapped[str] = mapped_column(
        String(12), default="manual", server_default="manual", nullable=False
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)
    author_email: Mapped[Optional[str]] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
