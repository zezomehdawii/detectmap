"""Public-schema (cross-tenant) models.

These live in the 'public' schema and are accessible regardless of which
customer schema is on search_path because public_metadata is bound to
schema='public' explicitly.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import PublicBase, enum_values, uuid_pk


class Role(str, enum.Enum):
    PRODUCT_SUPER_ADMIN = "product_super_admin"
    MSSP_ADMIN = "mssp_admin"
    MSSP_ANALYST = "mssp_analyst"
    MSSP_READONLY = "mssp_readonly"
    CUSTOMER_USER = "customer_user"


class CustomerStatus(str, enum.Enum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class MSSPOrg(PublicBase):
    __tablename__ = "mssp_orgs"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    branding: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # AI authoring config — Fernet-encrypted key, never returned to the client.
    ai_provider: Mapped[str] = mapped_column(String(20), default="anthropic", nullable=False)
    ai_api_key_encrypted: Mapped[Optional[str]] = mapped_column(Text)
    ai_model: Mapped[str] = mapped_column(String(80), default="claude-opus-4-7", nullable=False)
    ai_last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ai_last_status: Mapped[Optional[str]] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    customers: Mapped[list["Customer"]] = relationship(back_populates="mssp_org")
    users: Mapped[list["User"]] = relationship(back_populates="mssp_org")


class CustomRole(PublicBase):
    """Custom permission set defined by an MSSP admin within their org.

    Layers on top of the built-in `Role` enum: if a user has
    `custom_role_id` set, that role's permissions are used; otherwise the
    built-in grants apply. `permissions` is a JSON list of permission keys
    (e.g. ["detection:read", "coverage:read"]) validated against the
    Permission enum at write time.
    """
    __tablename__ = "custom_roles"
    __table_args__ = (
        UniqueConstraint("mssp_org_id", "key", name="uq_custom_role_org_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    mssp_org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.mssp_orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    permissions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Customer(PublicBase):
    __tablename__ = "customers"
    __table_args__ = (
        UniqueConstraint("mssp_org_id", "codename", name="uq_customer_org_codename"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    mssp_org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.mssp_orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    codename: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    sector: Mapped[Optional[str]] = mapped_column(String(80))
    status: Mapped[CustomerStatus] = mapped_column(
        SAEnum(CustomerStatus, name="customer_status", values_callable=enum_values),
        default=CustomerStatus.PROVISIONING,
        nullable=False,
    )
    branding: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Per-customer feature toggles. The allow-list of keys + default values
    # lives in `app/services/customer_features.py`; this column just holds
    # whatever the MSSP admin has overridden. Effective state is the merge
    # of (defaults | this map).
    features: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    mssp_org: Mapped[MSSPOrg] = relationship(back_populates="customers")
    users: Mapped[list["User"]] = relationship(back_populates="customer")

    @property
    def schema_name(self) -> str:
        return f"cust_{self.codename}"


class User(PublicBase):
    """Tenant users — MSSP staff and customer users.

    Constraints (enforced in service layer + check constraint):
      - MSSP roles (mssp_*) must have mssp_org_id set and customer_id NULL.
      - CUSTOMER_USER must have customer_id set; mssp_org_id is the parent MSSP.
      - PRODUCT_SUPER_ADMIN does not live here — see SuperAdmin model.
    """
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # Nullable: LDAP/AD users authenticate against the directory and have no
    # local password. `auth_source` records which path owns the account.
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255))
    auth_source: Mapped[str] = mapped_column(String(10), default="local", nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(200))
    role: Mapped[Role] = mapped_column(
        SAEnum(Role, name="user_role", values_callable=enum_values),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    mssp_org_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.mssp_orgs.id", ondelete="CASCADE"),
        index=True,
    )
    customer_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.customers.id", ondelete="CASCADE"),
        index=True,
    )
    # Optional custom-role override. When set, the user's effective
    # permissions come from this row instead of the built-in `role` enum
    # grants. SET NULL on delete so removing a custom role leaves the
    # user on their built-in role rather than orphaning them.
    custom_role_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.custom_roles.id", ondelete="SET NULL"),
        index=True,
    )

    # Forces the user into the change-password screen on next login.
    # Set when an admin (or the bootstrap script) generates a random
    # initial password; cleared on successful /auth/change-password.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    mssp_org: Mapped[Optional[MSSPOrg]] = relationship(back_populates="users")
    customer: Mapped[Optional[Customer]] = relationship(back_populates="users")
    custom_role: Mapped[Optional["CustomRole"]] = relationship(foreign_keys=[custom_role_id])


class UserPreferences(PublicBase):
    """Per-user UI preference blob (color mode, density, sidebar state, …).

    One row per user, created lazily on first write. The allow-list of
    keys + defaults lives in `app/services/user_prefs.py`; this column
    just stores whatever the user has set. Absence of a row means
    "all defaults".
    """
    __tablename__ = "user_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    prefs: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SuperAdmin(PublicBase):
    """Product Super Admin — manages the global catalog, MITRE, MSSPs.

    Separate table + separate JWT signing key isolates this blast radius
    from tenant auth: a leaked tenant JWT secret cannot mint super-admin tokens.
    """
    __tablename__ = "super_admins"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # See `User.must_change_password` — same semantics for super admins.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AttackCatalogVersion(PublicBase):
    """Tracks ingested ATT&CK STIX bundle versions across domains."""
    __tablename__ = "attack_catalog_versions"
    __table_args__ = (
        UniqueConstraint("domain", "version", name="uq_attack_domain_version"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)  # enterprise/ics/mobile
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AttackTechnique(PublicBase):
    """Flattened ATT&CK technique catalog — synced from STIX, shared across tenants."""
    __tablename__ = "attack_techniques"
    __table_args__ = (
        UniqueConstraint("domain", "technique_id", name="uq_attack_domain_tid"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # e.g. T1059.001
    parent_technique_id: Mapped[Optional[str]] = mapped_column(String(20), index=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    tactics: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    platforms: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    data_sources: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    raw_stix: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class AttackMitigation(PublicBase):
    """ATT&CK mitigation (STIX course-of-action), shared across tenants."""
    __tablename__ = "attack_mitigations"
    __table_args__ = (
        UniqueConstraint("domain", "mitigation_id", name="uq_attack_domain_mid"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    mitigation_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # e.g. M1040
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    raw_stix: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class AttackTechniqueMitigation(PublicBase):
    """Many-to-many: ATT&CK mitigation→technique relationship (STIX 'mitigates').

    No DB-level FK to technique/mitigation rows — the catalog can be stale, and
    we treat ATT&CK IDs as logical references (same pattern as
    customer.detection_techniques).
    """
    __tablename__ = "attack_technique_mitigations"
    __table_args__ = (
        UniqueConstraint(
            "domain", "technique_id", "mitigation_id", name="uq_attack_tech_mit"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    mitigation_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)


class AttackGroup(PublicBase):
    """ATT&CK intrusion-set (named adversary group, e.g. G0007 APT28)."""
    __tablename__ = "attack_groups"
    __table_args__ = (
        UniqueConstraint("domain", "group_id", name="uq_attack_domain_gid"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    group_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    aliases: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    raw_stix: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class AttackSoftware(PublicBase):
    """ATT&CK malware/tool (e.g. S0029 PsExec)."""
    __tablename__ = "attack_software"
    __table_args__ = (
        UniqueConstraint("domain", "software_id", name="uq_attack_domain_sid"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    software_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # malware|tool
    description: Mapped[Optional[str]] = mapped_column(Text)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    raw_stix: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class AttackGroupTechnique(PublicBase):
    """STIX 'uses' SRO: intrusion-set → attack-pattern."""
    __tablename__ = "attack_group_techniques"
    __table_args__ = (
        UniqueConstraint(
            "domain", "group_id", "technique_id", name="uq_attack_group_tech"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    group_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)


class AttackSoftwareTechnique(PublicBase):
    """STIX 'uses' SRO: malware/tool → attack-pattern."""
    __tablename__ = "attack_software_techniques"
    __table_args__ = (
        UniqueConstraint(
            "domain", "software_id", "technique_id", name="uq_attack_software_tech"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    software_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)


class AttackGroupSoftware(PublicBase):
    """STIX 'uses' SRO: intrusion-set → malware/tool (software a group uses).

    Used to expand APT-scoped denominators: group TTPs ∪ TTPs of groups' software.
    """
    __tablename__ = "attack_group_software"
    __table_args__ = (
        UniqueConstraint(
            "domain", "group_id", "software_id", name="uq_attack_group_software"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    group_id: Mapped[str] = mapped_column(String(20), nullable=False)
    software_id: Mapped[str] = mapped_column(String(20), nullable=False)


class GRCFramework(PublicBase):
    """A compliance/control framework (NIST CSF, ISO 27001, NCA ECC, …)."""
    __tablename__ = "grc_frameworks"

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(40))
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    controls: Mapped[list["GRCControl"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class GRCControl(PublicBase):
    """One control within a framework (e.g. NIST CSF PR.PS-04)."""
    __tablename__ = "grc_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_id", name="uq_grc_framework_control"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.grc_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_id: Mapped[str] = mapped_column(String(40), nullable=False)
    parent_control_id: Mapped[Optional[str]] = mapped_column(String(40))
    family: Mapped[Optional[str]] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    sort_order: Mapped[int] = mapped_column(default=0, nullable=False)

    framework: Mapped[GRCFramework] = relationship(back_populates="controls")
    technique_mappings: Mapped[list["GRCTechniqueMapping"]] = relationship(
        back_populates="control", cascade="all, delete-orphan"
    )
    mitigation_mappings: Mapped[list["GRCMitigationMapping"]] = relationship(
        back_populates="control", cascade="all, delete-orphan"
    )


class GRCTechniqueMapping(PublicBase):
    """Control ↔ ATT&CK technique. `source` tracks who owns the row."""
    __tablename__ = "grc_technique_mappings"
    __table_args__ = (
        UniqueConstraint("control_id", "technique_id", name="uq_grc_control_technique"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.grc_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    # 'seeded' rows may be overwritten on re-seed; 'user' rows are never touched.
    source: Mapped[str] = mapped_column(String(12), nullable=False, default="seeded", index=True)
    rationale: Mapped[Optional[str]] = mapped_column(Text)
    author: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    control: Mapped[GRCControl] = relationship(back_populates="technique_mappings")


class GRCMitigationMapping(PublicBase):
    """Control ↔ ATT&CK mitigation. Same source-tracking semantics as the
    technique mapping."""
    __tablename__ = "grc_mitigation_mappings"
    __table_args__ = (
        UniqueConstraint("control_id", "mitigation_id", name="uq_grc_control_mitigation"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("public.grc_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    mitigation_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(12), nullable=False, default="seeded")
    rationale: Mapped[Optional[str]] = mapped_column(Text)
    author: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    control: Mapped[GRCControl] = relationship(back_populates="mitigation_mappings")


class SectorProfile(PublicBase):
    """Curated sector → technique-ids mapping for the 'sector' denominator.

    Seeded with a small starter set from common ATT&CK industry guidance; an
    MSSP admin can extend or override per deployment.
    """
    __tablename__ = "sector_profiles"

    id: Mapped[uuid.UUID] = uuid_pk()
    sector: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class DefaultDetection(PublicBase):
    """Public-schema mirror of the SigmaHQ ruleset.

    Per provisioning we copy from here into `cust_<codename>.detections` with
    `source='global'` and `upstream_global_id=global_id`. Re-syncing SigmaHQ
    re-upserts these rows but never touches per-tenant `customized` / `custom`
    rules.
    """
    __tablename__ = "default_detections"

    id: Mapped[uuid.UUID] = uuid_pk()
    global_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    sigma_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    sigma_status: Mapped[Optional[str]] = mapped_column(String(32))
    level: Mapped[Optional[str]] = mapped_column(String(32))
    author: Mapped[Optional[str]] = mapped_column(String(200))
    sigma_references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    logsource: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    detection: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    falsepositives: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    source_path: Mapped[Optional[str]] = mapped_column(String(500))  # relative path inside SigmaHQ repo
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AppSettings(PublicBase):
    """Product-wide singleton settings row. `singleton=TRUE` PK enforces it."""
    __tablename__ = "app_settings"

    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True, default=True)
    attack_refresh_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attack_refresh_cron: Mapped[str] = mapped_column(String(80), default="0 4 * * 1", nullable=False)
    sigmahq_refresh_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sigmahq_refresh_cron: Mapped[str] = mapped_column(String(80), default="0 5 * * 1", nullable=False)
    d3fend_refresh_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    d3fend_refresh_cron: Mapped[str] = mapped_column(String(80), default="0 6 1 * *", nullable=False)
    # Periodic coverage snapshot capture across active customers (posture trend).
    snapshot_refresh_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    legend_overrides: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Show the configured default login credentials on the sign-in page.
    # Product-wide because the login screen has no tenant context; an MSSP
    # admin can switch it off once the bootstrap password has been rotated.
    show_login_hint: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- LDAP / Active Directory authentication (instance-wide) ---
    # When enabled, /auth/login falls through to an LDAP bind after local
    # auth fails, JIT-provisioning the user at `ldap_default_role`.
    ldap_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_host: Mapped[Optional[str]] = mapped_column(String(255))  # ldaps://dc.corp.local:636
    # Service account used to search the directory (search-then-bind). Optional:
    # without it we attempt a direct bind using the typed identifier (UPN).
    ldap_bind_dn: Mapped[Optional[str]] = mapped_column(String(500))
    ldap_bind_password_encrypted: Mapped[Optional[str]] = mapped_column(Text)  # Fernet
    ldap_user_search_base: Mapped[Optional[str]] = mapped_column(String(500))
    ldap_user_filter: Mapped[str] = mapped_column(
        String(300), default="(sAMAccountName={username})", nullable=False
    )
    ldap_email_attr: Mapped[str] = mapped_column(String(80), default="mail", nullable=False)
    ldap_full_name_attr: Mapped[str] = mapped_column(
        String(80), default="displayName", nullable=False
    )
    ldap_default_role: Mapped[str] = mapped_column(
        String(40), default="mssp_readonly", nullable=False
    )
    ldap_start_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_verify_cert: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Directory attribute holding group memberships, and a map of
    # group-identifier substring → role for auto role assignment on login.
    ldap_group_attr: Mapped[str] = mapped_column(String(80), default="memberOf", nullable=False)
    ldap_group_mappings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # --- Outbound mail / SMTP (instance-wide) ---
    # When enabled, the app can send mail (test messages now; report
    # delivery / notifications later). The SMTP password is Fernet-encrypted
    # at rest and never returned to the client.
    mail_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mail_host: Mapped[Optional[str]] = mapped_column(String(255))  # smtp.corp.local
    mail_port: Mapped[int] = mapped_column(default=587, nullable=False)
    mail_username: Mapped[Optional[str]] = mapped_column(String(320))
    mail_password_encrypted: Mapped[Optional[str]] = mapped_column(Text)  # Fernet
    mail_from_address: Mapped[Optional[str]] = mapped_column(String(320))
    mail_from_name: Mapped[str] = mapped_column(
        String(120), default="The Detection Map", nullable=False
    )
    # STARTTLS on a plaintext port (587); mutually exclusive with implicit SSL.
    mail_use_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Implicit TLS from connect (465).
    mail_use_ssl: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SigmaHQIngestRun(PublicBase):
    """Tracks SigmaHQ catalog sync runs (ref/commit + summary)."""
    __tablename__ = "sigmahq_ingest_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    ref: Mapped[str] = mapped_column(String(120), nullable=False)  # e.g. master, r2024-09-01
    commit_sha: Mapped[Optional[str]] = mapped_column(String(60))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class D3FENDTechnique(PublicBase):
    """D3FEND defensive technique (e.g. d3f:NetworkTrafficAnalysis)."""
    __tablename__ = "d3fend_techniques"

    id: Mapped[uuid.UUID] = uuid_pk()
    d3fend_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    definition: Mapped[Optional[str]] = mapped_column(Text)
    parent_d3fend_id: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    kind: Mapped[Optional[str]] = mapped_column(String(40))
    url: Mapped[Optional[str]] = mapped_column(String(500))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AttackTechniqueD3FEND(PublicBase):
    """ATT&CK technique ↔ D3FEND defensive technique mapping.

    `relation` carries the D3FEND ontology predicate (`d3f:detects`,
    `d3f:hardens`, `d3f:isolates`, …) so the UI can label the link.
    """
    __tablename__ = "attack_technique_d3fend"
    __table_args__ = (
        UniqueConstraint(
            "domain", "technique_id", "d3fend_id", "relation",
            name="uq_attack_d3fend",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain: Mapped[str] = mapped_column(String(20), nullable=False, default="enterprise")
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    d3fend_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    relation: Mapped[Optional[str]] = mapped_column(String(40))


class D3FENDIngestRun(PublicBase):
    """Tracks D3FEND catalog refresh runs."""
    __tablename__ = "d3fend_ingest_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_url: Mapped[Optional[str]] = mapped_column(String(500))
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AuditLog(PublicBase):
    """Append-only audit trail for admin/settings actions.

    Captures who changed sensitive configuration (LDAP, AI keys, schedule)
    and who managed users — important for a security/compliance product.
    """
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = uuid_pk()
    actor_email: Mapped[Optional[str]] = mapped_column(String(320), index=True)
    actor_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="user")  # user|superadmin
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target: Mapped[Optional[str]] = mapped_column(String(320))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class ScheduledJobRun(PublicBase):
    """Append-only history of celerybeat-fired refresh jobs.

    One row per fire; the Settings UI reads only the latest row per `job`.
    """
    __tablename__ = "scheduled_job_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    job: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    ran_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # ok|skipped|error
    detail: Mapped[Optional[str]] = mapped_column(Text)
