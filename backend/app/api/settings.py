"""Product + MSSP + customer settings: branding, catalog schedule, users.

Permission split:
  - MSSP branding & user list:    MSSP_ADMIN (scoped to caller's org)
  - Per-customer branding/legend: MSSP_ADMIN (with X-Customer)
  - Catalog refresh schedule + ATT&CK diffs: super admin (`current_super_admin`)
"""
from __future__ import annotations

import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from datetime import datetime, timezone

from app.api.deps import (
    TenantPrincipal,
    current_super_admin,
    current_tenant_user,
    require_active_customer,
    require_perm,
)
from app.config import settings as app_config
from app.core.rbac import Permission
from app.core.security import hash_password
from app.db.base import AsyncSessionLocal
from app.models.public import (
    AppSettings,
    AttackCatalogVersion,
    AuditLog,
    Customer,
    CustomerStatus,
    MSSPOrg,
    Role,
    ScheduledJobRun,
    SuperAdmin,
    User,
)
from app.services import deployment
from app.services.roles import user_has_permission

router = APIRouter(prefix="/settings", tags=["settings"])

# MSSP-portal user roles managed under /settings/users. Customer-pinned
# users (`customer_user`) are managed per-customer under /customers/{cn}/users
# so analysts don't have to scroll past tenant users to find the MSSP roster.
_MSSP_PORTAL_ROLES = {"mssp_admin", "mssp_analyst", "mssp_readonly"}
_MSSP_ROLES_ALL = _MSSP_PORTAL_ROLES | {"customer_user"}


async def _record_audit(
    session,
    *,
    actor_email: Optional[str],
    actor_kind: str,
    action: str,
    target: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Append an audit-log row. Caller commits the surrounding transaction."""
    session.add(
        AuditLog(
            id=uuid.uuid4(),
            actor_email=actor_email,
            actor_kind=actor_kind,
            action=action,
            target=target,
            detail=detail,
            at=datetime.now(timezone.utc),
        )
    )


# ---- Environment and sample data -----------------------------------------

class EnvironmentOption(BaseModel):
    codename: str
    name: str
    is_sample: bool


class EnvironmentSettingsOut(BaseModel):
    mode: Literal["multi_tenant"] = "multi_tenant"
    sample_data_enabled: bool
    primary_customer: None = None
    active_customer: None = None
    initial_customer: str | None
    environments: list[EnvironmentOption]
    can_edit: bool


class EnvironmentSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["multi_tenant"] | None = None
    sample_data_enabled: bool | None = None
    primary_customer: None = None


def _environment_out(org: MSSPOrg, workspaces: list[Customer], can_edit: bool) -> EnvironmentSettingsOut:
    scope = deployment.DeploymentScope.from_org(org)
    visible = [
        customer for customer in workspaces
        if customer.status == CustomerStatus.ACTIVE and scope.permits(customer)
    ]
    initial_customer = None
    if len(visible) == 1:
        initial_customer = visible[0].codename
    elif all(customer.sample_dataset for customer in visible):
        initial_customer = next(
            (customer.codename for customer in visible if customer.sample_dataset == "acme"), None,
        )
    return EnvironmentSettingsOut(
        sample_data_enabled=scope.sample_data_enabled,
        initial_customer=initial_customer,
        environments=[
            EnvironmentOption(codename=c.codename, name=c.name, is_sample=c.sample_dataset is not None)
            for c in visible
        ],
        can_edit=can_edit,
    )


async def _can_edit_environment(principal: TenantPrincipal) -> bool:
    return principal.user.role == Role.MSSP_ADMIN and await user_has_permission(
        principal.user, Permission.CUSTOMER_PROVISION
    )


@router.get("/mssp/environment", response_model=EnvironmentSettingsOut)
async def get_environment_settings(
    principal: TenantPrincipal = Depends(current_tenant_user),
) -> EnvironmentSettingsOut:
    if principal.user.role == Role.CUSTOMER_USER:
        raise HTTPException(403, "Environment settings are for dashboard staff.")
    can_edit = await _can_edit_environment(principal)
    async with AsyncSessionLocal() as session:
        org = await deployment.get_org(session, principal.user.mssp_org_id)
        if org is None:
            raise HTTPException(403, "User has no MSSP org")
        return _environment_out(org, await deployment.list_workspaces(session, org.id), can_edit)


@router.patch("/mssp/environment", response_model=EnvironmentSettingsOut)
async def patch_environment_settings(
    payload: EnvironmentSettingsPatch,
    principal: TenantPrincipal = Depends(current_tenant_user),
) -> EnvironmentSettingsOut:
    if not await _can_edit_environment(principal):
        raise HTTPException(403, "Only a dashboard administrator can change environment settings.")
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = await deployment.get_org(session, principal.user.mssp_org_id, for_update=True)
            if org is None:
                raise HTTPException(403, "User has no MSSP org")
            workspaces = await deployment.configure(session, org, sample_data_enabled=payload.sample_data_enabled)
            response = _environment_out(org, workspaces, can_edit=True)
            await _record_audit(
                session,
                actor_email=principal.user.email,
                actor_kind="user",
                action="deployment_settings_update",
                target=str(org.id),
                detail=f"sample_data={response.sample_data_enabled}",
            )
        return response


# ---- MSSP branding -------------------------------------------------------

class BrandingPayload(BaseModel):
    display_name: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    extra: Optional[dict] = None


class MSSPBrandingOut(BaseModel):
    mssp_org_id: str
    mssp_org_name: str
    branding: dict


@router.get("/mssp/branding", response_model=MSSPBrandingOut)
async def get_mssp_branding(
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> MSSPBrandingOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(
                select(MSSPOrg).where(MSSPOrg.id == principal.user.mssp_org_id)
            )
        ).scalar_one()
    return MSSPBrandingOut(
        mssp_org_id=str(org.id),
        mssp_org_name=org.name,
        branding=dict(org.branding or {}),
    )


@router.patch("/mssp/branding", response_model=MSSPBrandingOut)
async def patch_mssp_branding(
    payload: BrandingPayload = Body(...),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PROVISION)  # MSSP admin permission
    ),
) -> MSSPBrandingOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(
                select(MSSPOrg).where(MSSPOrg.id == principal.user.mssp_org_id)
            )
        ).scalar_one()
        branding = dict(org.branding or {})
        for k, v in payload.model_dump(exclude_none=True).items():
            if k == "extra" and isinstance(v, dict):
                branding.update(v)
            else:
                branding[k] = v
        org.branding = branding
        await session.commit()
    return MSSPBrandingOut(
        mssp_org_id=str(org.id), mssp_org_name=org.name, branding=branding
    )


# ---- Customer branding (per-tenant legend overrides) ---------------------

class CustomerBrandingOut(BaseModel):
    customer_id: str
    codename: str
    name: str
    branding: dict


@router.get("/customer/branding", response_model=CustomerBrandingOut)
async def get_customer_branding(
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CustomerBrandingOut:
    c = principal.customer
    return CustomerBrandingOut(
        customer_id=str(c.id),
        codename=c.codename,
        name=c.name,
        branding=dict(c.branding or {}),
    )


@router.patch("/customer/branding", response_model=CustomerBrandingOut)
async def patch_customer_branding(
    payload: BrandingPayload = Body(...),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PROVISION)
    ),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> CustomerBrandingOut:
    async with AsyncSessionLocal() as session:
        c = (
            await session.execute(
                select(Customer).where(Customer.id == principal.customer.id)
            )
        ).scalar_one()
        branding = dict(c.branding or {})
        for k, v in payload.model_dump(exclude_none=True).items():
            if k == "extra" and isinstance(v, dict):
                branding.update(v)
            else:
                branding[k] = v
        c.branding = branding
        await session.commit()
        return CustomerBrandingOut(
            customer_id=str(c.id),
            codename=c.codename,
            name=c.name,
            branding=branding,
        )


# ---- User list (read-only for MSSP admin) --------------------------------

class UserOut(BaseModel):
    id: str
    email: str
    role: str
    customer_id: Optional[str]
    custom_role_id: Optional[str]
    custom_role_label: Optional[str]
    is_active: bool
    last_login_at: Optional[str]
    is_primary: bool = False


async def _primary_user_id(session, mssp_org_id) -> Optional[uuid.UUID]:
    """Earliest-created user in this MSSP org — the bootstrap-seeded
    primary admin. Locked against role/customer/custom-role edits and
    against deletion/deactivation so the org can't be left without an
    administrator (or with the primary admin re-purposed as a tenant user)."""
    row = (
        await session.execute(
            select(User.id)
            .where(User.mssp_org_id == mssp_org_id)
            .order_by(User.created_at.asc(), User.email.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return row


@router.get("/users", response_model=list[UserOut])
async def list_users(
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> list[UserOut]:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    from app.models.public import CustomRole

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(User)
                .where(
                    User.mssp_org_id == principal.user.mssp_org_id,
                    # Customer-pinned users live under the Customers page; this
                    # endpoint is the MSSP staff roster only.
                    User.role.in_(tuple(_MSSP_PORTAL_ROLES)),
                )
                .order_by(User.email)
            )
        ).scalars().all()
        # Look up custom-role labels in one round trip so the user list
        # can render the friendly name instead of a UUID.
        role_ids = {r.custom_role_id for r in rows if r.custom_role_id}
        labels: dict[str, str] = {}
        if role_ids:
            cr_rows = (
                await session.execute(
                    select(CustomRole.id, CustomRole.label).where(
                        CustomRole.id.in_(role_ids)
                    )
                )
            ).all()
            labels = {str(rid): label for rid, label in cr_rows}
        primary_id = await _primary_user_id(session, principal.user.mssp_org_id)
    return [
        UserOut(
            id=str(r.id),
            email=r.email,
            role=r.role.value,
            customer_id=str(r.customer_id) if r.customer_id else None,
            custom_role_id=str(r.custom_role_id) if r.custom_role_id else None,
            custom_role_label=labels.get(str(r.custom_role_id)) if r.custom_role_id else None,
            is_active=r.is_active,
            last_login_at=r.last_login_at.isoformat() if r.last_login_at else None,
            is_primary=(primary_id is not None and r.id == primary_id),
        )
        for r in rows
    ]


# ---- Catalog refresh schedule + ATT&CK diffs (super admin) ---------------

class ScheduledJobRunOut(BaseModel):
    job: str
    ran_at: str
    status: str
    detail: Optional[str]


class CatalogSettingsOut(BaseModel):
    attack_refresh_enabled: bool
    attack_refresh_cron: str
    sigmahq_refresh_enabled: bool
    sigmahq_refresh_cron: str
    d3fend_refresh_enabled: bool
    d3fend_refresh_cron: str
    snapshot_refresh_enabled: bool
    updated_at: str
    # Latest run per job name (attack | sigmahq | d3fend | snapshot), if fired.
    last_runs: dict[str, ScheduledJobRunOut] = {}


class CatalogSettingsPatch(BaseModel):
    attack_refresh_enabled: Optional[bool] = None
    attack_refresh_cron: Optional[str] = None
    sigmahq_refresh_enabled: Optional[bool] = None
    sigmahq_refresh_cron: Optional[str] = None
    d3fend_refresh_enabled: Optional[bool] = None
    d3fend_refresh_cron: Optional[str] = None
    snapshot_refresh_enabled: Optional[bool] = None


async def _get_or_create_settings(session) -> AppSettings:
    row = (await session.execute(select(AppSettings))).scalar_one_or_none()
    if row is None:
        row = AppSettings(singleton=True)
        session.add(row)
        await session.flush()
    return row


# ---- Sign-in page hint ---------------------------------------------------

class LoginHintSettingsOut(BaseModel):
    enabled: bool
    email: Optional[str]
    password: Optional[str]


class LoginHintSettingsPatch(BaseModel):
    enabled: bool


def _login_hint_settings_out(row: AppSettings) -> LoginHintSettingsOut:
    return LoginHintSettingsOut(
        enabled=row.show_login_hint,
        email=(app_config.default_login_email or "").strip() or None,
        password=app_config.default_login_password or None,
    )


@router.get("/login-hint", response_model=LoginHintSettingsOut)
async def get_login_hint_settings(
    _: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> LoginHintSettingsOut:
    """Current state of the sign-in credential hint."""
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        return _login_hint_settings_out(row)


@router.patch("/login-hint", response_model=LoginHintSettingsOut)
async def patch_login_hint_settings(
    payload: LoginHintSettingsPatch = Body(...),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PROVISION)
    ),
) -> LoginHintSettingsOut:
    """Show or hide the default credentials on the sign-in page."""
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        row.show_login_hint = payload.enabled
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="login_hint.update",
            detail=f"enabled={payload.enabled}",
        )
        await session.commit()
        await session.refresh(row)
        return _login_hint_settings_out(row)


async def _latest_runs(session) -> dict[str, "ScheduledJobRunOut"]:
    """Most-recent scheduled run per job name."""
    rows = (
        await session.execute(
            select(ScheduledJobRun).order_by(ScheduledJobRun.ran_at.desc())
        )
    ).scalars().all()
    out: dict[str, ScheduledJobRunOut] = {}
    for r in rows:
        if r.job in out:
            continue  # rows are newest-first, so first seen is latest
        out[r.job] = ScheduledJobRunOut(
            job=r.job,
            ran_at=r.ran_at.isoformat() if r.ran_at else "",
            status=r.status,
            detail=r.detail,
        )
    return out


def _settings_out(row: AppSettings, last_runs: dict) -> "CatalogSettingsOut":
    return CatalogSettingsOut(
        attack_refresh_enabled=row.attack_refresh_enabled,
        attack_refresh_cron=row.attack_refresh_cron,
        sigmahq_refresh_enabled=row.sigmahq_refresh_enabled,
        sigmahq_refresh_cron=row.sigmahq_refresh_cron,
        d3fend_refresh_enabled=row.d3fend_refresh_enabled,
        d3fend_refresh_cron=row.d3fend_refresh_cron,
        snapshot_refresh_enabled=row.snapshot_refresh_enabled,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
        last_runs=last_runs,
    )


@router.get("/catalog", response_model=CatalogSettingsOut)
async def get_catalog_settings(
    _: SuperAdmin = Depends(current_super_admin),
) -> CatalogSettingsOut:
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        runs = await _latest_runs(session)
        return _settings_out(row, runs)


@router.patch("/catalog", response_model=CatalogSettingsOut)
async def patch_catalog_settings(
    payload: CatalogSettingsPatch = Body(...),
    admin: SuperAdmin = Depends(current_super_admin),
) -> CatalogSettingsOut:
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        changed = payload.model_dump(exclude_none=True)
        for k, v in changed.items():
            setattr(row, k, v)
        await _record_audit(
            session,
            actor_email=admin.email,
            actor_kind="superadmin",
            action="catalog_schedule.update",
            detail="changed: " + ", ".join(sorted(changed.keys())) if changed else "no-op",
        )
        await session.commit()
        await session.refresh(row)
        runs = await _latest_runs(session)
        return _settings_out(row, runs)


class CatalogDiff(BaseModel):
    domain: str
    version: str
    ingested_at: str
    is_current: bool
    added: list[str]
    removed: list[str]
    deprecated: list[str]
    revived: list[str]
    revoked: list[str]
    renamed: list[dict]


@router.get("/attack-diffs", response_model=list[CatalogDiff])
async def list_attack_diffs(
    limit: int = 25,
    _: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[CatalogDiff]:
    """Recent ATT&CK release diffs. Any tenant user with COVERAGE_READ can
    see these — they are public ATT&CK metadata, no tenant secrets."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(AttackCatalogVersion)
                .order_by(AttackCatalogVersion.ingested_at.desc())
                .limit(limit)
            )
        ).scalars().all()
    out: list[CatalogDiff] = []
    for r in rows:
        diff = (r.summary or {}).get("diff") or {}
        out.append(
            CatalogDiff(
                domain=r.domain,
                version=r.version,
                ingested_at=r.ingested_at.isoformat() if r.ingested_at else "",
                is_current=r.is_current,
                added=diff.get("added") or [],
                removed=diff.get("removed") or [],
                deprecated=diff.get("deprecated") or [],
                revived=diff.get("revived") or [],
                revoked=diff.get("revoked") or [],
                renamed=diff.get("renamed") or [],
            )
        )
    return out


class AttackNotification(BaseModel):
    """A tenant-actionable ATT&CK release diff entry.

    Filters the global catalog diffs down to changes that *touch the
    tenant* — techniques the tenant has detections mapped to. Lets the
    UI show "you have 3 rules tied to T1xxx which is now deprecated"
    instead of dumping the full catalog churn on every login.
    """
    domain: str
    version: str
    ingested_at: str
    deprecated_in_use: list[str]
    revoked_in_use: list[str]
    renamed_in_use: list[dict]
    added: list[str]  # informational only; full added list capped
    summary: str


@router.get(
    "/attack-notifications", response_model=list[AttackNotification]
)
async def list_attack_notifications(
    limit: int = 5,
    principal: TenantPrincipal = Depends(require_perm(Permission.COVERAGE_READ)),
) -> list[AttackNotification]:
    """Recent ATT&CK release diffs filtered to ones that touch this tenant.

    Requires an active customer because the filter relies on the tenant's
    detection_techniques table.
    """
    from sqlalchemy import select as _select  # local to keep import surface tidy

    from app.db.tenant import tenant_session
    from app.models.customer import DetectionTechnique

    if principal.customer is None:
        # MSSP user without a tenant pick → can't personalise. Return empty.
        return []

    async with tenant_session() as session:
        tenant_tids = set(
            (
                await session.execute(_select(DetectionTechnique.technique_id))
            ).scalars().all()
        )

    if not tenant_tids:
        return []

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(AttackCatalogVersion)
                .order_by(AttackCatalogVersion.ingested_at.desc())
                .limit(limit)
            )
        ).scalars().all()

    out: list[AttackNotification] = []
    for r in rows:
        diff = (r.summary or {}).get("diff") or {}
        dep = [t for t in (diff.get("deprecated") or []) if t in tenant_tids]
        rev = [t for t in (diff.get("revoked") or []) if t in tenant_tids]
        ren = [
            n
            for n in (diff.get("renamed") or [])
            if isinstance(n, dict) and n.get("technique_id") in tenant_tids
        ]
        if not (dep or rev or ren):
            continue
        bits = []
        if dep:
            bits.append(f"{len(dep)} deprecated")
        if rev:
            bits.append(f"{len(rev)} revoked")
        if ren:
            bits.append(f"{len(ren)} renamed")
        out.append(
            AttackNotification(
                domain=r.domain,
                version=r.version,
                ingested_at=r.ingested_at.isoformat() if r.ingested_at else "",
                deprecated_in_use=dep,
                revoked_in_use=rev,
                renamed_in_use=ren,
                added=(diff.get("added") or [])[:20],
                summary=f"ATT&CK {r.domain} {r.version}: " + " · ".join(bits),
            )
        )
    return out


# ---- AI authoring config (MSSP-org scoped) -------------------------------

class AIConfigOut(BaseModel):
    provider: str
    model: str
    has_key: bool
    key_tail: Optional[str]
    last_used_at: Optional[str]
    last_status: Optional[str]


class AIConfigPatch(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    # If `api_key` is provided, replace the stored ciphertext. If
    # `clear_key=True`, wipe it. The plaintext key is NEVER returned by
    # any endpoint — only the last-four masked tail.
    api_key: Optional[str] = None
    clear_key: Optional[bool] = None


class AITestRequest(BaseModel):
    """Optional payload for the test-connection probe.

    If `api_key` is omitted, the stored key is used. If both `api_key`
    and `model` are provided, this is the "test before save" path used
    by the Settings form.
    """
    api_key: Optional[str] = None
    model: Optional[str] = None


class AITestResponse(BaseModel):
    ok: bool
    message: str
    model: Optional[str] = None


def _mask_tail(plain: str) -> Optional[str]:
    if not plain:
        return None
    return ("…" + plain[-4:]) if len(plain) >= 4 else "…" + plain


@router.get("/ai-config", response_model=AIConfigOut)
async def get_ai_config(
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_PROVISION)),
) -> AIConfigOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(
                select(MSSPOrg).where(MSSPOrg.id == principal.user.mssp_org_id)
            )
        ).scalar_one()
        tail: Optional[str] = None
        if org.ai_api_key_encrypted:
            try:
                from app.core.crypto import decrypt
                tail = _mask_tail(decrypt(org.ai_api_key_encrypted))
            except ValueError:
                tail = "(decryption failed)"
        return AIConfigOut(
            provider=org.ai_provider or "anthropic",
            model=org.ai_model or "claude-opus-4-7",
            has_key=bool(org.ai_api_key_encrypted),
            key_tail=tail,
            last_used_at=org.ai_last_used_at.isoformat() if org.ai_last_used_at else None,
            last_status=org.ai_last_status,
        )


@router.patch("/ai-config", response_model=AIConfigOut)
async def patch_ai_config(
    payload: AIConfigPatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_PROVISION)),
) -> AIConfigOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    from app.core.crypto import encrypt
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(
                select(MSSPOrg).where(MSSPOrg.id == principal.user.mssp_org_id)
            )
        ).scalar_one()
        if payload.provider is not None:
            org.ai_provider = payload.provider[:20] or "anthropic"
        if payload.model is not None:
            org.ai_model = payload.model[:80] or "claude-opus-4-7"
        if payload.clear_key:
            org.ai_api_key_encrypted = None
            org.ai_last_status = None
        elif payload.api_key:
            org.ai_api_key_encrypted = encrypt(payload.api_key)
            org.ai_last_status = "configured"
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="ai_config.update",
            detail=(
                "key cleared" if payload.clear_key
                else "key set" if payload.api_key
                else "model/provider updated"
            ),
        )
        await session.commit()
        await session.refresh(org)
        tail: Optional[str] = None
        if org.ai_api_key_encrypted:
            try:
                from app.core.crypto import decrypt
                tail = _mask_tail(decrypt(org.ai_api_key_encrypted))
            except ValueError:
                tail = "(decryption failed)"
        return AIConfigOut(
            provider=org.ai_provider,
            model=org.ai_model,
            has_key=bool(org.ai_api_key_encrypted),
            key_tail=tail,
            last_used_at=org.ai_last_used_at.isoformat() if org.ai_last_used_at else None,
            last_status=org.ai_last_status,
        )


@router.post("/ai-config/test", response_model=AITestResponse)
async def test_ai_config(
    payload: AITestRequest = Body(default_factory=lambda: AITestRequest()),
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_PROVISION)),
) -> AITestResponse:
    """Ping the AI provider with the supplied (or stored) credentials.

    Used by the "Test connection" button before saving a new key.
    """
    from app.core.crypto import decrypt
    from app.services.ai_sigma import AISigmaError, test_credentials

    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")

    api_key = payload.api_key
    model = payload.model
    if not api_key or not model:
        async with AsyncSessionLocal() as session:
            org = (
                await session.execute(
                    select(MSSPOrg).where(MSSPOrg.id == principal.user.mssp_org_id)
                )
            ).scalar_one()
            if not api_key:
                if not org.ai_api_key_encrypted:
                    raise HTTPException(
                        400, "No stored API key — supply one in the request body"
                    )
                try:
                    api_key = decrypt(org.ai_api_key_encrypted)
                except ValueError as e:
                    raise HTTPException(400, f"stored AI key could not be decrypted: {e}")
            if not model:
                model = org.ai_model or "claude-opus-4-7"

    try:
        r = await test_credentials(api_key, model)
    except AISigmaError as e:
        return AITestResponse(ok=False, message=str(e), model=model)
    return AITestResponse(ok=r.ok, message=r.message, model=r.model)


# ---- LDAP / Active Directory auth config (super admin) -------------------

_MSSP_ROLE_VALUES = {"mssp_admin", "mssp_analyst", "mssp_readonly"}


class LdapConfigOut(BaseModel):
    enabled: bool
    host: Optional[str]
    bind_dn: Optional[str]
    has_bind_password: bool
    bind_password_tail: Optional[str]
    user_search_base: Optional[str]
    user_filter: str
    email_attr: str
    full_name_attr: str
    default_role: str
    start_tls: bool
    verify_cert: bool
    group_attr: str
    group_mappings: dict
    updated_at: str


class LdapConfigPatch(BaseModel):
    enabled: Optional[bool] = None
    host: Optional[str] = None
    bind_dn: Optional[str] = None
    # Set the service-account password (stored Fernet-encrypted) or clear it.
    bind_password: Optional[str] = None
    clear_bind_password: Optional[bool] = None
    user_search_base: Optional[str] = None
    user_filter: Optional[str] = None
    email_attr: Optional[str] = None
    full_name_attr: Optional[str] = None
    default_role: Optional[str] = None
    start_tls: Optional[bool] = None
    verify_cert: Optional[bool] = None
    group_attr: Optional[str] = None
    # Map of group-identifier substring → role (mssp_*). Replaces the map.
    group_mappings: Optional[dict] = None


class LdapTestRequest(BaseModel):
    """Probe the directory. With username+password, verifies a full user
    bind; without, just checks the service-account/connection."""
    username: Optional[str] = None
    password: Optional[str] = None


class LdapTestResponse(BaseModel):
    ok: bool
    message: str


def _ldap_out(row: AppSettings) -> LdapConfigOut:
    tail: Optional[str] = None
    if row.ldap_bind_password_encrypted:
        try:
            from app.core.crypto import decrypt
            tail = _mask_tail(decrypt(row.ldap_bind_password_encrypted))
        except ValueError:
            tail = "(decryption failed)"
    return LdapConfigOut(
        enabled=row.ldap_enabled,
        host=row.ldap_host,
        bind_dn=row.ldap_bind_dn,
        has_bind_password=bool(row.ldap_bind_password_encrypted),
        bind_password_tail=tail,
        user_search_base=row.ldap_user_search_base,
        user_filter=row.ldap_user_filter,
        email_attr=row.ldap_email_attr,
        full_name_attr=row.ldap_full_name_attr,
        default_role=row.ldap_default_role,
        start_tls=row.ldap_start_tls,
        verify_cert=row.ldap_verify_cert,
        group_attr=row.ldap_group_attr,
        group_mappings=dict(row.ldap_group_mappings or {}),
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


@router.get("/ldap-config", response_model=LdapConfigOut)
async def get_ldap_config(_: SuperAdmin = Depends(current_super_admin)) -> LdapConfigOut:
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        return _ldap_out(row)


@router.patch("/ldap-config", response_model=LdapConfigOut)
async def patch_ldap_config(
    payload: LdapConfigPatch = Body(...),
    admin: SuperAdmin = Depends(current_super_admin),
) -> LdapConfigOut:
    from app.core.crypto import encrypt

    if payload.default_role is not None and payload.default_role not in _MSSP_ROLE_VALUES:
        raise HTTPException(
            422,
            f"default_role must be one of {sorted(_MSSP_ROLE_VALUES)} "
            "(LDAP users are MSSP staff)",
        )
    if payload.group_mappings is not None:
        bad = [r for r in payload.group_mappings.values() if r not in _MSSP_ROLE_VALUES]
        if bad:
            raise HTTPException(
                422, f"group mapping roles must be one of {sorted(_MSSP_ROLE_VALUES)}"
            )
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        simple = payload.model_dump(
            exclude_none=True,
            exclude={"bind_password", "clear_bind_password"},
        )
        for k, v in simple.items():
            setattr(row, f"ldap_{k}", v)
        if payload.clear_bind_password:
            row.ldap_bind_password_encrypted = None
        elif payload.bind_password:
            row.ldap_bind_password_encrypted = encrypt(payload.bind_password)
        changed = sorted(simple.keys()) + (
            ["bind_password"] if payload.bind_password or payload.clear_bind_password else []
        )
        await _record_audit(
            session,
            actor_email=admin.email,
            actor_kind="superadmin",
            action="ldap_config.update",
            detail="changed: " + ", ".join(changed) if changed else "no-op",
        )
        await session.commit()
        await session.refresh(row)
        return _ldap_out(row)


@router.post("/ldap-config/test", response_model=LdapTestResponse)
async def test_ldap_config(
    payload: LdapTestRequest = Body(default_factory=lambda: LdapTestRequest()),
    _: SuperAdmin = Depends(current_super_admin),
) -> LdapTestResponse:
    from app.services import ldap_auth

    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        if not row.ldap_host:
            raise HTTPException(400, "Configure the LDAP host first")
        cfg = ldap_auth.settings_from_row(row)

    # Full user bind if creds supplied; otherwise just exercise the
    # service-account/connection path via a guaranteed-miss search.
    try:
        if payload.username and payload.password:
            identity = await ldap_auth.authenticate(cfg, payload.username, payload.password)
            if identity is None:
                return LdapTestResponse(ok=False, message="bind failed — bad username or password")
            who = identity.email or identity.dn
            return LdapTestResponse(ok=True, message=f"authenticated {who}")
        # connection-only probe
        await ldap_auth.authenticate(cfg, "__connectivity_probe__", "__none__")
        return LdapTestResponse(
            ok=True,
            message="connected (supply a username + password to verify a full user bind)",
        )
    except ldap_auth.LdapError as e:
        return LdapTestResponse(ok=False, message=str(e))


# ---- Outbound mail / SMTP config (super admin) ---------------------------

class MailConfigOut(BaseModel):
    enabled: bool
    host: Optional[str]
    port: int
    username: Optional[str]
    has_password: bool
    password_tail: Optional[str]
    from_address: Optional[str]
    from_name: str
    use_tls: bool
    use_ssl: bool
    updated_at: str


class MailConfigPatch(BaseModel):
    enabled: Optional[bool] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    # Set the SMTP password (stored Fernet-encrypted) or clear it.
    password: Optional[str] = None
    clear_password: Optional[bool] = None
    from_address: Optional[str] = None
    from_name: Optional[str] = None
    use_tls: Optional[bool] = None
    use_ssl: Optional[bool] = None


class MailTestRequest(BaseModel):
    """Send a test message. `to` defaults to the requesting admin's email."""
    to: Optional[str] = None


class MailTestResponse(BaseModel):
    ok: bool
    message: str


def _mail_out(row: AppSettings) -> MailConfigOut:
    tail: Optional[str] = None
    if row.mail_password_encrypted:
        try:
            from app.core.crypto import decrypt
            tail = _mask_tail(decrypt(row.mail_password_encrypted))
        except ValueError:
            tail = "(decryption failed)"
    return MailConfigOut(
        enabled=row.mail_enabled,
        host=row.mail_host,
        port=row.mail_port,
        username=row.mail_username,
        has_password=bool(row.mail_password_encrypted),
        password_tail=tail,
        from_address=row.mail_from_address,
        from_name=row.mail_from_name,
        use_tls=row.mail_use_tls,
        use_ssl=row.mail_use_ssl,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


@router.get("/mail-config", response_model=MailConfigOut)
async def get_mail_config(_: SuperAdmin = Depends(current_super_admin)) -> MailConfigOut:
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        return _mail_out(row)


@router.patch("/mail-config", response_model=MailConfigOut)
async def patch_mail_config(
    payload: MailConfigPatch = Body(...),
    admin: SuperAdmin = Depends(current_super_admin),
) -> MailConfigOut:
    from app.core.crypto import encrypt

    if payload.port is not None and not (1 <= payload.port <= 65535):
        raise HTTPException(422, "port must be between 1 and 65535")
    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        simple = payload.model_dump(
            exclude_none=True,
            exclude={"password", "clear_password"},
        )
        for k, v in simple.items():
            setattr(row, f"mail_{k}", v)
        if payload.clear_password:
            row.mail_password_encrypted = None
        elif payload.password:
            row.mail_password_encrypted = encrypt(payload.password)
        changed = sorted(simple.keys()) + (
            ["password"] if payload.password or payload.clear_password else []
        )
        await _record_audit(
            session,
            actor_email=admin.email,
            actor_kind="superadmin",
            action="mail_config.update",
            detail="changed: " + ", ".join(changed) if changed else "no-op",
        )
        await session.commit()
        await session.refresh(row)
        return _mail_out(row)


@router.post("/mail-config/test", response_model=MailTestResponse)
async def test_mail_config(
    payload: MailTestRequest = Body(default_factory=lambda: MailTestRequest()),
    admin: SuperAdmin = Depends(current_super_admin),
) -> MailTestResponse:
    """Send a test email with the stored SMTP config to verify it works."""
    from app.services import mail

    recipient = (payload.to or admin.email or "").strip()
    if not recipient:
        raise HTTPException(400, "no recipient — supply 'to' in the request body")

    async with AsyncSessionLocal() as session:
        row = await _get_or_create_settings(session)
        if not row.mail_host:
            raise HTTPException(400, "configure the SMTP host first")
        cfg = mail.settings_from_row(row)

    try:
        await mail.send_email(
            cfg,
            recipient,
            "The Detection Map — test email",
            "This is a test message from The Detection Map. Your SMTP "
            "configuration is working.",
        )
    except mail.MailError as e:
        return MailTestResponse(ok=False, message=str(e))
    return MailTestResponse(ok=True, message=f"test email sent to {recipient}")


# ---- User management (MSSP admin, scoped to caller's org) ----------------

class UserCreate(BaseModel):
    email: str
    password: str
    role: str
    full_name: Optional[str] = None
    customer_id: Optional[str] = None
    # Optional custom-role override — when set, the user's effective
    # permissions come from the custom role instead of `role`'s built-in
    # grants. `role` is still required because it sets the user "kind"
    # (MSSP staff vs customer-pinned).
    custom_role_id: Optional[str] = None


class UserPatch(BaseModel):
    role: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    customer_id: Optional[str] = None
    password: Optional[str] = None
    # Pass a UUID string to set the override, or an empty string ("") to
    # clear it and revert the user to their built-in role.
    custom_role_id: Optional[str] = None


def _user_out(
    u: User,
    custom_role_label: Optional[str] = None,
    is_primary: bool = False,
) -> UserOut:
    return UserOut(
        id=str(u.id),
        email=u.email,
        role=u.role.value,
        customer_id=str(u.customer_id) if u.customer_id else None,
        custom_role_id=str(u.custom_role_id) if u.custom_role_id else None,
        custom_role_label=custom_role_label,
        is_active=u.is_active,
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
        is_primary=is_primary,
    )


async def _resolve_custom_role(
    session, mssp_org_id, custom_role_id: Optional[str]
):
    """Validate that the given custom role belongs to the caller's MSSP org.

    Empty string / None means "no override". Returns the (UUID, label) tuple
    or (None, None) when no override.
    """
    if not custom_role_id:
        return None, None
    from app.models.public import CustomRole

    try:
        cr_uuid = uuid.UUID(custom_role_id)
    except ValueError:
        raise HTTPException(422, "invalid custom_role_id")
    row = (
        await session.execute(
            select(CustomRole).where(
                CustomRole.id == cr_uuid,
                CustomRole.mssp_org_id == mssp_org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(422, "custom role not found in your organisation")
    return cr_uuid, row.label


async def _validate_customer_for_role(session, org_id, role: str, customer_id: Optional[str]):
    """customer_user requires a customer_id in the caller's org; MSSP roles must not have one."""
    if role == "customer_user":
        if not customer_id:
            raise HTTPException(422, "customer_user requires a customer_id")
        scope = await deployment.load_scope(session, org_id)
        cust = (
            await session.execute(
                select(Customer).where(
                    Customer.id == uuid.UUID(customer_id),
                    Customer.mssp_org_id == org_id,
                    scope.customer_filter(),
                )
            )
        ).scalar_one_or_none()
        if cust is None:
            raise HTTPException(422, "customer not found in your organisation")
        return uuid.UUID(customer_id)
    return None


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    payload: UserCreate = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> UserOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    if payload.role not in _MSSP_PORTAL_ROLES:
        raise HTTPException(
            422,
            f"role must be one of {sorted(_MSSP_PORTAL_ROLES)} — "
            "customer_user accounts are created under the customer's page",
        )
    if len(payload.password) < 8:
        raise HTTPException(422, "password must be at least 8 characters")
    org_id = principal.user.mssp_org_id
    async with AsyncSessionLocal() as session:
        dupe = (
            await session.execute(select(User).where(User.email == payload.email.lower()))
        ).scalar_one_or_none()
        if dupe is not None:
            raise HTTPException(409, "a user with that email already exists")
        customer_uuid = await _validate_customer_for_role(
            session, org_id, payload.role, payload.customer_id
        )
        custom_uuid, custom_label = await _resolve_custom_role(
            session, org_id, payload.custom_role_id
        )
        user = User(
            id=uuid.uuid4(),
            email=payload.email.lower(),
            hashed_password=hash_password(payload.password),
            auth_source="local",
            full_name=payload.full_name,
            role=Role(payload.role),
            is_active=True,
            mssp_org_id=org_id,
            customer_id=customer_uuid,
            custom_role_id=custom_uuid,
        )
        session.add(user)
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="user.create",
            target=payload.email.lower(),
            detail=(
                f"role={payload.role}"
                + (f" custom_role={custom_label}" if custom_label else "")
            ),
        )
        await session.commit()
        await session.refresh(user)
        # New users are never the primary admin — that's pinned to the
        # earliest-created user in the org, which by definition exists.
        return _user_out(user, custom_role_label=custom_label, is_primary=False)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    payload: UserPatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> UserOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    org_id = principal.user.mssp_org_id
    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(
                select(User).where(User.id == user_id, User.mssp_org_id == org_id)
            )
        ).scalar_one_or_none()
        if user is None:
            raise HTTPException(404, "user not found in your organisation")
        primary_id = await _primary_user_id(session, org_id)
        is_primary = primary_id is not None and user.id == primary_id
        if is_primary:
            # The bootstrap-seeded primary admin is locked against changes
            # that could lock the MSSP out of administration. Password +
            # full_name remain editable so the account can still be
            # rotated by the operator.
            locked_fields = [
                f
                for f in ("role", "is_active", "customer_id", "custom_role_id")
                if getattr(payload, f) is not None
            ]
            if locked_fields:
                raise HTTPException(
                    422,
                    "primary administrator cannot be modified "
                    f"({', '.join(locked_fields)}). "
                    "Create a separate user for any role changes.",
                )
        if payload.role is not None:
            if payload.role not in _MSSP_PORTAL_ROLES:
                raise HTTPException(
                    422,
                    f"role must be one of {sorted(_MSSP_PORTAL_ROLES)} — "
                    "to convert this account into a customer user, manage it "
                    "on the customer's page",
                )
            user.role = Role(payload.role)
        if payload.full_name is not None:
            user.full_name = payload.full_name
        if payload.is_active is not None:
            if user.id == principal.user.id and not payload.is_active:
                raise HTTPException(422, "you cannot deactivate your own account")
            user.is_active = payload.is_active
        if payload.customer_id is not None:
            user.customer_id = await _validate_customer_for_role(
                session, org_id, user.role.value, payload.customer_id
            )
        if payload.password:
            if len(payload.password) < 8:
                raise HTTPException(422, "password must be at least 8 characters")
            user.hashed_password = hash_password(payload.password)
            user.auth_source = "local"
        # Custom-role override: empty string clears it, a UUID sets it,
        # None (omitted from the patch) leaves it alone.
        custom_label_for_out: Optional[str] = None
        if payload.custom_role_id is not None:
            if payload.custom_role_id == "":
                user.custom_role_id = None
            else:
                cr_uuid, cr_label = await _resolve_custom_role(
                    session, org_id, payload.custom_role_id
                )
                user.custom_role_id = cr_uuid
                custom_label_for_out = cr_label
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="user.update",
            target=user.email,
            detail="changed: "
            + ", ".join(sorted(payload.model_dump(exclude_none=True).keys())),
        )
        await session.commit()
        await session.refresh(user)
        return _user_out(
            user, custom_role_label=custom_label_for_out, is_primary=is_primary
        )


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
):
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    if user_id == principal.user.id:
        raise HTTPException(422, "you cannot delete your own account")
    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(
                select(User).where(
                    User.id == user_id, User.mssp_org_id == principal.user.mssp_org_id
                )
            )
        ).scalar_one_or_none()
        if user is None:
            raise HTTPException(404, "user not found in your organisation")
        if user.role == Role.CUSTOMER_USER:
            # Customer-pinned users are managed under the Customers page —
            # forward the operator there so the audit trail is consistent.
            raise HTTPException(
                422,
                "delete customer users from the customer's page, not the "
                "MSSP staff settings",
            )
        primary_id = await _primary_user_id(session, principal.user.mssp_org_id)
        if primary_id is not None and user.id == primary_id:
            raise HTTPException(
                422, "primary administrator cannot be deleted"
            )
        email = user.email
        await session.delete(user)
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="user.delete",
            target=email,
        )
        await session.commit()
    from fastapi import Response
    return Response(status_code=204)


# ---- Audit log -----------------------------------------------------------

class AuditEntryOut(BaseModel):
    id: str
    actor_email: Optional[str]
    actor_kind: str
    action: str
    target: Optional[str]
    detail: Optional[str]
    at: str


@router.get("/audit", response_model=list[AuditEntryOut])
async def list_audit(
    limit: int = 100,
    _: TenantPrincipal = Depends(require_perm(Permission.AUDIT_READ)),
) -> list[AuditEntryOut]:
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(AuditLog).order_by(AuditLog.at.desc()).limit(min(limit, 500))
            )
        ).scalars().all()
    return [
        AuditEntryOut(
            id=str(r.id),
            actor_email=r.actor_email,
            actor_kind=r.actor_kind,
            action=r.action,
            target=r.target,
            detail=r.detail,
            at=r.at.isoformat() if r.at else "",
        )
        for r in rows
    ]


__all__ = ["router"]
