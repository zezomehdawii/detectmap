"""Auth endpoints.

POST /auth/login        — MSSP staff + customer users  (JWT signed with tenant secret)
POST /auth/superadmin   — Product Super Admins         (JWT signed with super-admin secret)
GET  /auth/me           — Current tenant principal     (debug / UI bootstrap)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import TenantPrincipal, current_tenant_user
from app.config import settings
from app.core.rbac import Permission
from app.core.security import (
    TokenAudience,
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.base import AsyncSessionLocal
from app.models.public import AppSettings, Customer, MSSPOrg, Role, SuperAdmin, User
from app.services import customer_features
from app.services.deployment import load_scope
from app.services.roles import user_has_permission

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_tenant_token(user: User) -> str:
    return create_access_token(
        subject=str(user.id),
        audience=TokenAudience.TENANT,
        claims={
            "role": user.role.value,
            "mssp_org_id": str(user.mssp_org_id) if user.mssp_org_id else None,
            "customer_id": str(user.customer_id) if user.customer_id else None,
        },
    )


async def _ldap_login(session, settings_row: AppSettings, req: "LoginRequest") -> User | None:
    """Attempt LDAP/AD auth; JIT-provision the user on first success.

    Returns the (active) User to log in, or None if LDAP didn't authenticate.
    Raises HTTPException(401) for resolvable-but-forbidden situations.
    """
    from app.services import ldap_auth

    cfg = ldap_auth.settings_from_row(settings_row)
    try:
        identity = await ldap_auth.authenticate(cfg, req.email, req.password)
    except ldap_auth.LdapError as e:
        # Connection/config problem — log server-side, stay generic to client.
        log.warning("LDAP auth error: %s", e)
        return None
    if identity is None:
        return None

    email = (identity.email or req.email).strip().lower()
    user = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()

    # Role from AD group membership if mappings are configured, else default.
    mapped = ldap_auth.map_groups_to_role(cfg, identity.groups)
    resolved_role = mapped or ldap_auth.resolve_default_role(cfg)

    if user is not None:
        # A local-only account must authenticate locally — never let an LDAP
        # bind grant access to a password account that happens to share an
        # email (protects the bootstrap admin from directory compromise).
        if user.auth_source != "ldap":
            log.warning("LDAP login refused for local account %s", email)
            raise HTTPException(401, "Invalid credentials")
        if not user.is_active:
            raise HTTPException(401, "Invalid credentials")
        # AD is authoritative for LDAP users: if group mapping resolved a
        # different role, propagate it on this login.
        if mapped and user.role.value != mapped:
            user.role = Role(mapped)
            log.info("LDAP user %s role updated to %s via group mapping", email, mapped)
        return user

    # JIT provisioning — attach to the sole MSSP org at the resolved role.
    org_ids = (await session.execute(select(MSSPOrg.id))).scalars().all()
    if len(org_ids) != 1:
        log.error("LDAP JIT provisioning needs exactly one MSSP org, found %d", len(org_ids))
        raise HTTPException(401, "Invalid credentials")
    role = Role(resolved_role)
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=None,
        auth_source="ldap",
        full_name=identity.full_name,
        role=role,
        is_active=True,
        mssp_org_id=org_ids[0],
        customer_id=None,
    )
    session.add(user)
    await session.flush()
    log.info("JIT-provisioned LDAP user %s as %s", email, role.value)
    return user


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # True when the account was created with a generated password and the
    # user has not yet rotated it. The frontend uses this to force the
    # change-password screen before any other navigation.
    must_change_password: bool = False


class MeResponse(BaseModel):
    user_id: str
    email: str
    role: str
    customer_codename: str | None
    customer_name: str | None
    mssp_org_id: str | None
    must_change_password: bool = False
    can_write_assets: bool = False


class LoginHintOut(BaseModel):
    """Public sign-in hint.

    Credentials are omitted entirely when an administrator has hidden the
    hint, so the response never leaks them by accident.
    """
    enabled: bool
    email: str | None = None
    password: str | None = None


@router.get("/login-hint", response_model=LoginHintOut)
async def login_hint() -> LoginHintOut:
    """Default credentials for the sign-in card, if the admin allows it.

    The values come from configuration (never the database). This is meant
    for fresh/demo installations; rotate the bootstrap password and switch
    the hint off in Settings before exposing the instance publicly.
    """
    async with AsyncSessionLocal() as session:
        row = (await session.execute(select(AppSettings))).scalar_one_or_none()
    if row is not None and not row.show_login_hint:
        return LoginHintOut(enabled=False)

    email = (settings.default_login_email or "").strip()
    password = settings.default_login_password or ""
    if not email or not password:
        return LoginHintOut(enabled=False)
    return LoginHintOut(enabled=True, email=email, password=password)


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest) -> TokenResponse:
    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(select(User).where(User.email == req.email))
        ).scalar_one_or_none()

        # 1) Local password auth (only for accounts that have a local password).
        local_ok = (
            user is not None
            and user.is_active
            and user.hashed_password
            and verify_password(req.password, user.hashed_password)
        )

        if not local_ok:
            # 2) Fall through to LDAP/AD if it's enabled and configured.
            settings_row = (
                await session.execute(select(AppSettings))
            ).scalar_one_or_none()
            if settings_row and settings_row.ldap_enabled and settings_row.ldap_host:
                user = await _ldap_login(session, settings_row, req)
            else:
                user = None

        if user is None:
            raise HTTPException(401, "Invalid credentials")

        # Per-customer toggle: an MSSP admin can suspend tenant-portal access
        # without deleting the user account. MSSP staff are unaffected.
        if user.role == Role.CUSTOMER_USER and user.customer_id is not None:
            customer = (
                await session.execute(
                    select(Customer).where(Customer.id == user.customer_id)
                )
            ).scalar_one_or_none()
            scope = await load_scope(session, user.mssp_org_id)
            if customer is None or customer.mssp_org_id != user.mssp_org_id or not scope.permits(customer):
                raise HTTPException(403, "This environment is unavailable in the current deployment mode.")
            if not customer_features.is_enabled(customer.features, "customer_portal"):
                raise HTTPException(
                    403,
                    "Customer portal access is disabled for this tenant. "
                    "Contact your MSSP administrator.",
                )

        user.last_login_at = datetime.now(timezone.utc)
        must_change = user.must_change_password
        await session.commit()
        return TokenResponse(
            access_token=_issue_tenant_token(user),
            must_change_password=must_change,
        )


@router.post("/superadmin", response_model=TokenResponse)
async def superadmin_login(req: LoginRequest) -> TokenResponse:
    async with AsyncSessionLocal() as session:
        admin = (
            await session.execute(
                select(SuperAdmin).where(SuperAdmin.email == req.email)
            )
        ).scalar_one_or_none()
        if admin is None or not admin.is_active or not verify_password(
            req.password, admin.hashed_password
        ):
            raise HTTPException(401, "Invalid credentials")
        token = create_access_token(
            subject=str(admin.id),
            audience=TokenAudience.SUPERADMIN,
        )
        return TokenResponse(
            access_token=token,
            must_change_password=admin.must_change_password,
        )


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password", status_code=204)
async def change_password(
    req: ChangePasswordRequest,
    principal: TenantPrincipal = Depends(current_tenant_user),
):
    """Self-service password change for tenant users.

    Refused for LDAP-sourced accounts — those rotate in the directory.
    """
    from fastapi import Response

    if principal.user.auth_source != "local" or not principal.user.hashed_password:
        raise HTTPException(
            400, "this account is managed by the directory — change the password there"
        )
    if not verify_password(req.current_password, principal.user.hashed_password):
        raise HTTPException(400, "current password is incorrect")
    if len(req.new_password) < 8:
        raise HTTPException(422, "new password must be at least 8 characters")
    if req.new_password == req.current_password:
        raise HTTPException(422, "new password must differ from the current password")

    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(select(User).where(User.id == principal.user.id))
        ).scalar_one()
        user.hashed_password = hash_password(req.new_password)
        # Clear the force-change flag — the user has now rotated the
        # bootstrap password, so subsequent logins land on the dashboard.
        user.must_change_password = False
        await session.commit()
    return Response(status_code=204)


@router.get("/me", response_model=MeResponse)
async def me(principal: TenantPrincipal = Depends(current_tenant_user)) -> MeResponse:
    return MeResponse(
        user_id=str(principal.user.id),
        email=principal.user.email,
        role=principal.user.role.value,
        customer_codename=principal.customer.codename if principal.customer else None,
        customer_name=principal.customer.name if principal.customer else None,
        mssp_org_id=(
            str(principal.user.mssp_org_id) if principal.user.mssp_org_id else None
        ),
        must_change_password=principal.user.must_change_password,
        can_write_assets=await user_has_permission(principal.user, Permission.ASSET_WRITE),
    )


# ---- /me/preferences -----------------------------------------------------
#
# Server-side persistence for per-user UI preferences (color mode, table
# density, sidebar collapse, …). The frontend keeps a localStorage cache
# for first-paint, then reconciles against the server on mount so prefs
# follow the user across browsers.

from app.models.public import UserPreferences  # noqa: E402
from app.services import user_prefs  # noqa: E402


class PrefMetaOut(BaseModel):
    key: str
    label: str
    description: str
    default: object
    choices: list[str]
    value_type: str


class PreferencesOut(BaseModel):
    catalog: list[PrefMetaOut]
    # Effective state — defaults merged with the user's stored overrides.
    preferences: dict


class PreferencesPatch(BaseModel):
    preferences: dict


@router.get("/me/preferences", response_model=PreferencesOut)
async def get_preferences(
    principal: TenantPrincipal = Depends(current_tenant_user),
) -> PreferencesOut:
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(
                select(UserPreferences).where(
                    UserPreferences.user_id == principal.user.id
                )
            )
        ).scalar_one_or_none()
        stored = row.prefs if row else {}
    return PreferencesOut(
        catalog=[PrefMetaOut(**m) for m in user_prefs.catalog()],
        preferences=user_prefs.normalise(stored),
    )


@router.patch("/me/preferences", response_model=PreferencesOut)
async def patch_preferences(
    payload: PreferencesPatch,
    principal: TenantPrincipal = Depends(current_tenant_user),
) -> PreferencesOut:
    try:
        cleaned = user_prefs.validate_patch(payload.preferences)
    except ValueError as e:
        raise HTTPException(422, str(e))
    async with AsyncSessionLocal() as session:
        async with session.begin():
            row = (
                await session.execute(
                    select(UserPreferences).where(
                        UserPreferences.user_id == principal.user.id
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                row = UserPreferences(
                    user_id=principal.user.id, prefs=cleaned
                )
                session.add(row)
            else:
                merged = dict(row.prefs or {})
                merged.update(cleaned)
                row.prefs = merged
        # row is bound to the closed transaction — refetch to read .prefs
        # back after the on-insert default kicked in.
        row = (
            await session.execute(
                select(UserPreferences).where(
                    UserPreferences.user_id == principal.user.id
                )
            )
        ).scalar_one()
        stored = row.prefs
    return PreferencesOut(
        catalog=[PrefMetaOut(**m) for m in user_prefs.catalog()],
        preferences=user_prefs.normalise(stored),
    )
