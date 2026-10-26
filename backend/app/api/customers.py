"""Customer management endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import (
    TenantPrincipal,
    current_tenant_user,
    require_perm,
)
from app.api.settings import _record_audit, _resolve_custom_role
from app.core.rbac import Permission
from app.core.security import hash_password
from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for
from app.models.public import Customer, CustomerStatus, CustomRole, Role, User
from app.services import customer_features
from app.services.provisioning import provision_customer

router = APIRouter(prefix="/customers", tags=["customers"])


class CustomerCreate(BaseModel):
    codename: str = Field(min_length=2, max_length=30, pattern=r"^[a-z][a-z0-9_]{1,29}$")
    name: str = Field(min_length=2, max_length=200)
    sector: Optional[str] = None


class CustomerPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=200)
    sector: Optional[str] = Field(default=None, max_length=80)
    status: Optional[CustomerStatus] = None


class CustomerOut(BaseModel):
    id: str
    codename: str
    name: str
    sector: Optional[str]
    status: str
    schema_name: str
    created_at: Optional[datetime] = None


def _serialize(c: Customer) -> CustomerOut:
    return CustomerOut(
        id=str(c.id),
        codename=c.codename,
        name=c.name,
        sector=c.sector,
        status=c.status.value,
        schema_name=schema_for(c.codename),
        created_at=c.created_at,
    )


# Permitted lifecycle transitions. PROVISIONING is set by create() only; once
# a tenant is ARCHIVED it is read-only — undo lives outside the API surface.
_ALLOWED_TRANSITIONS: dict[CustomerStatus, set[CustomerStatus]] = {
    CustomerStatus.PROVISIONING: {CustomerStatus.ACTIVE},
    CustomerStatus.ACTIVE: {CustomerStatus.SUSPENDED, CustomerStatus.ARCHIVED},
    CustomerStatus.SUSPENDED: {CustomerStatus.ACTIVE, CustomerStatus.ARCHIVED},
    CustomerStatus.ARCHIVED: set(),
}


@router.get("", response_model=list[CustomerOut])
async def list_customers(
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> list[CustomerOut]:
    async with AsyncSessionLocal() as session:
        if principal.user.role == Role.CUSTOMER_USER:
            # A customer user sees only their own customer.
            stmt = select(Customer).where(Customer.id == principal.user.customer_id)
        else:
            stmt = select(Customer).where(
                Customer.mssp_org_id == principal.user.mssp_org_id
            )
        rows = (await session.execute(stmt)).scalars().all()
        return [_serialize(c) for c in rows]


@router.post("", response_model=CustomerOut, status_code=201)
async def create_customer(
    payload: CustomerCreate,
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_PROVISION)),
) -> CustomerOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(400, "Caller has no MSSP org")

    async with AsyncSessionLocal() as session:
        existing = (
            await session.execute(
                select(Customer).where(
                    Customer.mssp_org_id == principal.user.mssp_org_id,
                    Customer.codename == payload.codename,
                )
            )
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Codename already used in this MSSP")

        customer = Customer(
            id=uuid.uuid4(),
            mssp_org_id=principal.user.mssp_org_id,
            codename=payload.codename,
            name=payload.name,
            sector=payload.sector,
            status=CustomerStatus.PROVISIONING,
        )
        session.add(customer)
        await session.commit()
        await session.refresh(customer)

    # Provisioning is synchronous here for v1; queue this onto Celery once
    # default-catalog copy (~3,300 rules) is wired up.
    await provision_customer(customer.codename)

    async with AsyncSessionLocal() as session:
        customer = (
            await session.execute(select(Customer).where(Customer.id == customer.id))
        ).scalar_one()
        customer.status = CustomerStatus.ACTIVE
        await session.commit()
        await session.refresh(customer)
        return _serialize(customer)


@router.get("/{codename}", response_model=CustomerOut)
async def get_customer(
    codename: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> CustomerOut:
    async with AsyncSessionLocal() as session:
        stmt = select(Customer).where(Customer.codename == codename)
        if principal.user.role == Role.CUSTOMER_USER:
            stmt = stmt.where(Customer.id == principal.user.customer_id)
        else:
            stmt = stmt.where(Customer.mssp_org_id == principal.user.mssp_org_id)
        customer = (await session.execute(stmt)).scalar_one_or_none()
        if customer is None:
            raise HTTPException(404, "Customer not found")
        return _serialize(customer)


@router.patch("/{codename}", response_model=CustomerOut)
async def patch_customer(
    codename: str,
    payload: CustomerPatch,
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_PROVISION)),
) -> CustomerOut:
    """Edit customer metadata or transition lifecycle status.

    Status transitions are restricted to the matrix in `_ALLOWED_TRANSITIONS`.
    ARCHIVED is terminal — un-archiving is a manual ops action, not a UI flow.
    """
    if principal.user.mssp_org_id is None:
        raise HTTPException(400, "Caller has no MSSP org")

    async with AsyncSessionLocal() as session:
        customer = (
            await session.execute(
                select(Customer).where(
                    Customer.codename == codename,
                    Customer.mssp_org_id == principal.user.mssp_org_id,
                )
            )
        ).scalar_one_or_none()
        if customer is None:
            raise HTTPException(404, "Customer not found")

        if payload.status is not None and payload.status != customer.status:
            allowed = _ALLOWED_TRANSITIONS.get(customer.status, set())
            if payload.status not in allowed:
                raise HTTPException(
                    409,
                    f"Cannot transition from {customer.status.value} to "
                    f"{payload.status.value}",
                )
            customer.status = payload.status

        if customer.status == CustomerStatus.ARCHIVED and (
            payload.name is not None or payload.sector is not None
        ):
            # Archived tenants are immutable apart from re-activation flows
            # we deliberately don't expose.
            raise HTTPException(409, "Archived customer is read-only")

        if payload.name is not None:
            customer.name = payload.name
        if payload.sector is not None:
            customer.sector = payload.sector or None

        await session.commit()
        await session.refresh(customer)
        return _serialize(customer)


# ---- Per-customer users (customer_user accounts pinned to this tenant) ----

class CustomerUserOut(BaseModel):
    id: str
    email: str
    role: str
    customer_id: str
    custom_role_id: Optional[str]
    custom_role_label: Optional[str]
    is_active: bool
    last_login_at: Optional[str]


class CustomerUserCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=8, max_length=256)
    full_name: Optional[str] = Field(default=None, max_length=200)
    custom_role_id: Optional[str] = None


class CustomerUserPatch(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=256)
    # Empty string clears the override and reverts to the built-in role.
    custom_role_id: Optional[str] = None


async def _load_customer_or_404(session, codename: str, org_id) -> Customer:
    row = (
        await session.execute(
            select(Customer).where(
                Customer.codename == codename,
                Customer.mssp_org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Customer not found")
    return row


def _customer_user_out(u: User, custom_role_label: Optional[str]) -> CustomerUserOut:
    return CustomerUserOut(
        id=str(u.id),
        email=u.email,
        role=u.role.value,
        customer_id=str(u.customer_id),
        custom_role_id=str(u.custom_role_id) if u.custom_role_id else None,
        custom_role_label=custom_role_label,
        is_active=u.is_active,
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
    )


@router.get("/{codename}/users", response_model=list[CustomerUserOut])
async def list_customer_users(
    codename: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> list[CustomerUserOut]:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(
            session, codename, principal.user.mssp_org_id
        )
        rows = (
            await session.execute(
                select(User)
                .where(
                    User.customer_id == customer.id,
                    User.role == Role.CUSTOMER_USER,
                )
                .order_by(User.email)
            )
        ).scalars().all()
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
    return [
        _customer_user_out(
            u,
            labels.get(str(u.custom_role_id)) if u.custom_role_id else None,
        )
        for u in rows
    ]


@router.post(
    "/{codename}/users", response_model=CustomerUserOut, status_code=201
)
async def create_customer_user(
    codename: str,
    payload: CustomerUserCreate = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> CustomerUserOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    org_id = principal.user.mssp_org_id
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(422, "email must contain '@'")
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(session, codename, org_id)
        if customer.status == CustomerStatus.ARCHIVED:
            raise HTTPException(409, "Archived customer is read-only")
        dupe = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if dupe is not None:
            raise HTTPException(409, "a user with that email already exists")
        custom_uuid, custom_label = await _resolve_custom_role(
            session, org_id, payload.custom_role_id
        )
        user = User(
            id=uuid.uuid4(),
            email=email,
            hashed_password=hash_password(payload.password),
            auth_source="local",
            full_name=payload.full_name,
            role=Role.CUSTOMER_USER,
            is_active=True,
            mssp_org_id=org_id,
            customer_id=customer.id,
            custom_role_id=custom_uuid,
        )
        session.add(user)
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="customer_user.create",
            target=email,
            detail=(
                f"customer={customer.codename}"
                + (f" custom_role={custom_label}" if custom_label else "")
            ),
        )
        await session.commit()
        await session.refresh(user)
    return _customer_user_out(user, custom_label)


@router.patch(
    "/{codename}/users/{user_id}", response_model=CustomerUserOut
)
async def update_customer_user(
    codename: str,
    user_id: uuid.UUID,
    payload: CustomerUserPatch = Body(...),
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
) -> CustomerUserOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    org_id = principal.user.mssp_org_id
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(session, codename, org_id)
        user = (
            await session.execute(
                select(User).where(
                    User.id == user_id,
                    User.customer_id == customer.id,
                    User.role == Role.CUSTOMER_USER,
                )
            )
        ).scalar_one_or_none()
        if user is None:
            raise HTTPException(404, "user not found for this customer")
        if payload.full_name is not None:
            user.full_name = payload.full_name
        if payload.is_active is not None:
            user.is_active = payload.is_active
        if payload.password:
            user.hashed_password = hash_password(payload.password)
            user.auth_source = "local"
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
        elif user.custom_role_id:
            # Fetch the existing label so the response stays informative.
            cr_label = (
                await session.execute(
                    select(CustomRole.label).where(
                        CustomRole.id == user.custom_role_id
                    )
                )
            ).scalar_one_or_none()
            custom_label_for_out = cr_label
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="customer_user.update",
            target=user.email,
            detail="changed: "
            + ", ".join(sorted(payload.model_dump(exclude_none=True).keys())),
        )
        await session.commit()
        await session.refresh(user)
    return _customer_user_out(user, custom_label_for_out)


@router.delete("/{codename}/users/{user_id}", status_code=204)
async def delete_customer_user(
    codename: str,
    user_id: uuid.UUID,
    principal: TenantPrincipal = Depends(require_perm(Permission.USER_MANAGE)),
):
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    org_id = principal.user.mssp_org_id
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(session, codename, org_id)
        user = (
            await session.execute(
                select(User).where(
                    User.id == user_id,
                    User.customer_id == customer.id,
                    User.role == Role.CUSTOMER_USER,
                )
            )
        ).scalar_one_or_none()
        if user is None:
            raise HTTPException(404, "user not found for this customer")
        email = user.email
        await session.delete(user)
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="customer_user.delete",
            target=email,
            detail=f"customer={customer.codename}",
        )
        await session.commit()
    return Response(status_code=204)


# ---- Per-customer feature toggles ----------------------------------------

class FeatureMetaOut(BaseModel):
    key: str
    label: str
    description: str
    default: bool
    category: str


class CustomerFeaturesOut(BaseModel):
    codename: str
    catalog: list[FeatureMetaOut]
    # Effective state (defaults merged with the customer's overrides).
    features: dict[str, bool]


class CustomerFeaturesPatch(BaseModel):
    features: dict[str, bool]


@router.get(
    "/{codename}/features", response_model=CustomerFeaturesOut
)
async def get_customer_features(
    codename: str,
    principal: TenantPrincipal = Depends(require_perm(Permission.CUSTOMER_READ)),
) -> CustomerFeaturesOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(
            session, codename, principal.user.mssp_org_id
        )
        effective = customer_features.normalise(customer.features)
    return CustomerFeaturesOut(
        codename=customer.codename,
        catalog=[FeatureMetaOut(**m) for m in customer_features.catalog()],
        features=effective,
    )


@router.patch(
    "/{codename}/features", response_model=CustomerFeaturesOut
)
async def patch_customer_features(
    codename: str,
    payload: CustomerFeaturesPatch = Body(...),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PROVISION)
    ),
) -> CustomerFeaturesOut:
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "Caller has no MSSP org")
    try:
        cleaned = customer_features.validate_patch(payload.features)
    except ValueError as e:
        raise HTTPException(422, str(e))
    async with AsyncSessionLocal() as session:
        customer = await _load_customer_or_404(
            session, codename, principal.user.mssp_org_id
        )
        if customer.status == CustomerStatus.ARCHIVED:
            raise HTTPException(409, "Archived customer is read-only")
        merged = dict(customer.features or {})
        merged.update(cleaned)
        customer.features = merged
        await _record_audit(
            session,
            actor_email=principal.user.email,
            actor_kind="user",
            action="customer.features",
            target=customer.codename,
            detail="set: " + ", ".join(f"{k}={v}" for k, v in cleaned.items()),
        )
        await session.commit()
        await session.refresh(customer)
        effective = customer_features.normalise(customer.features)
    return CustomerFeaturesOut(
        codename=customer.codename,
        catalog=[FeatureMetaOut(**m) for m in customer_features.catalog()],
        features=effective,
    )
