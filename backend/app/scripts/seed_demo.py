"""Seed demo data: a couple of customers and one user per role.

Idempotent — existing rows are left alone. Run inside the backend container:

    docker compose exec backend python -m app.scripts.seed_demo

Assumes `app.scripts.bootstrap` has already created the "Demo MSSP" org.
"""
from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import select

from app.core.security import hash_password
from app.db.base import AsyncSessionLocal
from app.models.public import Customer, CustomerStatus, MSSPOrg, Role, User
from app.services.provisioning import provision_customer


CUSTOMERS = [
    {"codename": "acme", "name": "Acme Industries", "sector": "Finance"},
    {"codename": "globex", "name": "Globex Corp", "sector": "Energy"},
]

USERS = [
    # MSSP-level users (no customer pin)
    {"email": "analyst@demo.local", "role": Role.MSSP_ANALYST, "customer": None},
    {"email": "readonly@demo.local", "role": Role.MSSP_READONLY, "customer": None},
    # Customer-scoped users (pinned via customer_id; X-Customer header ignored)
    {"email": "user@acme.local", "role": Role.CUSTOMER_USER, "customer": "acme"},
    {"email": "user@globex.local", "role": Role.CUSTOMER_USER, "customer": "globex"},
]

PASSWORD = "change-me"


async def _get_demo_org_id() -> uuid.UUID:
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(
                select(MSSPOrg).where(MSSPOrg.name == "Demo MSSP")
            )
        ).scalar_one_or_none()
    if org is None:
        raise SystemExit(
            "Demo MSSP not found — run `app.scripts.bootstrap` first."
        )
    return org.id


async def _ensure_customer(org_id: uuid.UUID, spec: dict) -> uuid.UUID:
    async with AsyncSessionLocal() as session:
        existing = (
            await session.execute(
                select(Customer).where(
                    Customer.mssp_org_id == org_id,
                    Customer.codename == spec["codename"],
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            print(f"  customer {spec['codename']:<8s} exists ({existing.status.value})")
            return existing.id
        customer = Customer(
            id=uuid.uuid4(),
            mssp_org_id=org_id,
            codename=spec["codename"],
            name=spec["name"],
            sector=spec["sector"],
            status=CustomerStatus.PROVISIONING,
        )
        session.add(customer)
        await session.commit()
        customer_id = customer.id

    print(f"  customer {spec['codename']:<8s} provisioning schema...")
    await provision_customer(spec["codename"], seed_global_rules=True)

    async with AsyncSessionLocal() as session:
        customer = (
            await session.execute(select(Customer).where(Customer.id == customer_id))
        ).scalar_one()
        customer.status = CustomerStatus.ACTIVE
        await session.commit()
    print(f"  customer {spec['codename']:<8s} active")
    return customer_id


async def _ensure_user(
    email: str,
    role: Role,
    org_id: uuid.UUID,
    customer_id: uuid.UUID | None,
) -> None:
    async with AsyncSessionLocal() as session:
        existing = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing is not None:
            print(f"  user {email:<24s} exists ({existing.role.value})")
            return
        session.add(
            User(
                id=uuid.uuid4(),
                email=email,
                hashed_password=hash_password(PASSWORD),
                role=role,
                mssp_org_id=org_id,
                customer_id=customer_id,
            )
        )
        await session.commit()
    pinned = f" pinned=customer_id={customer_id}" if customer_id else ""
    print(f"  user {email:<24s} added ({role.value}){pinned}")


async def run() -> None:
    org_id = await _get_demo_org_id()
    print(f"using mssp_org_id={org_id}")

    print("\ncustomers:")
    customer_ids: dict[str, uuid.UUID] = {}
    for spec in CUSTOMERS:
        customer_ids[spec["codename"]] = await _ensure_customer(org_id, spec)

    print("\nusers:")
    for u in USERS:
        customer_id = customer_ids[u["customer"]] if u["customer"] else None
        await _ensure_user(u["email"], u["role"], org_id, customer_id)

    print(f"\nseed complete. all demo passwords: {PASSWORD!r}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
