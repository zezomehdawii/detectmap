"""Bootstrap script: seed first MSSP org, MSSP admin, and super admin.

Run inside the backend container:
    docker compose exec backend python -m app.scripts.bootstrap \
        --mssp-name "Acme MSSP" \
        --admin-email admin@acme.example \
        --admin-password change-me \
        --super-email super@detectmap.example \
        --super-password change-me

Idempotent: existing rows are left untouched, password is NOT updated.
"""
from __future__ import annotations

import argparse
import asyncio
import uuid
from typing import Optional

from sqlalchemy import select

from app.core.security import hash_password
from app.db.base import AsyncSessionLocal
from app.models.public import MSSPOrg, Role, SuperAdmin, User


async def _get_or_create_mssp(session, name: str) -> MSSPOrg:
    existing = (
        await session.execute(select(MSSPOrg).where(MSSPOrg.name == name))
    ).scalar_one_or_none()
    if existing:
        return existing
    org = MSSPOrg(id=uuid.uuid4(), name=name)
    session.add(org)
    await session.flush()
    return org


async def _get_or_create_user(
    session,
    email: str,
    password: str,
    role: Role,
    mssp_org_id: Optional[uuid.UUID],
) -> User:
    existing = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if existing:
        return existing
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=hash_password(password),
        role=role,
        mssp_org_id=mssp_org_id,
    )
    session.add(user)
    await session.flush()
    return user


async def _get_or_create_super(session, email: str, password: str) -> SuperAdmin:
    existing = (
        await session.execute(select(SuperAdmin).where(SuperAdmin.email == email))
    ).scalar_one_or_none()
    if existing:
        return existing
    sa = SuperAdmin(
        id=uuid.uuid4(),
        email=email,
        hashed_password=hash_password(password),
    )
    session.add(sa)
    await session.flush()
    return sa


async def run(args: argparse.Namespace) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = await _get_or_create_mssp(session, args.mssp_name)
            await _get_or_create_user(
                session, args.admin_email, args.admin_password,
                Role.MSSP_ADMIN, org.id,
            )
            await _get_or_create_super(
                session, args.super_email, args.super_password,
            )
    print(f"bootstrap: mssp={args.mssp_name!r} admin={args.admin_email!r} "
          f"super={args.super_email!r}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--mssp-name", required=True)
    p.add_argument("--admin-email", required=True)
    p.add_argument("--admin-password", required=True)
    p.add_argument("--super-email", required=True)
    p.add_argument("--super-password", required=True)
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
