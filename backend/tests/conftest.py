"""Shared pytest fixtures for DB-touching tests."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Awaitable, Callable

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.security import TokenAudience, create_access_token, hash_password
from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackCatalogVersion,
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackMitigation,
    AttackSoftware,
    AttackSoftwareTechnique,
    AttackTechnique,
    AttackTechniqueMitigation,
    GRCControl,
    GRCFramework,
    GRCMitigationMapping,
    GRCTechniqueMapping,
    MSSPOrg,
    Role,
    SectorProfile,
    SuperAdmin,
    User,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "attack"


@pytest_asyncio.fixture(autouse=True)
async def _reset_engine_pool():
    # asyncpg connections are bound to the event loop that created them.
    # pytest-asyncio's per-function loop would otherwise resurface stale
    # connections and fail with "Future attached to a different loop".
    from app.db.base import engine
    await engine.dispose()
    yield


def load_bundle(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / f"{name}.json").read_text())


def make_fetch_fn(
    mapping: dict[str, dict],
) -> Callable[[str], Awaitable[dict]]:
    async def _fetch(domain: str) -> dict:
        if domain not in mapping:
            raise KeyError(f"no fixture for domain={domain!r}")
        return mapping[domain]

    return _fetch


@pytest.fixture
def fetch_v1() -> Callable[[str], Awaitable[dict]]:
    return make_fetch_fn({"enterprise": load_bundle("enterprise_v1")})


@pytest.fixture
def fetch_v2() -> Callable[[str], Awaitable[dict]]:
    return make_fetch_fn({"enterprise": load_bundle("enterprise_v2")})


async def _wipe_attack_tables() -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(AttackTechniqueMitigation))
            await session.execute(delete(AttackGroupTechnique))
            await session.execute(delete(AttackSoftwareTechnique))
            await session.execute(delete(AttackGroupSoftware))
            await session.execute(delete(AttackMitigation))
            await session.execute(delete(AttackGroup))
            await session.execute(delete(AttackSoftware))
            await session.execute(delete(AttackTechnique))
            await session.execute(delete(AttackCatalogVersion))


@pytest.fixture
def fetch_groups() -> Callable[[str], Awaitable[dict]]:
    return make_fetch_fn({"enterprise": load_bundle("enterprise_groups")})


@pytest_asyncio.fixture
async def clean_sector_profiles():
    """Wipe sector_profiles before and after — shared dev DB safety."""
    async def _wipe():
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(SectorProfile))
    await _wipe()
    yield
    await _wipe()


@pytest_asyncio.fixture
async def clean_grc_tables():
    """Wipe GRC tables before AND after — shared dev DB safety."""
    async def _wipe():
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(GRCTechniqueMapping))
                await session.execute(delete(GRCMitigationMapping))
                await session.execute(delete(GRCControl))
                await session.execute(delete(GRCFramework))
    await _wipe()
    yield
    await _wipe()


@pytest_asyncio.fixture
async def clean_attack_tables():
    # Wipe before AND after — the dev DB is shared with the live API, so
    # fixture rows left behind would corrupt the real catalog.
    await _wipe_attack_tables()
    yield
    await _wipe_attack_tables()


@pytest_asyncio.fixture
async def super_admin_token() -> str:
    email = "phase2-super@detectmap.test"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            admin = (
                await session.execute(
                    select(SuperAdmin).where(SuperAdmin.email == email)
                )
            ).scalar_one_or_none()
            if admin is None:
                admin = SuperAdmin(
                    id=uuid.uuid4(),
                    email=email,
                    hashed_password=hash_password("phase2-test"),
                )
                session.add(admin)
        admin_id = admin.id
    return create_access_token(
        subject=str(admin_id), audience=TokenAudience.SUPERADMIN
    )


async def _ensure_user_in_org(
    email: str, role: Role, org_name: str, password: str = "phase3-test"
) -> uuid.UUID:
    """Get-or-create an MSSP org + a user with the given role in it."""
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = (
                await session.execute(select(MSSPOrg).where(MSSPOrg.name == org_name))
            ).scalar_one_or_none()
            if org is None:
                org = MSSPOrg(id=uuid.uuid4(), name=org_name)
                session.add(org)
                await session.flush()
            user = (
                await session.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is None:
                user = User(
                    id=uuid.uuid4(),
                    email=email,
                    hashed_password=hash_password(password),
                    role=role,
                    mssp_org_id=org.id,
                )
                session.add(user)
                await session.flush()
        return user.id


@pytest_asyncio.fixture
async def demo_admin_token() -> str:
    """MSSP admin in the 'Demo MSSP' org (which owns acme + globex)."""
    user_id = await _ensure_user_in_org(
        "phase3-demo-admin@detectmap.test", Role.MSSP_ADMIN, "Demo MSSP"
    )
    return create_access_token(
        subject=str(user_id),
        audience=TokenAudience.TENANT,
        claims={"role": Role.MSSP_ADMIN.value},
    )


@pytest_asyncio.fixture
async def demo_readonly_token() -> str:
    user_id = await _ensure_user_in_org(
        "phase3-demo-readonly@detectmap.test", Role.MSSP_READONLY, "Demo MSSP"
    )
    return create_access_token(
        subject=str(user_id),
        audience=TokenAudience.TENANT,
        claims={"role": Role.MSSP_READONLY.value},
    )


@pytest_asyncio.fixture
async def readonly_token() -> str:
    email = "phase3-readonly@detectmap.test"
    org_name = "Phase2 Test MSSP"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = (
                await session.execute(select(MSSPOrg).where(MSSPOrg.name == org_name))
            ).scalar_one_or_none()
            if org is None:
                org = MSSPOrg(id=uuid.uuid4(), name=org_name)
                session.add(org)
                await session.flush()
            user = (
                await session.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is None:
                user = User(
                    id=uuid.uuid4(),
                    email=email,
                    hashed_password=hash_password("phase3-test"),
                    role=Role.MSSP_READONLY,
                    mssp_org_id=org.id,
                )
                session.add(user)
                await session.flush()
        user_id = user.id
    return create_access_token(
        subject=str(user_id),
        audience=TokenAudience.TENANT,
        claims={"role": Role.MSSP_READONLY.value},
    )


@pytest_asyncio.fixture
async def tenant_token() -> str:
    org_name = "Phase2 Test MSSP"
    email = "phase2-admin@detectmap.test"
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = (
                await session.execute(
                    select(MSSPOrg).where(MSSPOrg.name == org_name)
                )
            ).scalar_one_or_none()
            if org is None:
                org = MSSPOrg(id=uuid.uuid4(), name=org_name)
                session.add(org)
                await session.flush()
            user = (
                await session.execute(
                    select(User).where(User.email == email)
                )
            ).scalar_one_or_none()
            if user is None:
                user = User(
                    id=uuid.uuid4(),
                    email=email,
                    hashed_password=hash_password("phase2-test"),
                    role=Role.MSSP_ADMIN,
                    mssp_org_id=org.id,
                )
                session.add(user)
                await session.flush()
        user_id = user.id
    return create_access_token(
        subject=str(user_id),
        audience=TokenAudience.TENANT,
        claims={"role": Role.MSSP_ADMIN.value},
    )
