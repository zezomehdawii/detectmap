"""Async SQLAlchemy engine + session factories + declarative bases.

We keep two MetaData objects:
  - public_metadata: shared cross-tenant tables (mssp_orgs, customers, users, roles)
  - customer_metadata: per-tenant tables created inside each cust_<codename> schema

Two Alembic environments (migrations/public, migrations/customer) target each
metadata. The customer tree is applied once per customer schema at provisioning
time (and again on later upgrades by iterating all customer schemas).
"""
from __future__ import annotations

import uuid

from sqlalchemy import MetaData
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings

# ---- Engine ---------------------------------------------------------------
# Disable BOTH asyncpg's internal statement cache AND SQLAlchemy's asyncpg
# adapter cache. The same SQL text can resolve to different schema OIDs
# depending on the current `search_path`, so any plan caching across tenant
# swaps inside a pooled connection raises InvalidCachedStatementError. The
# `statement_cache_size=0` connect_arg disables asyncpg's cache;
# `prepared_statement_cache_size=0` on the URL disables SQLAlchemy's adapter
# cache (the latter is what was leaking across the portfolio iterator).
_db_url = settings.database_url
if "prepared_statement_cache_size" not in _db_url:
    sep = "&" if "?" in _db_url else "?"
    _db_url = f"{_db_url}{sep}prepared_statement_cache_size=0"

engine = create_async_engine(
    _db_url,
    echo=settings.app_debug,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args={"statement_cache_size": 0},
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# ---- Metadata trees -------------------------------------------------------
# Public schema metadata — explicit schema='public' so Alembic generates DDL
# that's unambiguous when search_path is set to a customer schema.
public_metadata = MetaData(schema="public")

# Customer (per-tenant) metadata — NO schema set; tables resolve against
# whatever search_path is active for the connection. The customer Alembic
# env applies these against each cust_<codename> schema.
customer_metadata = MetaData()


class PublicBase(DeclarativeBase):
    metadata = public_metadata


class CustomerBase(DeclarativeBase):
    metadata = customer_metadata


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def enum_values(obj):
    return [e.value for e in obj]
