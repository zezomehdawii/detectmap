"""Alembic environment for the CUSTOMER (per-tenant) schema.

Run with the target schema in env:
    DETECTMAP_TARGET_SCHEMA=cust_acme alembic -n customer upgrade head

Each customer schema gets its own alembic_version table inside that schema,
keeping migration state per-tenant so a customer can be upgraded independently.
"""
from __future__ import annotations

import os
import re
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool, text

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.db.base import customer_metadata  # noqa: E402
from app.models import customer as _customer_models  # noqa: F401,E402  -- registers tables

config = context.config

db_url = os.getenv("DATABASE_URL_SYNC") or config.get_main_option("sqlalchemy.url")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = customer_metadata

# Target customer schema must be supplied — there is no sensible default.
TARGET_SCHEMA = os.environ.get("DETECTMAP_TARGET_SCHEMA")
if not TARGET_SCHEMA:
    raise RuntimeError(
        "DETECTMAP_TARGET_SCHEMA must be set when running customer migrations "
        "(e.g. 'cust_acme')"
    )
if not re.match(r"^cust_[a-z][a-z0-9_]{1,30}$", TARGET_SCHEMA):
    raise RuntimeError(f"invalid target schema name: {TARGET_SCHEMA!r}")


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=False,
        version_table="alembic_version_customer",
        version_table_schema=TARGET_SCHEMA,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # Make sure the schema exists, then pin search_path so the migration
        # creates tables inside cust_<name>, not public.
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{TARGET_SCHEMA}"'))
        connection.execute(text(f'SET search_path TO "{TARGET_SCHEMA}", public'))
        # CRITICAL: commit the schema + SET so alembic's own begin_transaction()
        # starts fresh. Without this, the SQLAlchemy 2.0 autobegin transaction
        # is still open when alembic enters begin_transaction(), alembic
        # detects it and no-ops, and on connection close every DDL rolls back
        # silently. The migration logs success but no tables get created.
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=False,
            version_table="alembic_version_customer",
            version_table_schema=TARGET_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
