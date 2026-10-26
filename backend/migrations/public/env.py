"""Alembic environment for the PUBLIC (cross-tenant) schema."""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make `app.*` importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.db.base import public_metadata  # noqa: E402
from app.models import public as _public_models  # noqa: F401,E402  -- registers tables

config = context.config

# Allow overriding sqlalchemy.url from env (docker-compose passes DATABASE_URL_SYNC).
db_url = os.getenv("DATABASE_URL_SYNC") or config.get_main_option("sqlalchemy.url")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = public_metadata


def include_object(obj, name, type_, reflected, compare_to):
    # Public tree only owns objects in the 'public' schema (or unspecified).
    if type_ == "table":
        schema = obj.schema or "public"
        return schema == "public"
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        version_table_schema="public",
        include_object=include_object,
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
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            version_table_schema="public",
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
