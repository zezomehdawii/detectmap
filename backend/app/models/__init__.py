"""Model package — imports register tables onto their metadata objects.

Alembic env.py imports this module so both PublicBase.metadata and
CustomerBase.metadata are populated before autogeneration runs.
"""
from app.models import customer, public  # noqa: F401

__all__ = ["customer", "public"]
