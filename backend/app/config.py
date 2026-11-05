"""Application settings loaded from environment via pydantic-settings."""
from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_env: str = "development"
    app_debug: bool = True
    app_name: str = "The Detection Map"
    cors_origins: str = "http://localhost:3000"

    # Sign-in page hint for fresh/demo installations. The credentials are
    # only returned by /auth/login-hint while an administrator leaves the
    # hint enabled in Settings; they are never written to the database.
    default_login_email: str = "admin@demo.local"
    default_login_password: str = "change-me"

    # DB
    database_url: str
    database_url_sync: str

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"

    # JWT — two separate secrets (tenant users vs Product Super Admin)
    jwt_tenant_secret: str
    jwt_superadmin_secret: str
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 60
    jwt_refresh_ttl_days: int = 14

    # Fernet
    fernet_key: str

    # Internal bootstrap
    internal_api_key: str

    # ATT&CK STIX source
    attack_stix_base_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    )
    attack_stix_fetch_timeout: float = 60.0

    # SigmaHQ ruleset source
    sigmahq_repo: str = "SigmaHQ/sigma"
    sigmahq_default_ref: str = "master"
    sigmahq_subdir: str = "rules"  # only ingest the curated stable set
    sigmahq_fetch_timeout: float = 300.0

    # D3FEND mapping source
    d3fend_mappings_url: str = (
        "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"
    )
    d3fend_fetch_timeout: float = 120.0

    # Customer-diagram uploads (Stage 2 of the customer profile feature).
    # Files land at <root>/<codename>/<diagram_uuid><.ext>. Default is a
    # path relative to the backend container's working dir (/app), which
    # is bind-mounted from ./backend on the host — so diagrams survive
    # container restarts and are visible on the host filesystem.
    diagram_storage_root: str = "storage/diagrams"
    diagram_max_bytes: int = 50 * 1024 * 1024  # 50 MB

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
