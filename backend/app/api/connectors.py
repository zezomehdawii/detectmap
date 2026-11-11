"""Connector configuration (Splunk / Sentinel / Elastic) — tenant-scoped.

Secrets are Fernet-encrypted at the application layer before reaching the
database. Endpoints never echo decrypted secret values — only field
presence + a masked tail — so a stolen API token can't read them back even
if it has read access.

Per CLAUDE.md Phase 8 the `/test` endpoint is a stub that returns
{"status": "planned"} — live sync is explicit future work.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, File, HTTPException, Response, UploadFile
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import (
    TenantPrincipal,
    require_active_customer,
    require_feature,
    require_perm,
)
from app.core.crypto import decrypt, encrypt
from app.core.rbac import Permission
from app.db.tenant import tenant_session
from app.models.customer import Connector, DeployedUseCase

router = APIRouter(prefix="/connectors", tags=["connectors"])


SUPPORTED_KINDS = ("splunk", "sentinel", "elastic", "logrhythm")

# Per-kind secret field names. Anything in `config` is plain-text; anything
# whose key shows up here gets Fernet-encrypted before persisting.
SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "splunk":    ("hec_token", "password"),
    "sentinel":  ("workspace_key", "client_secret"),
    "elastic":   ("api_key", "password"),
    "logrhythm": ("api_token",),
}


def _mask(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]


def _split_secrets(kind: str, config_in: dict) -> tuple[dict, dict]:
    """Split incoming config into (plain, secrets) by SECRET_FIELDS[kind]."""
    secret_keys = set(SECRET_FIELDS.get(kind, ()))
    plain: dict = {}
    secrets: dict = {}
    for k, v in (config_in or {}).items():
        if k in secret_keys and v is not None and v != "":
            secrets[k] = encrypt(str(v))
        elif k not in secret_keys:
            plain[k] = v
    return plain, secrets


class ConnectorOut(BaseModel):
    id: str
    kind: str
    label: str
    description: Optional[str]
    status: str
    last_test_at: Optional[str]
    last_test_message: Optional[str]
    config: dict
    # Map of secret_field_name → masked-tail string. Never decrypted on read.
    secret_fields: dict[str, str]
    created_at: str
    updated_at: str


class ConnectorCreate(BaseModel):
    kind: str
    label: str
    description: Optional[str] = None
    config: dict = {}


class ConnectorPatch(BaseModel):
    label: Optional[str] = None
    description: Optional[str] = None
    config: Optional[dict] = None
    # Optional clear of one or more secret fields.
    clear_secrets: Optional[list[str]] = None


def _serialize(c: Connector) -> ConnectorOut:
    masked: dict[str, str] = {}
    enc = dict(c.encrypted_config or {})
    for k in enc.keys():
        try:
            masked[k] = _mask(decrypt(enc[k]))
        except ValueError:
            masked[k] = "(unreadable)"
    return ConnectorOut(
        id=str(c.id),
        kind=c.kind,
        label=c.label,
        description=c.description,
        status=c.status,
        last_test_at=c.last_test_at.isoformat() if c.last_test_at else None,
        last_test_message=c.last_test_message,
        config=dict(c.config or {}),
        secret_fields=masked,
        created_at=c.created_at.isoformat() if c.created_at else "",
        updated_at=c.updated_at.isoformat() if c.updated_at else "",
    )


def _validate_kind(kind: str) -> None:
    if kind not in SUPPORTED_KINDS:
        raise HTTPException(
            422,
            f"unsupported connector kind: {kind!r} — pick from {SUPPORTED_KINDS}",
        )


def _decrypt_secrets(row: Connector) -> dict[str, str]:
    """Decrypt the connector's secret map in memory. Undecryptable entries are
    skipped (they surface downstream as missing credentials)."""
    secrets: dict[str, str] = {}
    for k, v in dict(row.encrypted_config or {}).items():
        try:
            secrets[k] = decrypt(v)
        except Exception:  # noqa: BLE001
            continue
    return secrets


@router.get("", response_model=list[ConnectorOut])
async def list_connectors(
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[ConnectorOut]:
    async with tenant_session() as session:
        rows = (
            await session.execute(select(Connector).order_by(Connector.kind, Connector.label))
        ).scalars().all()
        return [_serialize(r) for r in rows]


@router.post("", response_model=ConnectorOut, status_code=201)
async def create_connector(
    payload: ConnectorCreate = Body(...),
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> ConnectorOut:
    _validate_kind(payload.kind)
    plain, secrets = _split_secrets(payload.kind, payload.config or {})
    async with tenant_session() as session:
        # Duplicate label guard — UniqueConstraint handles the DB, we surface a 409.
        existing = (
            await session.execute(
                select(Connector).where(
                    Connector.kind == payload.kind,
                    Connector.label == payload.label,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                409,
                f"connector {payload.kind}/{payload.label!r} already exists",
            )
        row = Connector(
            id=uuid.uuid4(),
            kind=payload.kind,
            label=payload.label,
            description=payload.description,
            config=plain,
            encrypted_config=secrets,
            status="planned",
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _serialize(row)


@router.patch("/{connector_id}", response_model=ConnectorOut)
async def patch_connector(
    connector_id: uuid.UUID,
    payload: ConnectorPatch = Body(...),
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> ConnectorOut:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Connector).where(Connector.id == connector_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "connector not found")

        if payload.label is not None:
            row.label = payload.label
        if payload.description is not None:
            row.description = payload.description

        if payload.config is not None:
            plain, new_secrets = _split_secrets(row.kind, payload.config)
            row.config = plain
            # Merge new ciphertexts onto the existing map — only fields the
            # caller actually supplied get rewritten.
            current = dict(row.encrypted_config or {})
            current.update(new_secrets)
            row.encrypted_config = current

        if payload.clear_secrets:
            current = dict(row.encrypted_config or {})
            for key in payload.clear_secrets:
                current.pop(key, None)
            row.encrypted_config = current

        await session.flush()
        await session.refresh(row)
        return _serialize(row)


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(
    connector_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(select(Connector).where(Connector.id == connector_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "connector not found")
        await session.delete(row)
    return Response(status_code=204)


class ConnectorTestOut(BaseModel):
    status: str
    message: str
    last_test_at: str


@router.post("/{connector_id}/test", response_model=ConnectorTestOut, status_code=202)
async def test_connector(
    connector_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
    ___: TenantPrincipal = Depends(require_feature("connector_tests")),
) -> ConnectorTestOut:
    """Live ping against the configured Splunk / Elastic / Sentinel.

    Decrypts the per-connector secrets in memory, fires one read-only
    request, records the outcome on the row. Never returns the secret
    material or token; only a short success/failure message.
    """
    from app.services.connector_tests import run_test

    now = datetime.now(timezone.utc)
    async with tenant_session() as session:
        row = (
            await session.execute(select(Connector).where(Connector.id == connector_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "connector not found")
        secrets = _decrypt_secrets(row)
        result = await run_test(row.kind, dict(row.config or {}), secrets)
        row.last_test_at = now
        row.last_test_message = result.message
        row.status = "ok" if result.ok else "error"
        await session.flush()
    return ConnectorTestOut(
        status="ok" if result.ok else "error",
        message=result.message,
        last_test_at=now.isoformat(),
    )


# ---------------------------------------------------------------------------
# Deployed use-cases — detection rules running in the customer's SIEM, imported
# either live from the connector API or from an uploaded CSV. Stored in the
# tenant `deployed_use_cases` table (separate from the curated detections).
# ---------------------------------------------------------------------------

# Some products export sizeable rule sets; cap the upload so a stray file
# can't exhaust memory. 5 MB comfortably covers thousands of rules.
_MAX_CSV_BYTES = 5 * 1024 * 1024


class DeployedUseCaseOut(BaseModel):
    id: str
    connector_id: str
    import_source: str
    external_id: str
    name: str
    description: Optional[str]
    severity: Optional[str]
    enabled: bool
    query: Optional[str]
    technique_ids: list[str]
    synced_at: Optional[str]


class UseCaseImportOut(BaseModel):
    imported: int
    created: int
    updated: int
    technique_count: int
    source: str


def _serialize_use_case(u: DeployedUseCase) -> DeployedUseCaseOut:
    return DeployedUseCaseOut(
        id=str(u.id),
        connector_id=str(u.connector_id),
        import_source=u.import_source,
        external_id=u.external_id,
        name=u.name,
        description=u.description,
        severity=u.severity,
        enabled=u.enabled,
        query=u.query,
        technique_ids=list(u.technique_ids or []),
        synced_at=u.synced_at.isoformat() if u.synced_at else None,
    )


async def _get_connector_or_404(session, connector_id: uuid.UUID) -> Connector:
    row = (
        await session.execute(select(Connector).where(Connector.id == connector_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "connector not found")
    return row


@router.get("/{connector_id}/use-cases", response_model=list[DeployedUseCaseOut])
async def list_use_cases(
    connector_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_READ)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> list[DeployedUseCaseOut]:
    async with tenant_session() as session:
        await _get_connector_or_404(session, connector_id)
        rows = (
            await session.execute(
                select(DeployedUseCase)
                .where(DeployedUseCase.connector_id == connector_id)
                .order_by(DeployedUseCase.name)
            )
        ).scalars().all()
        return [_serialize_use_case(r) for r in rows]


@router.post("/{connector_id}/use-cases/sync", response_model=UseCaseImportOut)
async def sync_use_cases(
    connector_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> UseCaseImportOut:
    """Live-fetch the connector's deployed rules and upsert them."""
    from app.services import deployed_usecases as uc

    if __.customer.sample_dataset is not None:
        raise HTTPException(403, "Live connector sync is unavailable in sample workspaces.")
    async with tenant_session() as session:
        row = await _get_connector_or_404(session, connector_id)
        secrets = _decrypt_secrets(row)
        try:
            items = await uc.fetch_live(row.kind, dict(row.config or {}), secrets)
        except uc.UseCaseFetchError as e:
            raise HTTPException(502, f"sync failed: {e}") from e
        summary = await uc.upsert(session, connector_id, items, import_source="api")
    return UseCaseImportOut(source="api", **summary)


@router.post("/{connector_id}/use-cases/import", response_model=UseCaseImportOut)
async def import_use_cases_csv(
    connector_id: uuid.UUID,
    file: UploadFile = File(...),
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> UseCaseImportOut:
    """Parse an uploaded CSV export of deployed rules and upsert them."""
    from app.services import deployed_usecases as uc

    raw = await file.read()
    if len(raw) > _MAX_CSV_BYTES:
        raise HTTPException(413, "CSV exceeds 5 MB limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    items = uc.parse_csv(text)
    if not items:
        raise HTTPException(
            422,
            "no rows parsed — CSV needs at least a name/title or query/search column",
        )
    async with tenant_session() as session:
        await _get_connector_or_404(session, connector_id)
        summary = await uc.upsert(session, connector_id, items, import_source="csv")
    return UseCaseImportOut(source="csv", **summary)


@router.delete("/{connector_id}/use-cases/{use_case_id}", status_code=204)
async def delete_use_case(
    connector_id: uuid.UUID,
    use_case_id: uuid.UUID,
    _: TenantPrincipal = Depends(require_perm(Permission.CONNECTOR_WRITE)),
    __: TenantPrincipal = Depends(require_active_customer()),
) -> Response:
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(DeployedUseCase).where(
                    DeployedUseCase.id == use_case_id,
                    DeployedUseCase.connector_id == connector_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "use-case not found")
        await session.delete(row)
    return Response(status_code=204)


__all__ = ["router"]
