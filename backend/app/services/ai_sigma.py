"""AI-assisted Sigma authoring — Anthropic Claude integration.

Public entrypoints:
  - `draft(brief, *, org_id)` → DraftResult
  - `test_credentials(api_key, model)` → TestResult

The model is called via the Anthropic Python SDK. The API key is
decrypted from `mssp_orgs.ai_api_key_encrypted` at call time and held
in memory only for the duration of the request. On a validation failure
we send up to MAX_RETRIES correction round-trips before giving up.

Anthropic is the only provider supported today; the abstraction is
intentionally thin (an MSSP brings their own key, and we don't want to
maintain provider drift).
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from app.core.crypto import decrypt
from app.db.base import AsyncSessionLocal
from app.models.public import MSSPOrg
from app.services.ai_sigma_prompt import (
    SigmaBrief,
    build_messages,
    build_retry_messages,
)
from app.services.ai_sigma_validate import (
    AISigmaValidationError,
    validate,
)

log = logging.getLogger(__name__)

MAX_RETRIES = 2  # initial + 2 corrections = up to 3 model calls
MAX_TOKENS = 1500
TIMEOUT_SECONDS = 45.0


@dataclass
class DraftResult:
    yaml_text: str
    parsed_fields: dict
    attempts: int
    warnings: list[str]


@dataclass
class TestResult:
    ok: bool
    message: str
    model: Optional[str] = None


class AISigmaError(RuntimeError):
    """Configuration or upstream-call error (not a validation failure)."""


# ---- internal helpers ----------------------------------------------------

def _load_anthropic():
    """Imported lazily so the rest of the app boots fine even if the SDK
    isn't installed yet (e.g. between requirements bump and image rebuild).
    """
    try:
        import anthropic  # type: ignore
    except ImportError as e:
        raise AISigmaError(
            "anthropic SDK is not installed in this image. "
            "Run `docker compose build backend` after a `pip install` bump."
        ) from e
    return anthropic


async def _resolve_org_key(org_id: uuid.UUID) -> tuple[str, str, MSSPOrg]:
    async with AsyncSessionLocal() as session:
        org = (
            await session.execute(select(MSSPOrg).where(MSSPOrg.id == org_id))
        ).scalar_one_or_none()
        if org is None:
            raise AISigmaError("MSSP org not found")
        if not org.ai_api_key_encrypted:
            raise AISigmaError(
                "AI authoring is not configured for this MSSP. "
                "Set an API key in Settings → AI authoring."
            )
        try:
            plain = decrypt(org.ai_api_key_encrypted)
        except ValueError as e:
            raise AISigmaError(f"stored AI key could not be decrypted: {e}") from e
        return plain, (org.ai_model or "claude-opus-4-7"), org


async def _record_status(org_id: uuid.UUID, status: str) -> None:
    """Stamp `ai_last_used_at` + `ai_last_status` on the org row.

    Best-effort — never raised back to the caller.
    """
    try:
        async with AsyncSessionLocal() as session:
            org = (
                await session.execute(select(MSSPOrg).where(MSSPOrg.id == org_id))
            ).scalar_one_or_none()
            if org is None:
                return
            org.ai_last_used_at = datetime.now(timezone.utc)
            org.ai_last_status = status[:40]
            await session.commit()
    except Exception:  # noqa: BLE001 - never break the user path on bookkeeping
        log.exception("failed to record AI usage status")


def _call_model_sync(
    api_key: str, model: str, system: str, messages: list[dict]
) -> str:
    """Single Anthropic API call. Sync because the SDK's async client
    can be flaky inside Celery loops; we already wrap this in a thread
    pool via `asyncio.to_thread` in the caller.
    """
    anthropic = _load_anthropic()
    client = anthropic.Anthropic(api_key=api_key, timeout=TIMEOUT_SECONDS)
    resp = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=system,
        messages=messages,
    )
    # Concatenate any text blocks the SDK returned. The output contract
    # asks for a single YAML block, but `content` is always a list.
    chunks: list[str] = []
    for block in resp.content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            chunks.append(text)
    return "".join(chunks)


# ---- public API ----------------------------------------------------------

async def draft(brief: SigmaBrief, *, org_id: uuid.UUID) -> DraftResult:
    """Generate a validated Sigma YAML draft from a structured brief.

    Raises AISigmaError on config / upstream failures.
    On exhausted retries, raises AISigmaValidationError with the final
    set of validation errors so the UI can show them.
    """
    import asyncio

    if brief.is_minimal():
        raise AISigmaError(
            "Brief is too thin. Fill in at least the intent or one technique ID."
        )

    api_key, model, _org = await _resolve_org_key(org_id)

    system, messages = build_messages(brief)
    last_errors: list[str] = []
    last_yaml = ""
    warnings: list[str] = []

    for attempt in range(MAX_RETRIES + 1):
        try:
            raw = await asyncio.to_thread(
                _call_model_sync, api_key, model, system, messages
            )
        except Exception as e:  # noqa: BLE001 - anthropic raises a zoo
            await _record_status(org_id, "upstream_error")
            raise AISigmaError(f"AI provider call failed: {e}") from e

        try:
            yaml_text, parsed = validate(raw)
            await _record_status(org_id, "ok")
            return DraftResult(
                yaml_text=yaml_text,
                parsed_fields=parsed,
                attempts=attempt + 1,
                warnings=warnings,
            )
        except AISigmaValidationError as e:
            last_errors = list(e.errors)
            last_yaml = raw
            warnings.append(
                f"attempt {attempt + 1}: " + " / ".join(last_errors[:3])
            )
            if attempt < MAX_RETRIES:
                system, messages = build_retry_messages(brief, last_yaml, last_errors)
                continue
            await _record_status(org_id, "validation_failed")
            raise

    # Should be unreachable — the loop always returns or raises.
    raise AISigmaError("AI draft loop exited without a result")


async def test_credentials(api_key: str, model: str) -> TestResult:
    """One-shot ping: a tiny prompt to validate the API key + model.

    Used by the Settings page's "Test connection" button. Never persists
    anything — the key isn't saved yet at this point.
    """
    import asyncio

    try:
        raw = await asyncio.to_thread(
            _call_model_sync,
            api_key,
            model,
            "Reply with exactly the word OK and nothing else.",
            [{"role": "user", "content": "ping"}],
        )
    except AISigmaError:
        raise
    except Exception as e:  # noqa: BLE001
        return TestResult(ok=False, message=f"call failed: {e}", model=model)
    return TestResult(
        ok=True,
        message=f"connected. Model replied with {raw.strip()[:40]!r}.",
        model=model,
    )


__all__ = [
    "AISigmaError",
    "DraftResult",
    "TestResult",
    "draft",
    "test_credentials",
]
