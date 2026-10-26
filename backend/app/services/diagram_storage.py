"""Bytes-on-disk storage for customer-profile diagrams.

Files land at <root>/<codename>/<diagram_uuid><.ext> on the host
filesystem (via the backend bind mount). The DB row holds only the
metadata + the relative `stored_path`; the file lives outside Postgres
so we don't bloat the database with binary blobs.

Pure-function on purpose: takes the codename + bytes + filename, returns
the relative path it wrote. No DB awareness — the caller is responsible
for persisting the row that points at it.
"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Final

from app.config import settings
from app.db.tenant import schema_for

# Reject obvious script payloads outright. We always serve binaries with
# Content-Disposition: attachment, so the browser won't *execute* what we
# serve back — but blocking these here avoids storing them in the first
# place (defence-in-depth for the rare misconfigured proxy / direct
# bind-mount download).
_FORBIDDEN_MIME: Final[frozenset[str]] = frozenset({
    "text/html",
    "text/javascript",
    "application/javascript",
    "application/x-msdownload",  # .exe / .dll
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-dosexec",
})

_SAFE_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,8}$")


def kind_for_mime(mime: str) -> str:
    """`image` | `pdf` | `binary` — used by the UI to pick a renderer."""
    if not mime:
        return "binary"
    if mime.startswith("image/"):
        return "image"
    if mime == "application/pdf":
        return "pdf"
    return "binary"


def safe_extension(filename: str) -> str:
    """Return a safe lowercase file extension (incl. dot), or '' if none.

    Anything with non-alphanumeric chars or longer than 8 chars is treated
    as "no extension" — we'd rather lose the suffix than persist
    `evil.pdf.exe.....` as a stored filename.
    """
    if not filename:
        return ""
    m = _SAFE_EXT_RE.search(filename.strip())
    return m.group(0).lower() if m else ""


def _resolve_root() -> Path:
    """Storage root as an absolute Path. Creates it if missing."""
    raw = settings.diagram_storage_root
    root = Path(raw)
    if not root.is_absolute():
        # Resolve relative to the working dir (the container's /app).
        root = Path(os.getcwd()) / root
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_bytes(
    *,
    codename: str,
    diagram_id: uuid.UUID,
    filename: str,
    data: bytes,
) -> str:
    """Persist `data` and return the *relative* path stored on the row.

    The relative path (codename/<uuid><.ext>) is what we store in the DB
    — keeping it relative means rotating the storage root in config
    doesn't require a data migration.
    """
    # Validate codename so we can't be coaxed into writing outside the
    # storage root via path traversal.
    schema_for(codename)
    ext = safe_extension(filename)
    rel = f"{codename}/{diagram_id}{ext}"
    target = _resolve_root() / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return rel


def absolute_path(stored_path: str) -> Path:
    """Resolve a stored relative path to an absolute path under the root.

    Defends against `..` segments — if the resolved path escapes the
    storage root we raise (a stored row should never contain such a
    path, but a sanity check costs nothing).
    """
    root = _resolve_root().resolve()
    resolved = (root / stored_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:  # pragma: no cover — defensive
        raise PermissionError("stored_path escapes storage root") from exc
    return resolved


def delete_file(stored_path: str) -> None:
    """Best-effort delete — a missing file is not an error.

    We swallow `FileNotFoundError` because the file may already have
    been cleaned up out-of-band (e.g., when the operator runs a fresh
    setup that wipes tenant rows but leaves the storage volume).
    """
    try:
        absolute_path(stored_path).unlink()
    except FileNotFoundError:
        return


def is_forbidden_mime(mime: str) -> bool:
    return (mime or "").lower() in _FORBIDDEN_MIME


__all__ = [
    "kind_for_mime",
    "safe_extension",
    "write_bytes",
    "absolute_path",
    "delete_file",
    "is_forbidden_mime",
]
