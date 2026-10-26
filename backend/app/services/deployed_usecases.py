"""Import detection use-cases that are deployed in a customer's SIEM.

Two ingest paths, both landing in the tenant `deployed_use_cases` table:

1. **Live API** (`fetch_live`) — query the configured connector's own rule
   catalog read-only:
     - Splunk:   GET <host>/services/saved/searches      (saved/correlation searches)
     - Elastic:  GET <host>/api/detection_engine/rules/_find  (Kibana security rules)
     - Sentinel: ARM list of Microsoft.SecurityInsights/alertRules

2. **CSV upload** (`parse_csv`) — parse an exported rule list with tolerant,
   case-insensitive header matching so exports from different products /
   versions still line up.

Both produce a list of `ParsedUseCase`; `upsert` writes them idempotently
keyed on (connector_id, external_id). ATT&CK technique IDs are extracted
from whatever text the source offers (tags, annotations, threat blocks,
free text) via a single regex so coverage can light up regardless of source.

These are dual-use admin reads against the user's *own* configured
connectors — every call is gated behind CONNECTOR_WRITE + active tenant at
the API layer. We never write back to the SIEM.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.customer import DeployedUseCase

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)

# T1059 or T1059.001 — bounded by non-alphanumerics so we don't match inside
# longer tokens. Case-insensitive; we upper-case before storing.
_TECH_RE = re.compile(r"(?<![A-Za-z0-9])([Tt]\d{4}(?:\.\d{3})?)(?![0-9])")


class UseCaseFetchError(Exception):
    """Raised when a live fetch fails — surfaced to the API as a 502/400."""


def extract_technique_ids(*texts: Any) -> list[str]:
    """Pull unique ATT&CK technique IDs from arbitrary text/JSON blobs.

    Accepts strings, lists, dicts — anything; non-strings are stringified so
    we catch IDs buried in nested annotation JSON. Order-preserving dedupe.
    """
    seen: dict[str, None] = {}
    for t in texts:
        if t is None:
            continue
        blob = t if isinstance(t, str) else json.dumps(t, default=str)
        for m in _TECH_RE.findall(blob):
            seen.setdefault(m.upper(), None)
    return list(seen.keys())


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "y", "on", "enabled", "active"):
        return True
    if s in ("false", "0", "no", "n", "off", "disabled", "inactive"):
        return False
    return default


@dataclass
class ParsedUseCase:
    external_id: str
    name: str
    description: str | None = None
    severity: str | None = None
    enabled: bool = True
    query: str | None = None
    technique_ids: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CSV path
# ---------------------------------------------------------------------------

# Candidate header names per logical field, tried in order (case-insensitive).
_CSV_FIELDS: dict[str, tuple[str, ...]] = {
    "external_id": ("id", "rule_id", "ruleid", "uuid", "guid", "sid", "external_id"),
    "name": ("name", "title", "rule", "rule_name", "search_name", "display_name", "displayname"),
    "description": ("description", "desc", "notes", "summary"),
    "severity": ("severity", "level", "priority", "urgency", "risk"),
    "enabled": ("enabled", "status", "state", "is_enabled", "active", "disabled"),
    "query": ("query", "search", "spl", "kql", "rule_query", "logic", "detection"),
    "techniques": (
        "technique", "techniques", "technique_id", "technique_ids",
        "attack", "mitre", "mitre_attack", "mitre_technique", "tactic_technique", "tags",
    ),
}


def parse_csv(csv_text: str) -> list[ParsedUseCase]:
    """Parse an exported rule list. Tolerant of column-name drift; rows that
    have neither a name nor a query are skipped as noise."""
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        return []
    # lower-cased header -> original header
    headers = {(h or "").strip().lower(): h for h in reader.fieldnames}

    def pick(row: dict, logical: str) -> str | None:
        for cand in _CSV_FIELDS[logical]:
            if cand in headers:
                val = row.get(headers[cand])
                if val not in (None, ""):
                    return str(val)
        return None

    out: list[ParsedUseCase] = []
    for i, row in enumerate(reader):
        name = pick(row, "name")
        query = pick(row, "query")
        if not name and not query:
            continue
        name = name or f"row {i + 1}"
        desc = pick(row, "description")
        severity = pick(row, "severity")
        techniques_cell = pick(row, "techniques")
        # 'disabled' column inverts the meaning of the truthy value.
        enabled_raw = pick(row, "enabled")
        enabled = _as_bool(enabled_raw)
        if "disabled" in headers and row.get(headers["disabled"]) not in (None, ""):
            enabled = not _as_bool(row.get(headers["disabled"]), default=False)

        technique_ids = extract_technique_ids(techniques_cell, name, desc, query)
        ext = pick(row, "external_id") or f"csv:{name}"
        out.append(
            ParsedUseCase(
                external_id=ext[:200],
                name=name[:500],
                description=desc,
                severity=severity,
                enabled=enabled,
                query=query,
                technique_ids=technique_ids,
                raw={k: v for k, v in row.items() if k},
            )
        )
    return out


# ---------------------------------------------------------------------------
# Live API path
# ---------------------------------------------------------------------------


async def fetch_live(
    kind: str, config: dict[str, Any], secrets: dict[str, str]
) -> list[ParsedUseCase]:
    if kind == "splunk":
        return await _fetch_splunk(config, secrets)
    if kind == "elastic":
        return await _fetch_elastic(config, secrets)
    if kind == "sentinel":
        return await _fetch_sentinel(config, secrets)
    if kind == "logrhythm":
        return await _fetch_logrhythm(config, secrets)
    raise UseCaseFetchError(f"unsupported connector kind: {kind!r}")


async def _fetch_splunk(
    config: dict[str, Any], secrets: dict[str, str]
) -> list[ParsedUseCase]:
    host = (config.get("host") or "").rstrip("/")
    if not host:
        raise UseCaseFetchError("missing host")
    verify = bool(config.get("verify_tls", True))

    headers: dict[str, str] = {}
    auth: httpx.BasicAuth | None = None
    if config.get("username") and secrets.get("password"):
        auth = httpx.BasicAuth(config["username"], secrets["password"])
    elif secrets.get("token"):
        headers["Authorization"] = f"Bearer {secrets['token']}"
    else:
        raise UseCaseFetchError(
            "listing saved searches needs a username+password or a bearer token "
            "(a HEC token cannot read the splunkd REST API)"
        )

    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, verify=verify, auth=auth) as client:
            r = await client.get(
                f"{host}/services/saved/searches",
                headers=headers,
                params={"output_mode": "json", "count": 0},
            )
    except httpx.HTTPError as e:
        raise UseCaseFetchError(f"splunkd unreachable: {type(e).__name__}") from e
    if not r.is_success:
        raise UseCaseFetchError(f"splunkd returned {r.status_code}")

    entries = r.json().get("entry", [])
    out: list[ParsedUseCase] = []
    for e in entries:
        name = e.get("name") or ""
        content = e.get("content", {}) or {}
        search = content.get("search")
        # ES correlation searches stash MITRE annotations as a JSON string.
        annotations = content.get("action.correlationsearch.annotations")
        technique_ids = extract_technique_ids(annotations, search, name, content.get("description"))
        out.append(
            ParsedUseCase(
                external_id=(e.get("id") or name)[:200],
                name=name[:500] or "(unnamed saved search)",
                description=content.get("description"),
                severity=content.get("alert.severity"),
                enabled=not _as_bool(content.get("disabled"), default=False),
                query=search,
                technique_ids=technique_ids,
                raw={"name": name, "content_keys": list(content.keys())},
            )
        )
    return out


async def _fetch_elastic(
    config: dict[str, Any], secrets: dict[str, str]
) -> list[ParsedUseCase]:
    # Detection rules live in Kibana, not Elasticsearch. Allow a kibana_url
    # override; otherwise assume the configured host fronts Kibana.
    host = (config.get("kibana_url") or config.get("host") or "").rstrip("/")
    if not host:
        raise UseCaseFetchError("missing host (or kibana_url)")
    verify = bool(config.get("verify_tls", True))

    headers: dict[str, str] = {"kbn-xsrf": "true"}
    auth: httpx.BasicAuth | None = None
    if secrets.get("api_key"):
        headers["Authorization"] = f"ApiKey {secrets['api_key']}"
    elif config.get("username") and secrets.get("password"):
        auth = httpx.BasicAuth(config["username"], secrets["password"])
    else:
        raise UseCaseFetchError("no credentials configured")

    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, verify=verify, auth=auth) as client:
            r = await client.get(
                f"{host}/api/detection_engine/rules/_find",
                headers=headers,
                params={"per_page": 1000, "page": 1},
            )
    except httpx.HTTPError as e:
        raise UseCaseFetchError(f"Kibana unreachable: {type(e).__name__}") from e
    if not r.is_success:
        raise UseCaseFetchError(
            f"Kibana detection-engine returned {r.status_code} "
            "(set kibana_url if the host points at Elasticsearch)"
        )

    data = r.json().get("data", [])
    out: list[ParsedUseCase] = []
    for rule in data:
        threat = rule.get("threat", [])
        technique_ids = extract_technique_ids(threat, rule.get("query"), rule.get("name"))
        out.append(
            ParsedUseCase(
                external_id=(rule.get("rule_id") or rule.get("id") or "")[:200],
                name=(rule.get("name") or "(unnamed rule)")[:500],
                description=rule.get("description"),
                severity=rule.get("severity"),
                enabled=bool(rule.get("enabled", True)),
                query=rule.get("query"),
                technique_ids=technique_ids,
                raw={"type": rule.get("type"), "rule_id": rule.get("rule_id")},
            )
        )
    return out


async def _fetch_sentinel(
    config: dict[str, Any], secrets: dict[str, str]
) -> list[ParsedUseCase]:
    tenant_id = config.get("tenant_id")
    subscription_id = config.get("subscription_id")
    resource_group = config.get("resource_group")
    workspace = config.get("workspace_name")
    client_id = config.get("client_id")
    client_secret = secrets.get("client_secret")
    if not all([tenant_id, subscription_id, resource_group, workspace, client_id, client_secret]):
        raise UseCaseFetchError(
            "missing one of: tenant_id, subscription_id, resource_group, "
            "workspace_name, client_id, client_secret"
        )

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            tr = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )
            if not tr.is_success:
                raise UseCaseFetchError(f"AAD token endpoint returned {tr.status_code}")
            token = tr.json().get("access_token")
            if not token:
                raise UseCaseFetchError("AAD response missing access_token")

            arm_url = (
                f"https://management.azure.com/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}/providers/Microsoft."
                f"OperationalInsights/workspaces/{workspace}/providers/"
                f"Microsoft.SecurityInsights/alertRules?api-version=2023-02-01-preview"
            )
            rr = await client.get(arm_url, headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as e:
        raise UseCaseFetchError(f"Sentinel unreachable: {type(e).__name__}") from e
    if not rr.is_success:
        raise UseCaseFetchError(f"alertRules list returned {rr.status_code}")

    values = rr.json().get("value", [])
    out: list[ParsedUseCase] = []
    for item in values:
        props = item.get("properties", {}) or {}
        techniques = props.get("techniques", []) or []
        technique_ids = extract_technique_ids(
            techniques, props.get("query"), props.get("displayName")
        )
        out.append(
            ParsedUseCase(
                external_id=(item.get("name") or "")[:200],
                name=(props.get("displayName") or "(unnamed analytics rule)")[:500],
                description=props.get("description"),
                severity=props.get("severity"),
                enabled=bool(props.get("enabled", True)),
                query=props.get("query"),
                technique_ids=technique_ids,
                raw={"kind": item.get("kind")},
            )
        )
    return out


async def _fetch_logrhythm(
    config: dict[str, Any], secrets: dict[str, str]
) -> list[ParsedUseCase]:
    # LogRhythm's detection content is AI Engine rules, which are managed in
    # the Deployment Manager and not enumerable through a stable public REST
    # endpoint (the API Gateway exposes cases / alarms / hosts, not the rule
    # catalog). So the live path can confirm connectivity but can't list rules
    # — direct the user to the CSV export, which LogRhythm supports.
    host = (config.get("host") or "").rstrip("/")
    if not host:
        raise UseCaseFetchError("missing host")
    raise UseCaseFetchError(
        "LogRhythm does not expose an API to enumerate AI Engine rules. "
        "Export the rule list from the Deployment Manager and use the CSV "
        "import instead."
    )


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


async def siem_overlay(session: AsyncSession) -> dict[str, list[dict]]:
    """Map ATT&CK technique id → the deployed SIEM use-cases that cover it.

    Used as a read-only overlay on the coverage matrix (it does NOT change the
    DeTT&CT score, which reflects curated detections) so analysts can see
    catalog-vs-production drift. Caller owns the tenant-bound session.
    """
    from app.models.customer import Connector

    rows = (
        await session.execute(
            select(DeployedUseCase, Connector.label, Connector.kind)
            .join(Connector, Connector.id == DeployedUseCase.connector_id)
            .order_by(DeployedUseCase.name)
        )
    ).all()
    by_technique: dict[str, list[dict]] = {}
    for uc, label, kind in rows:
        entry = {
            "id": str(uc.id),
            "name": uc.name,
            "connector_label": label,
            "connector_kind": kind,
            "severity": uc.severity,
            "enabled": uc.enabled,
        }
        for tid in (uc.technique_ids or []):
            by_technique.setdefault(str(tid).upper(), []).append(entry)
    return by_technique


async def upsert(
    session: AsyncSession,
    connector_id: uuid.UUID,
    items: list[ParsedUseCase],
    import_source: str,
) -> dict[str, int]:
    """Idempotent upsert keyed on (connector_id, external_id).

    Caller owns the (tenant-bound) session/transaction.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    existing_rows = (
        await session.execute(
            select(DeployedUseCase).where(DeployedUseCase.connector_id == connector_id)
        )
    ).scalars().all()
    by_ext = {r.external_id: r for r in existing_rows}

    created = updated = 0
    techniques: set[str] = set()
    for it in items:
        techniques.update(it.technique_ids)
        row = by_ext.get(it.external_id)
        if row is None:
            session.add(
                DeployedUseCase(
                    id=uuid.uuid4(),
                    connector_id=connector_id,
                    import_source=import_source,
                    external_id=it.external_id,
                    name=it.name,
                    description=it.description,
                    severity=it.severity,
                    enabled=it.enabled,
                    query=it.query,
                    technique_ids=it.technique_ids,
                    raw=it.raw,
                    synced_at=now,
                )
            )
            created += 1
        else:
            row.import_source = import_source
            row.name = it.name
            row.description = it.description
            row.severity = it.severity
            row.enabled = it.enabled
            row.query = it.query
            row.technique_ids = it.technique_ids
            row.raw = it.raw
            row.synced_at = now
            updated += 1
    await session.flush()
    return {
        "imported": created + updated,
        "created": created,
        "updated": updated,
        "technique_count": len(techniques),
    }


__all__ = [
    "ParsedUseCase",
    "UseCaseFetchError",
    "extract_technique_ids",
    "parse_csv",
    "fetch_live",
    "upsert",
]
