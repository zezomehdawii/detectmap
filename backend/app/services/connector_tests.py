"""Live connector tests for Splunk / Elastic / Sentinel.

Each kind has a tiny "ping" that confirms the configured host and the
encrypted credentials are usable. We deliberately use the smallest
read-only endpoint each platform offers:

- Splunk:   GET <host>/services/server/info
- Elastic:  GET <host>/_cluster/health
- Sentinel: GET <ARM endpoint>/subscriptions/<sub>/resourceGroups/<rg>/providers/
            Microsoft.OperationalInsights/workspaces/<ws>?api-version=2022-10-01

Sentinel needs an OAuth token from a service principal — we use the
client-credentials flow against `login.microsoftonline.com`. All calls
have a 6s timeout; failures bubble up as `LiveTestResult.ok=False` with
a redacted message.

These are dual-use admin tools — the user explicitly authorized this for
*their own* configured connectors. We never auto-test or scan; every
call is gated behind CONNECTOR_WRITE + active tenant.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)


@dataclass
class LiveTestResult:
    ok: bool
    message: str
    detail: dict[str, Any]


_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=6.0, write=5.0, pool=5.0)


def _redact(s: str | None) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= 8:
        return "***"
    return s[:3] + "…" + s[-3:]


async def _test_splunk(config: dict[str, Any], secrets: dict[str, str]) -> LiveTestResult:
    host = (config.get("host") or "").rstrip("/")
    if not host:
        return LiveTestResult(False, "missing host", {})
    verify = bool(config.get("verify_tls", True))

    headers: dict[str, str] = {}
    auth: httpx.BasicAuth | None = None
    if secrets.get("hec_token"):
        # HEC token validates against the HEC endpoint, not splunkd REST.
        # A GET of /services/collector/health is the canonical HEC check.
        try:
            async with httpx.AsyncClient(
                timeout=_DEFAULT_TIMEOUT, verify=verify
            ) as client:
                r = await client.get(
                    f"{host}/services/collector/health",
                    headers={"Authorization": f"Splunk {secrets['hec_token']}"},
                )
            return LiveTestResult(
                ok=r.is_success,
                message=f"HEC health status {r.status_code}",
                detail={"endpoint": "/services/collector/health"},
            )
        except httpx.HTTPError as e:
            return LiveTestResult(False, f"HEC unreachable: {type(e).__name__}", {})

    if config.get("username") and secrets.get("password"):
        auth = httpx.BasicAuth(config["username"], secrets["password"])
    elif secrets.get("token"):
        headers["Authorization"] = f"Bearer {secrets['token']}"
    else:
        return LiveTestResult(False, "no credentials configured", {})

    try:
        async with httpx.AsyncClient(
            timeout=_DEFAULT_TIMEOUT, verify=verify, auth=auth
        ) as client:
            r = await client.get(
                f"{host}/services/server/info",
                headers=headers,
                params={"output_mode": "json"},
            )
        if not r.is_success:
            return LiveTestResult(
                False,
                f"splunkd returned {r.status_code}",
                {"endpoint": "/services/server/info"},
            )
        try:
            body = r.json()
            version = (
                body.get("entry", [{}])[0]
                .get("content", {})
                .get("version", "?")
            )
        except Exception:  # noqa: BLE001
            version = "?"
        return LiveTestResult(
            True,
            f"Splunk reachable (version {version})",
            {"version": version},
        )
    except httpx.HTTPError as e:
        return LiveTestResult(False, f"splunkd unreachable: {type(e).__name__}", {})


async def _test_elastic(config: dict[str, Any], secrets: dict[str, str]) -> LiveTestResult:
    host = (config.get("host") or "").rstrip("/")
    if not host:
        return LiveTestResult(False, "missing host", {})
    verify = bool(config.get("verify_tls", True))

    headers: dict[str, str] = {}
    auth: httpx.BasicAuth | None = None
    if secrets.get("api_key"):
        headers["Authorization"] = f"ApiKey {secrets['api_key']}"
    elif config.get("username") and secrets.get("password"):
        auth = httpx.BasicAuth(config["username"], secrets["password"])
    else:
        return LiveTestResult(False, "no credentials configured", {})

    try:
        async with httpx.AsyncClient(
            timeout=_DEFAULT_TIMEOUT, verify=verify, auth=auth
        ) as client:
            r = await client.get(f"{host}/_cluster/health", headers=headers)
        if not r.is_success:
            return LiveTestResult(
                False,
                f"elastic returned {r.status_code}",
                {"endpoint": "/_cluster/health"},
            )
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        return LiveTestResult(
            True,
            f"Cluster '{body.get('cluster_name', '?')}' status={body.get('status', '?')}",
            {
                "cluster_name": body.get("cluster_name"),
                "status": body.get("status"),
                "number_of_nodes": body.get("number_of_nodes"),
            },
        )
    except httpx.HTTPError as e:
        return LiveTestResult(False, f"elastic unreachable: {type(e).__name__}", {})


async def _test_sentinel(config: dict[str, Any], secrets: dict[str, str]) -> LiveTestResult:
    tenant_id = config.get("tenant_id")
    subscription_id = config.get("subscription_id")
    resource_group = config.get("resource_group")
    workspace = config.get("workspace_name")
    client_id = config.get("client_id")
    client_secret = secrets.get("client_secret")
    if not all([tenant_id, subscription_id, resource_group, workspace, client_id, client_secret]):
        return LiveTestResult(
            False,
            "missing one of: tenant_id, subscription_id, resource_group, "
            "workspace_name, client_id, client_secret",
            {},
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
                return LiveTestResult(
                    False,
                    f"AAD token endpoint returned {tr.status_code}",
                    {"client_id": _redact(client_id)},
                )
            token = tr.json().get("access_token")
            if not token:
                return LiveTestResult(False, "AAD response missing access_token", {})

            arm_url = (
                f"https://management.azure.com/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}/providers/Microsoft."
                f"OperationalInsights/workspaces/{workspace}"
                f"?api-version=2022-10-01"
            )
            wr = await client.get(arm_url, headers={"Authorization": f"Bearer {token}"})
        if not wr.is_success:
            return LiveTestResult(
                False,
                f"workspace lookup returned {wr.status_code}",
                {"workspace": workspace},
            )
        body = wr.json()
        return LiveTestResult(
            True,
            f"Workspace '{workspace}' reachable in {resource_group}",
            {
                "location": body.get("location"),
                "provisioningState": body.get("properties", {}).get("provisioningState"),
            },
        )
    except httpx.HTTPError as e:
        return LiveTestResult(False, f"Sentinel unreachable: {type(e).__name__}", {})


async def _test_logrhythm(config: dict[str, Any], secrets: dict[str, str]) -> LiveTestResult:
    # LogRhythm exposes its REST services behind an API Gateway (commonly the
    # Platform Manager on :8501). The Admin API hosts list is a small,
    # read-only endpoint that confirms both reachability and a valid token.
    host = (config.get("host") or "").rstrip("/")
    if not host:
        return LiveTestResult(False, "missing host", {})
    token = secrets.get("api_token")
    if not token:
        return LiveTestResult(False, "no api_token configured", {})
    verify = bool(config.get("verify_tls", True))

    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, verify=verify) as client:
            r = await client.get(
                f"{host}/lr-admin-api/hosts",
                headers={"Authorization": f"Bearer {token}", "count": "1"},
                params={"count": 1},
            )
    except httpx.HTTPError as e:
        return LiveTestResult(False, f"LogRhythm unreachable: {type(e).__name__}", {})
    if not r.is_success:
        return LiveTestResult(
            False,
            f"LogRhythm admin-api returned {r.status_code}",
            {"endpoint": "/lr-admin-api/hosts"},
        )
    try:
        n = len(r.json())
    except Exception:  # noqa: BLE001
        n = None
    return LiveTestResult(
        True,
        "LogRhythm API reachable" + (f" ({n} host(s) visible)" if n is not None else ""),
        {"endpoint": "/lr-admin-api/hosts"},
    )


async def run_test(
    kind: str, config: dict[str, Any], secrets: dict[str, str]
) -> LiveTestResult:
    if kind == "splunk":
        return await _test_splunk(config, secrets)
    if kind == "elastic":
        return await _test_elastic(config, secrets)
    if kind == "sentinel":
        return await _test_sentinel(config, secrets)
    if kind == "logrhythm":
        return await _test_logrhythm(config, secrets)
    return LiveTestResult(False, f"unsupported connector kind: {kind!r}", {})


__all__ = ["LiveTestResult", "run_test"]
