"""LDAP / Active Directory authentication.

Used by `/auth/login` as a fallback after local password auth fails, and by
the Settings → Active Directory test button. Config lives on the
`app_settings` singleton (super-admin managed); the service-account password
is Fernet-encrypted at rest.

Flow (`authenticate`):
  1. Build a server connection (LDAPS or StartTLS, cert validation optional).
  2. If a service-account bind DN is configured: bind as it, then search the
     directory for the user with the configured filter, pulling the email +
     full-name attributes and the user's DN.
  3. Re-bind as the user's DN with the supplied password to verify it.
  4. Return the resolved identity, or None on any auth failure.

Security:
  - The login identifier is **escaped** with ldap3's `escape_filter_chars`
    before being interpolated into the search filter, so a value like
    `*)(uid=*` cannot turn into an injection. This is the critical control.
  - All ldap3 calls are synchronous; we run them in a worker thread so the
    event loop is never blocked.
  - Bad credentials raise `LDAPBindError`, which we convert to a None result
    (auth failure) for login. Connection/config errors raise `LdapError` so
    the test endpoint can surface them.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass
from typing import Optional

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.core.crypto import decrypt

log = logging.getLogger(__name__)

_MSSP_ROLES = {"mssp_admin", "mssp_analyst", "mssp_readonly"}
_CONNECT_TIMEOUT = 8  # seconds


class LdapError(Exception):
    """Connection / configuration error (not a bad-password failure)."""


# Role privilege order (highest first) for resolving multiple group matches.
_ROLE_RANK = {"mssp_admin": 3, "mssp_analyst": 2, "mssp_readonly": 1}


@dataclass
class LdapSettings:
    host: str
    bind_dn: Optional[str]
    bind_password: Optional[str]
    user_search_base: Optional[str]
    user_filter: str
    email_attr: str
    full_name_attr: str
    default_role: str
    start_tls: bool
    verify_cert: bool
    group_attr: str = "memberOf"
    group_mappings: dict | None = None


@dataclass
class LdapIdentity:
    email: str
    full_name: Optional[str]
    dn: str
    groups: list[str] = None  # type: ignore[assignment]


def settings_from_row(row) -> LdapSettings:
    """Build an LdapSettings from an AppSettings row, decrypting the bind pw."""
    bind_pw: Optional[str] = None
    if row.ldap_bind_password_encrypted:
        try:
            bind_pw = decrypt(row.ldap_bind_password_encrypted)
        except ValueError as e:  # tampered / wrong key
            raise LdapError(f"stored LDAP bind password could not be decrypted: {e}")
    return LdapSettings(
        host=(row.ldap_host or "").strip(),
        bind_dn=(row.ldap_bind_dn or None),
        bind_password=bind_pw,
        user_search_base=(row.ldap_user_search_base or None),
        user_filter=row.ldap_user_filter or "(sAMAccountName={username})",
        email_attr=row.ldap_email_attr or "mail",
        full_name_attr=row.ldap_full_name_attr or "displayName",
        default_role=row.ldap_default_role or "mssp_readonly",
        start_tls=bool(row.ldap_start_tls),
        verify_cert=bool(row.ldap_verify_cert),
        group_attr=row.ldap_group_attr or "memberOf",
        group_mappings=dict(row.ldap_group_mappings or {}),
    )


def resolve_default_role(cfg: LdapSettings) -> str:
    """JIT users must land on an MSSP role; fall back to least privilege."""
    return cfg.default_role if cfg.default_role in _MSSP_ROLES else "mssp_readonly"


def map_groups_to_role(cfg: LdapSettings, groups: list[str] | None) -> Optional[str]:
    """Resolve a role from the user's directory groups via configured mappings.

    A mapping key matches if it appears (case-insensitively) within any of the
    user's group values — so an admin can use a full DN
    (`CN=SOC-Admins,OU=Groups,...`) or just `SOC-Admins`. When several groups
    match, the highest-privilege role wins. Returns None if nothing matches.
    """
    mappings = cfg.group_mappings or {}
    if not mappings or not groups:
        return None
    lowered = [g.lower() for g in groups]
    best: Optional[str] = None
    for key, role in mappings.items():
        if role not in _MSSP_ROLES:
            continue
        k = str(key).lower()
        if any(k in g for g in lowered):
            if best is None or _ROLE_RANK.get(role, 0) > _ROLE_RANK.get(best, 0):
                best = role
    return best


def build_filter(template: str, username: str) -> str:
    """Interpolate the (escaped) identifier into the configured filter."""
    return template.replace("{username}", escape_filter_chars(username))


def _server(cfg: LdapSettings) -> Server:
    if not cfg.host:
        raise LdapError("LDAP host is not configured")
    use_ssl = cfg.host.lower().startswith("ldaps://")
    tls = Tls(
        validate=ssl.CERT_REQUIRED if cfg.verify_cert else ssl.CERT_NONE
    )
    return Server(
        cfg.host,
        use_ssl=use_ssl,
        get_info=ALL,
        tls=tls,
        connect_timeout=_CONNECT_TIMEOUT,
    )


def _authenticate_sync(cfg: LdapSettings, username: str, password: str) -> Optional[LdapIdentity]:
    if not password:
        # Empty password against AD can yield an "unauthenticated bind" that
        # succeeds — never allow it.
        return None
    server = _server(cfg)

    user_dn: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    groups: list[str] = []

    if cfg.bind_dn:
        # search-then-bind via the service account
        try:
            svc = Connection(
                server, cfg.bind_dn, cfg.bind_password or "", auto_bind=True
            )
            if cfg.start_tls:
                svc.start_tls()
        except LDAPBindError as e:
            raise LdapError(f"service-account bind failed: {e}")
        except LDAPException as e:
            raise LdapError(f"LDAP connection failed: {e}")
        try:
            base = cfg.user_search_base or ""
            attrs = [cfg.email_attr, cfg.full_name_attr]
            if cfg.group_attr:
                attrs.append(cfg.group_attr)
            svc.search(
                base,
                build_filter(cfg.user_filter, username),
                SUBTREE,
                attributes=attrs,
            )
            if not svc.entries:
                return None
            entry = svc.entries[0]
            user_dn = entry.entry_dn
            email = _attr(entry, cfg.email_attr)
            full_name = _attr(entry, cfg.full_name_attr)
            groups = _attr_list(entry, cfg.group_attr)
        finally:
            svc.unbind()
    else:
        # No service account — attempt a direct bind with the typed identifier
        # (AD accepts userPrincipalName / DOMAIN\\user). We can't read
        # attributes in this mode, so the identifier doubles as the email.
        user_dn = username
        email = username

    # Verify the user's password by binding as them.
    try:
        user_conn = Connection(server, user_dn, password, auto_bind=True)
        if cfg.start_tls:
            user_conn.start_tls()
        user_conn.unbind()
    except LDAPBindError:
        return None  # wrong password / disabled account
    except LDAPException as e:
        raise LdapError(f"LDAP bind failed: {e}")

    return LdapIdentity(
        email=email or username,
        full_name=full_name,
        dn=user_dn or username,
        groups=groups,
    )


def _attr(entry, name: str) -> Optional[str]:
    try:
        v = entry[name].value
    except Exception:  # noqa: BLE001 — attribute absent
        return None
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return str(v) if v is not None else None


def _attr_list(entry, name: str) -> list[str]:
    try:
        v = entry[name].value
    except Exception:  # noqa: BLE001
        return []
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


async def authenticate(cfg: LdapSettings, username: str, password: str) -> Optional[LdapIdentity]:
    """Async wrapper — runs the blocking ldap3 flow in a thread."""
    return await asyncio.to_thread(_authenticate_sync, cfg, username, password)


__all__ = [
    "LdapError",
    "LdapSettings",
    "LdapIdentity",
    "authenticate",
    "settings_from_row",
    "resolve_default_role",
    "map_groups_to_role",
    "build_filter",
]
