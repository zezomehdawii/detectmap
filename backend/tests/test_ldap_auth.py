"""Unit tests for LDAP auth helpers (pure functions, no directory needed).

The escaping test is the security-critical one: it proves a hostile login
identifier can't break out of the search filter (LDAP injection).
"""
from dataclasses import replace

from app.services.ldap_auth import (
    LdapSettings,
    build_filter,
    map_groups_to_role,
    resolve_default_role,
)

_BASE = LdapSettings(
    host="ldaps://dc.corp.local:636",
    bind_dn=None,
    bind_password=None,
    user_search_base="DC=corp,DC=local",
    user_filter="(sAMAccountName={username})",
    email_attr="mail",
    full_name_attr="displayName",
    default_role="mssp_readonly",
    start_tls=False,
    verify_cert=True,
)


class TestBuildFilter:
    def test_plain_username(self):
        assert build_filter("(sAMAccountName={username})", "jdoe") == "(sAMAccountName=jdoe)"

    def test_escapes_filter_injection(self):
        # A classic LDAP-injection payload must be neutralised — the special
        # characters get hex-escaped, so the filter still has exactly one term.
        out = build_filter("(sAMAccountName={username})", "*)(uid=*))(|(uid=*")
        assert "*)(uid=*" not in out
        assert r"\2a" in out  # '*' escaped
        assert r"\28" in out  # '(' escaped
        assert r"\29" in out  # ')' escaped

    def test_escapes_parentheses_and_backslash(self):
        out = build_filter("(mail={username})", "a)b(c\\d")
        assert ")" not in out.replace("(mail=", "").rstrip(")")
        assert r"\5c" in out  # backslash escaped

    def test_upn_filter_template(self):
        assert (
            build_filter("(userPrincipalName={username})", "jdoe@corp.local")
            == "(userPrincipalName=jdoe@corp.local)"
        )


class TestResolveDefaultRole:
    def test_valid_mssp_roles_passthrough(self):
        for role in ("mssp_admin", "mssp_analyst", "mssp_readonly"):
            assert resolve_default_role(replace(_BASE, default_role=role)) == role

    def test_invalid_role_falls_back_to_readonly(self):
        # Never let a non-MSSP / bogus role through — least privilege.
        assert resolve_default_role(replace(_BASE, default_role="product_super_admin")) == "mssp_readonly"
        assert resolve_default_role(replace(_BASE, default_role="customer_user")) == "mssp_readonly"
        assert resolve_default_role(replace(_BASE, default_role="garbage")) == "mssp_readonly"


class TestMapGroupsToRole:
    def _cfg(self, mappings):
        return replace(_BASE, group_mappings=mappings)

    def test_no_mappings_returns_none(self):
        assert map_groups_to_role(self._cfg({}), ["CN=SOC,OU=G,DC=corp"]) is None

    def test_substring_match_on_dn(self):
        cfg = self._cfg({"SOC-Admins": "mssp_admin"})
        groups = ["CN=SOC-Admins,OU=Groups,DC=corp,DC=local"]
        assert map_groups_to_role(cfg, groups) == "mssp_admin"

    def test_case_insensitive(self):
        cfg = self._cfg({"soc-analysts": "mssp_analyst"})
        assert map_groups_to_role(cfg, ["CN=SOC-Analysts,DC=corp"]) == "mssp_analyst"

    def test_highest_privilege_wins_on_multiple_matches(self):
        cfg = self._cfg({"Analysts": "mssp_analyst", "Admins": "mssp_admin"})
        groups = ["CN=Analysts,DC=corp", "CN=Admins,DC=corp"]
        assert map_groups_to_role(cfg, groups) == "mssp_admin"

    def test_no_match_returns_none(self):
        cfg = self._cfg({"SOC-Admins": "mssp_admin"})
        assert map_groups_to_role(cfg, ["CN=Helpdesk,DC=corp"]) is None

    def test_invalid_target_role_ignored(self):
        cfg = self._cfg({"Everyone": "product_super_admin"})
        assert map_groups_to_role(cfg, ["CN=Everyone,DC=corp"]) is None
