"""Initialization safety and TLS regressions; no database or service access."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import pytest

from app.models.public import MSSPOrg, Role, SuperAdmin, User
from app.scripts import initialize_admins as initial
from app.scripts.generate_tls import generate_certificate


class Transaction:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.session.committed = exc_type is None
        if exc_type is None and self.session.fail_commit:
            raise RuntimeError("simulated commit failure")


class Session:
    def __init__(self, counts, *, fail_commit=False):
        self.counts = iter(counts)
        self.fail_commit = fail_commit
        self.committed = False
        self.added = []
        self.queries = []
        self.statements = []
        self.flush = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def begin(self):
        return Transaction(self)

    async def execute(self, query, params=None):
        self.queries.append((str(query), params))
        self.statements.append(query)
        # The advisory lock is not an ownership probe.
        is_probe = "pg_advisory_xact_lock" not in str(query) and not str(query).startswith("INSERT INTO public.app_settings")
        count = next(self.counts) if is_probe else None
        return SimpleNamespace(scalar_one=lambda: count)

    def add(self, value):
        self.added.append(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("counts", [[1], [0, 1], [0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 0, True]])
async def test_existing_state_never_creates_accounts_or_generates_passwords(monkeypatch, counts):
    session = Session(counts)
    monkeypatch.setattr(initial, "AsyncSessionLocal", lambda: session)
    generate = Mock(side_effect=AssertionError("existing deployment must not generate credentials"))
    monkeypatch.setattr(initial.secrets, "token_urlsafe", generate)
    result = await initial.initialize_admins()
    assert not result.empty and not result.created
    assert session.added == [] and session.committed
    assert "pg_advisory_xact_lock" in session.queries[0][0]
    assert not any("INSERT INTO public.app_settings" in query for query, _ in session.queries)


@pytest.mark.asyncio
async def test_fresh_initialization_creates_two_forced_change_accounts_after_commit(monkeypatch):
    session = Session([0, 0, 0, 0, False])
    monkeypatch.setattr(initial, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(initial.secrets, "token_urlsafe", Mock(side_effect=["admin-temporary", "super-temporary"]))
    monkeypatch.setattr(initial, "hash_password", lambda value: "hashed:" + value)
    output = io.StringIO()
    with redirect_stdout(output):
        result = await initial.initialize_admins(admin_email=" ADMIN@EXAMPLE.LOCAL ", super_email=" SUPER@EXAMPLE.LOCAL ")
    assert output.getvalue() == ""  # The transaction function never prints secrets.
    assert session.committed and result.created
    assert len(session.added) == 3
    org, admin, super_admin = session.added
    assert isinstance(org, MSSPOrg) and isinstance(admin, User) and isinstance(super_admin, SuperAdmin)
    assert admin.role == Role.MSSP_ADMIN and admin.mssp_org_id == org.id
    assert admin.email == "admin@example.local" and super_admin.email == "super@example.local"
    assert admin.must_change_password and super_admin.must_change_password
    assert admin.hashed_password == "hashed:admin-temporary"
    assert super_admin.hashed_password == "hashed:super-temporary"
    assert "admin-temporary" not in repr(result)
    with redirect_stdout(output):
        initial.print_result(result)
    assert output.getvalue().count("admin-temporary") == 1
    assert output.getvalue().count("super-temporary") == 1


@pytest.mark.asyncio
async def test_new_administrators_hide_placeholder_login_without_resetting_other_settings(monkeypatch):
    session = Session([0, 0, 0, 0, False])
    monkeypatch.setattr(initial, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(initial, "hash_password", lambda _: "hash")
    await initial.initialize_admins()
    statement = next(query for query in session.statements if str(query).startswith("INSERT INTO public.app_settings"))
    compiled = statement.compile()
    assert compiled.params["show_login_hint"] is False
    update = str(compiled).split("DO UPDATE SET", 1)[1]
    assert update.strip().startswith("show_login_hint =")
    assert "," not in update  # No other existing singleton settings are replaced.


@pytest.mark.asyncio
async def test_status_only_reports_empty_without_password_generation_or_mutation(monkeypatch):
    session = Session([0, 0, 0, 0, False])
    monkeypatch.setattr(initial, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(initial.secrets, "token_urlsafe", Mock(side_effect=AssertionError("status must not generate credentials")))
    result = await initial.initialize_admins(status_only=True)
    assert result.empty and not result.created and session.added == []
    output = io.StringIO()
    with redirect_stdout(output):
        initial.print_result(result, status_only=True)
    assert output.getvalue().strip() == '{"empty": true}'


@pytest.mark.asyncio
async def test_failed_commit_returns_no_credentials_or_printed_passwords(monkeypatch):
    session = Session([0, 0, 0, 0, False], fail_commit=True)
    monkeypatch.setattr(initial, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(initial, "hash_password", lambda _: "hash")
    output = io.StringIO()
    with redirect_stdout(output), pytest.raises(RuntimeError, match="commit failure"):
        await initial.initialize_admins()
    assert output.getvalue() == ""


@pytest.mark.parametrize("host", ["hmi.example.local", "192.0.2.44", "2001:db8::1"])
def test_generated_certificate_matches_host_and_localhost_with_matching_private_key(host):
    with TemporaryDirectory() as temporary:
        cert_path, key_path = generate_certificate(host, Path(temporary))
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert "localhost" in sans.get_values_for_type(x509.DNSName)
        import ipaddress
        if ":" in host or host.startswith("192."):
            assert ipaddress.ip_address(host) in sans.get_values_for_type(x509.IPAddress)
        else:
            assert host in sans.get_values_for_type(x509.DNSName)
        assert cert.not_valid_before_utc < datetime.now(timezone.utc) < cert.not_valid_after_utc
        if os.name == "posix":
            assert key_path.stat().st_mode & 0o777 == 0o600
        assert sorted(p.name for p in Path(temporary).iterdir()) == ["cert.pem", "key.pem"]


@pytest.mark.parametrize("host", ["https://host", "host/path", "host:8080", "", "a" * 254])
def test_invalid_certificate_host_does_not_create_output(host):
    with TemporaryDirectory() as temporary:
        target = Path(temporary) / "new-tls"
        with pytest.raises(ValueError):
            generate_certificate(host, target)
        assert not target.exists()
