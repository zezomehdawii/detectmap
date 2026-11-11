"""Reset credential modes and preflight validation; no live database access."""
import argparse
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.models.public import SuperAdmin, User
from app.scripts import factory_reset as reset
from app.scripts import initialize_admins as initial


def arguments(**overrides):
    values = dict(
        mssp_name="Test MSSP", admin_email=None, admin_password=None,
        super_email="super@example.local", super_password=None,
        use_login_defaults=True, yes=True,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture
def reset_calls(monkeypatch):
    calls = SimpleNamespace(
        drop=AsyncMock(return_value=[]), wipe=AsyncMock(), seed=AsyncMock(),
        counts=AsyncMock(return_value={}), generate=Mock(return_value="super-temporary"),
    )
    monkeypatch.setattr(reset, "_drop_customer_schemas", calls.drop)
    monkeypatch.setattr(reset, "_wipe_public_tenant_state", calls.wipe)
    monkeypatch.setattr(reset, "_seed_admin", calls.seed)
    monkeypatch.setattr(reset, "_summarise_preserved", calls.counts)
    monkeypatch.setattr(reset, "_gen_password", calls.generate)
    monkeypatch.setattr(initial, "settings", SimpleNamespace(
        default_login_email="admin@demo.local", default_login_password="change-me",
    ))
    return calls


@pytest.mark.asyncio
async def test_opted_in_reset_uses_matching_dashboard_defaults_and_generated_super(reset_calls, capsys):
    assert await reset._amain(arguments()) == 0
    reset_calls.drop.assert_awaited_once()
    reset_calls.wipe.assert_awaited_once()
    reset_calls.generate.assert_called_once()
    reset_calls.seed.assert_awaited_once_with(
        mssp_name="Test MSSP", admin_email="admin@demo.local", admin_password="change-me",
        super_email="super@example.local", super_password="super-temporary", use_login_defaults=True,
    )
    output = capsys.readouterr().out
    assert "Settings -> Branding" in output
    assert "Both accounts will be required" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("configured_email,password,overrides,error", [
    ("invalid", "change-me", {}, "DEFAULT_LOGIN_EMAIL"),
    ("admin@demo.local", "", {}, "DEFAULT_LOGIN_PASSWORD"),
    ("admin@demo.local", "short", {}, "DEFAULT_LOGIN_PASSWORD"),
    ("admin@demo.local", "x" * 73, {}, "72-byte limit"),
    ("admin@demo.local", "change-me", {"admin_email": "other@example.local"}, "must match"),
    ("admin@demo.local", "change-me", {"admin_password": "override-password"}, "cannot be combined"),
    ("admin@demo.local", "change-me", {"super_email": "invalid"}, "valid email"),
])
async def test_opted_in_reset_rejects_invalid_hint_before_destructive_calls(
    monkeypatch, reset_calls, configured_email, password, overrides, error,
):
    monkeypatch.setattr(initial, "settings", SimpleNamespace(
        default_login_email=configured_email, default_login_password=password,
    ))
    with pytest.raises(ValueError, match=error):
        await reset._amain(arguments(**overrides))
    reset_calls.drop.assert_not_awaited()
    reset_calls.wipe.assert_not_awaited()
    reset_calls.seed.assert_not_awaited()
    reset_calls.generate.assert_not_called()


@pytest.mark.asyncio
async def test_legacy_reset_still_generates_two_passwords_with_legacy_email(reset_calls, capsys):
    reset_calls.generate.side_effect = ["admin-temporary", "super-temporary"]
    assert await reset._amain(arguments(use_login_defaults=False)) == 0
    assert reset_calls.generate.call_count == 2
    reset_calls.seed.assert_awaited_once_with(
        mssp_name="Test MSSP", admin_email="admin@detectmap.local", admin_password="admin-temporary",
        super_email="super@example.local", super_password="super-temporary", use_login_defaults=False,
    )
    assert "Both accounts will be required" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cancelled_reset_never_reaches_destructive_calls(monkeypatch, reset_calls):
    monkeypatch.setattr("builtins.input", lambda _: "cancel")
    assert await reset._amain(arguments(yes=False)) == 1
    reset_calls.drop.assert_not_awaited()
    reset_calls.wipe.assert_not_awaited()
    reset_calls.seed.assert_not_awaited()


class Context:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize("use_defaults", [True, False])
async def test_seeded_hint_and_dashboard_rotation_match_selected_mode(monkeypatch, use_defaults):
    added = []
    session = SimpleNamespace(add=added.append, flush=AsyncMock(), execute=AsyncMock(), begin=lambda: Context())
    monkeypatch.setattr(reset, "AsyncSessionLocal", lambda: Context(session))
    monkeypatch.setattr(reset, "hash_password", lambda value: "hashed:" + value)
    await reset._seed_admin(
        mssp_name="Test", admin_email="admin@example.local", admin_password="dashboard-password",
        super_email="super@example.local", super_password="super-temporary", use_login_defaults=use_defaults,
    )
    admin = next(item for item in added if isinstance(item, User))
    super_admin = next(item for item in added if isinstance(item, SuperAdmin))
    settings_upsert = session.execute.await_args.args[0].compile()
    assert admin.hashed_password == "hashed:dashboard-password"
    assert admin.must_change_password is not use_defaults
    assert super_admin.must_change_password is True
    assert settings_upsert.params["show_login_hint"] is use_defaults


def test_cli_accepts_use_login_defaults_without_password_argument(monkeypatch):
    action = AsyncMock(return_value=0)
    monkeypatch.setattr(reset, "_amain", action)
    monkeypatch.setattr(reset.sys, "argv", ["factory-reset", "--yes", "--use-login-defaults"])
    with pytest.raises(SystemExit) as result:
        reset.main()
    assert result.value.code == 0
    args = action.await_args.args[0]
    assert args.use_login_defaults and args.yes
    assert args.admin_email is None and args.admin_password is None
