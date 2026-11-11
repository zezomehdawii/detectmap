"""Installer regression tests using temporary files and mocked system commands.

These checks never install packages, start Docker, or access a database.
Run from the repository root: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
SPEC = importlib.util.spec_from_file_location("detectmap_setup_flow", PROJECT_ROOT / "setup.py")
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


def env_values(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#"))


@contextmanager
def isolated_project():
    """Redirect every installer-owned file to one disposable directory."""
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
        root = Path(temporary)
        tls = root / "tls"
        for name, value in {
            "REPO_ROOT": root,
            "ENV_PATH": root / ".env",
            "ENV_EXAMPLE": root / ".env.example",
            "TLS_DIR": tls,
            "CADDYFILE": tls / "Caddyfile",
            "CERT_PATH": tls / "cert.pem",
            "KEY_PATH": tls / "key.pem",
        }.items():
            stack.enter_context(mock.patch.object(installer, name, value))
        for filename in ["docker-compose.yml", "docker-compose.tls.yml"]:
            (root / filename).write_bytes((PROJECT_ROOT / filename).read_bytes())
        yield root


@contextmanager
def mocked_flow(arguments, *, answer=None, confirms=None, choices=None, empty=True):
    """Mock every boundary that can mutate the host or the Docker deployment."""
    with ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ))
        stack.enter_context(mock.patch.object(sys, "argv", ["setup.py", *arguments]))
        runtime = stack.enter_context(mock.patch.object(
            installer, "ensure_runtime", return_value=["docker", "compose"]))
        compose = stack.enter_context(mock.patch.object(installer, "run_compose"))
        health = stack.enter_context(mock.patch.object(installer, "wait_for_backend"))
        status = stack.enter_context(mock.patch.object(installer, "deployment_is_empty", return_value=empty))
        initialize = stack.enter_context(mock.patch.object(installer, "run_initialization"))
        reset = stack.enter_context(mock.patch.object(installer, "run_factory_reset"))
        stack.enter_context(mock.patch.object(installer, "detect_host_ip", return_value="198.51.100.25"))
        stack.enter_context(mock.patch.object(installer, "prompt", side_effect=answer or (
            lambda question, default=None: default or "")))
        confirmation = stack.enter_context(mock.patch.object(installer, "confirm", side_effect=confirms or (
            lambda question, default=False: default)))
        selection = stack.enter_context(mock.patch.object(
            installer, "choose", side_effect=lambda question, options, default=None: (choices or {}).get(question, default)))
        for method in ["run", "check_call", "check_output", "Popen"]:
            stack.enter_context(mock.patch.object(installer.subprocess, method,
                side_effect=AssertionError("test attempted a real subprocess boundary")))
        output = stack.enter_context(redirect_stdout(io.StringIO()))
        yield {"runtime": runtime, "compose": compose, "health": health,
               "initialize": initialize, "reset": reset, "confirm": confirmation,
               "status": status, "choose": selection,
               "output": output}


def seed_saved_configuration(root, *, tls_mode="none", listen_port=8181):
    scheme = "http" if tls_mode == "none" else "https"
    with redirect_stdout(io.StringIO()):
        installer.write_env(
            server_host="saved.example", listen_port=listen_port, tls_mode=tls_mode,
            cors_origin=f"{scheme}://saved.example:{listen_port}",
            api_base="http://saved.example:8000" if tls_mode == "none" else "/api",
        )
    with (root / ".env").open("a", encoding="utf-8") as stream:
        stream.write("\n# Preserve custom operator settings too.\nOPERATOR_SETTING=keep-this-value\n")
    tls = root / "tls"
    tls.mkdir(exist_ok=True)
    for name in ["cert.pem", "key.pem", "Caddyfile"]:
        (tls / name).write_text(f"existing {name} content", encoding="utf-8")
    return (root / ".env").read_bytes(), {p.name: p.read_bytes() for p in tls.iterdir()}


def assert_kept_files(testcase, root, original_env, original_tls):
    testcase.assertEqual((root / ".env").read_bytes(), original_env)
    for name, data in original_tls.items():
        testcase.assertEqual((root / "tls" / name).read_bytes(), data)


class EnvironmentConfigurationTests(unittest.TestCase):
    def test_selected_http_port_and_browser_endpoints_are_consistent(self):
        with isolated_project() as root, redirect_stdout(io.StringIO()):
            installer.write_env(
                server_host="192.0.2.25", listen_port=8181, tls_mode="none",
                cors_origin="http://192.0.2.25:8181", api_base="http://192.0.2.25:8000",
            )
            values = env_values(root / ".env")
            self.assertEqual(values["DETECTMAP_HTTP_PORT"], "8181")
            self.assertEqual(values["DETECTMAP_LISTEN_PORT"], "8181")
            self.assertEqual(values["CORS_ORIGINS"], "http://192.0.2.25:8181")
            self.assertEqual(values["NEXT_PUBLIC_API_BASE"], "http://192.0.2.25:8000")
            self.assertEqual(values["DEFAULT_LOGIN_EMAIL"], "admin@demo.local")
            self.assertEqual(values["DEFAULT_LOGIN_PASSWORD"], "change-me")
            # The selected setting must actually drive the frontend mapping.
            compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("${DETECTMAP_HTTP_PORT:-3000}:3000", compose)

    def test_tls_uses_selected_proxy_port_and_same_origin_api(self):
        with isolated_project() as root, redirect_stdout(io.StringIO()):
            installer.write_env(
                server_host="training.example", listen_port=9443, tls_mode="self-signed",
                cors_origin="https://training.example:9443", api_base="/api",
            )
            values = env_values(root / ".env")
            self.assertEqual(values["TLS_LISTEN_PORT"], "9443")
            self.assertEqual(values["DETECTMAP_LISTEN_PORT"], "9443")
            self.assertEqual(values["NEXT_PUBLIC_API_BASE"], "/api")
            self.assertEqual(values["CORS_ORIGINS"], "https://training.example:9443")
            self.assertNotEqual(values["DETECTMAP_HTTP_PORT"], "9443")

    def test_new_environment_has_usable_distinct_secrets(self):
        with isolated_project() as root, redirect_stdout(io.StringIO()):
            installer.write_env(
                server_host="localhost", listen_port=8080, tls_mode="none",
                cors_origin="http://localhost:8080", api_base="http://localhost:8000",
            )
            values = env_values(root / ".env")
            keys = ["POSTGRES_PASSWORD", "JWT_TENANT_SECRET", "JWT_SUPERADMIN_SECRET", "INTERNAL_API_KEY"]
            secrets = [values[key] for key in keys]
            self.assertEqual(len(secrets), len(set(secrets)))
            self.assertTrue(all(len(secret) >= 24 for secret in secrets))
            self.assertEqual(len(base64.urlsafe_b64decode(values["FERNET_KEY"])), 32)
            self.assertIn("${POSTGRES_PASSWORD}", values["DATABASE_URL"])
            self.assertIn("${POSTGRES_PASSWORD}", values["DATABASE_URL_SYNC"])

    def test_legacy_environment_uses_the_existing_browser_origin(self):
        value = installer.deployment_from_env({
            "CORS_ORIGINS": "http://saved.example:8181,http://localhost:3001",
            "NEXT_PUBLIC_API_BASE": "http://saved.example:8000",
        })
        self.assertEqual(value["server_host"], "saved.example")
        self.assertEqual(value["listen_port"], 8181)
        self.assertEqual(value["public_url"], "http://saved.example:8181")

    def test_fresh_environment_writer_cannot_rotate_an_existing_installation(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with self.assertRaises(ValueError):
                installer.write_env(
                    server_host="new.example", listen_port=8080, tls_mode="none",
                    cors_origin="http://new.example:8080", api_base="http://new.example:8000",
                )
            assert_kept_files(self, root, original_env, original_tls)

    def test_reconfigure_removes_obsolete_duplicate_network_settings(self):
        with isolated_project() as root, redirect_stdout(io.StringIO()):
            seed_saved_configuration(root)
            path = root / ".env"
            before = env_values(path)
            with path.open("a", encoding="utf-8") as stream:
                stream.write("CORS_ORIGINS=http://obsolete.example:3000\nDETECTMAP_HTTP_PORT=3000\n")
            installer.update_network_env(
                server_host="new.example", listen_port=8181, tls_mode="none",
                cors_origin="http://new.example:8181", api_base="http://new.example:8000",
            )
            after = env_values(path)
            self.assertEqual(after["CORS_ORIGINS"], "http://new.example:8181")
            self.assertEqual(after["DETECTMAP_HTTP_PORT"], "8181")
            self.assertEqual(after["FERNET_KEY"], before["FERNET_KEY"])
            self.assertEqual(after["OPERATOR_SETTING"], before["OPERATOR_SETTING"])
            self.assertEqual(sum(line.startswith("CORS_ORIGINS=") for line in path.read_text(encoding="utf-8").splitlines()), 1)


class InteractiveSetupFlowTests(unittest.TestCase):
    def test_fresh_defaults_create_a_usable_http_configuration_and_initialize_admins(self):
        with isolated_project() as root, mocked_flow([]) as calls:
            installer.main()
            values = env_values(root / ".env")
            self.assertEqual(values["DETECTMAP_SERVER_HOST"], "198.51.100.25")
            self.assertEqual(values["DETECTMAP_HTTP_PORT"], "8080")
            self.assertEqual(values["CORS_ORIGINS"], "http://198.51.100.25:8080")
            self.assertEqual(values["DEFAULT_LOGIN_EMAIL"], "admin@demo.local")
            self.assertEqual(values["DEFAULT_LOGIN_PASSWORD"], "change-me")
            self.assertIn("http://198.51.100.25:8080", calls["output"].getvalue())
            calls["runtime"].assert_called_once()
            calls["compose"].assert_called_once()
            calls["health"].assert_called_once()
            calls["status"].assert_called_once_with(["docker", "compose"], False)
            calls["initialize"].assert_called_once()
            self.assertEqual(calls["initialize"].call_args.args[2], values["DEFAULT_LOGIN_EMAIL"])
            self.assertEqual(calls["initialize"].call_args.kwargs, {"mode": "single", "sample_data": "fresh"})
            self.assertIn("Settings -> Deployment", calls["output"].getvalue())
            calls["reset"].assert_not_called()

    def test_empty_database_can_choose_multi_tenant_and_sample_data_with_saved_env(self):
        choices = {"How will you use Detect Map?": "multi_tenant",
                   "What data should Detect Map start with?": "sample"}
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow(["--keep-env"], choices=choices) as calls:
                installer.main()
                calls["initialize"].assert_called_once_with(
                    ["docker", "compose"], False, None, "super@detectmap.local",
                    mode="multi_tenant", sample_data="sample")
                assert_kept_files(self, root, original_env, original_tls)

    def test_custom_fresh_admin_email_matches_the_configured_login_hint(self):
        def answers(question, default=None):
            return " Trainer@Example.Local " if question == "Email for the MSSP administrator" else default or ""

        with isolated_project() as root, mocked_flow([], answer=answers) as calls:
            installer.main()
            values = env_values(root / ".env")
            self.assertEqual(values["DEFAULT_LOGIN_EMAIL"], "trainer@example.local")
            self.assertEqual(values["DEFAULT_LOGIN_PASSWORD"], "change-me")
            self.assertEqual(calls["initialize"].call_args.args[2], values["DEFAULT_LOGIN_EMAIL"])

    def test_rerun_keeps_configured_hint_identity_and_password_unchanged(self):
        with isolated_project() as root:
            seed_saved_configuration(root)
            path = root / ".env"
            path.write_text(path.read_text(encoding="utf-8")
                            .replace("DEFAULT_LOGIN_EMAIL=admin@demo.local", "DEFAULT_LOGIN_EMAIL=trainer@example.local")
                            .replace("DEFAULT_LOGIN_PASSWORD=change-me", "DEFAULT_LOGIN_PASSWORD=operator-default"), encoding="utf-8")
            before = path.read_bytes()

            def answers(question, default=None):
                self.assertNotEqual(question, "Email for the MSSP administrator")
                return default or ""

            with mocked_flow(["--keep-env"], answer=answers) as calls:
                installer.main()
                self.assertEqual(path.read_bytes(), before)
                self.assertIsNone(calls["initialize"].call_args.args[2])

    def test_fresh_self_signed_setup_writes_environment_before_container_certificate_step(self):
        with isolated_project() as root, mocked_flow([], choices={
            "How should the dashboard be served?": "self-signed",
        }) as calls:
            def generate(host, compose):
                # Compose's backend has env_file=.env even during this first
                # certificate build, so it must already exist at this point.
                self.assertTrue((root / ".env").is_file())
                values = env_values(root / ".env")
                self.assertEqual(values["NEXT_PUBLIC_API_BASE"], "/api")
                self.assertEqual(values["TLS_LISTEN_PORT"], "8443")
                self.assertEqual(host, "198.51.100.25")
                self.assertEqual(compose, ["docker", "compose"])
                (root / "tls").mkdir()
                (root / "tls" / "cert.pem").write_text("generated certificate", encoding="utf-8")
                (root / "tls" / "key.pem").write_text("generated key", encoding="utf-8")

            with mock.patch.object(installer, "generate_self_signed", side_effect=generate) as certificate:
                installer.main()
            certificate.assert_called_once()
            self.assertTrue((root / "tls" / "Caddyfile").is_file())
            self.assertIn("https://198.51.100.25:8443", calls["output"].getvalue())
            self.assertTrue(calls["compose"].call_args.kwargs["tls"])
            calls["initialize"].assert_called_once()
            calls["reset"].assert_not_called()

    def test_keep_env_and_skip_reset_preserve_secrets_tls_and_actual_url(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow(["--keep-env", "--skip-reset"], empty=False) as calls:
                installer.main()
                assert_kept_files(self, root, original_env, original_tls)
                self.assertIn("http://saved.example:8181", calls["output"].getvalue())
                self.assertNotIn("http://198.51.100.25:", calls["output"].getvalue())
                calls["initialize"].assert_not_called()
                calls["choose"].assert_not_called()
                calls["reset"].assert_not_called()
    def test_existing_environment_is_preserved_by_default_without_special_flags(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow([], empty=False) as calls:
                installer.main()
                assert_kept_files(self, root, original_env, original_tls)
                self.assertIn("http://saved.example:8181", calls["output"].getvalue())
                self.assertIn("Existing deployment detected", calls["output"].getvalue())
                calls["initialize"].assert_not_called()
                calls["choose"].assert_not_called()
                calls["reset"].assert_not_called()

    def test_declined_dependency_setup_cannot_change_environment_or_start_stack(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow([]) as calls:
                calls["runtime"].side_effect = installer.DependencyError("dependency installation declined")
                try:
                    installer.main()
                except installer.DependencyError:
                    pass
                except SystemExit as exc:
                    self.assertNotEqual(exc.code, 0)
                assert_kept_files(self, root, original_env, original_tls)
                calls["compose"].assert_not_called()
                calls["health"].assert_not_called()
                calls["initialize"].assert_not_called()
                calls["reset"].assert_not_called()

    def test_declining_explicit_reset_leaves_deployment_unchanged(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow(["--reset"], confirms=lambda question, default=False: False) as calls:
                try:
                    installer.main()
                except SystemExit as exc:
                    self.assertIn(exc.code, (0, 130, None))
                assert_kept_files(self, root, original_env, original_tls)
                calls["reset"].assert_not_called()
                calls["compose"].assert_not_called()
                calls["initialize"].assert_not_called()
                self.assertTrue(calls["confirm"].called)
                self.assertTrue(any(call.kwargs.get("default", False) is False
                                    for call in calls["confirm"].call_args_list))

    def test_confirmed_reset_prompts_for_new_mode_and_data_without_probing_empty_database(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root)
            with mocked_flow(["--reset", "--keep-env"], confirms=lambda *_args, **_kwargs: True,
                             choices={"What data should Detect Map start with?": "sample"}) as calls:
                installer.main()
                calls["status"].assert_not_called()
                calls["initialize"].assert_not_called()
                calls["reset"].assert_called_once_with(
                    ["docker", "compose"], False, None, "super@detectmap.local",
                    mode="single", sample_data="sample")
                assert_kept_files(self, root, original_env, original_tls)

    def test_reconfigure_changes_network_only_and_keeps_old_tls_material(self):
        with isolated_project() as root:
            original_env, original_tls = seed_saved_configuration(root, tls_mode="self-signed", listen_port=9443)
            before = env_values(root / ".env")
            with mocked_flow(["--skip-reset"], confirms=lambda question, default=False: False,
                             choices={"How should the dashboard be served?": "none"}) as calls:
                installer.main()
                after = env_values(root / ".env")
                for key in ["POSTGRES_PASSWORD", "JWT_TENANT_SECRET", "JWT_SUPERADMIN_SECRET",
                            "FERNET_KEY", "INTERNAL_API_KEY", "OPERATOR_SETTING",
                            "DEFAULT_LOGIN_EMAIL", "DEFAULT_LOGIN_PASSWORD"]:
                    self.assertEqual(after[key], before[key])
                self.assertEqual(after["DETECTMAP_TLS_MODE"], "none")
                self.assertEqual(after["DETECTMAP_HTTP_PORT"], "8080")
                for name, data in original_tls.items():
                    self.assertEqual((root / "tls" / name).read_bytes(), data)
                calls["reset"].assert_not_called()

    def test_invalid_saved_network_can_be_repaired_without_rotating_secrets(self):
        with isolated_project() as root:
            seed_saved_configuration(root)
            path = root / ".env"
            path.write_text(path.read_text(encoding="utf-8").replace("DETECTMAP_HTTP_PORT=8181", "DETECTMAP_HTTP_PORT=invalid"), encoding="utf-8")
            before = env_values(path)
            with mocked_flow(["--skip-reset"], confirms=lambda question, default=False: False) as calls:
                installer.main()
                after = env_values(path)
                self.assertEqual(after["DETECTMAP_HTTP_PORT"], "8080")
                self.assertEqual(after["FERNET_KEY"], before["FERNET_KEY"])
                self.assertEqual(after["POSTGRES_PASSWORD"], before["POSTGRES_PASSWORD"])
                self.assertIn("http://198.51.100.25:8080", calls["output"].getvalue())

    def test_keep_env_refuses_invalid_saved_port_without_changing_files(self):
        with isolated_project() as root:
            _, original_tls = seed_saved_configuration(root)
            path = root / ".env"
            path.write_text(path.read_text(encoding="utf-8").replace("DETECTMAP_HTTP_PORT=8181", "DETECTMAP_HTTP_PORT=invalid"), encoding="utf-8")
            original_env = path.read_bytes()
            with mocked_flow(["--keep-env", "--skip-reset"]) as calls:
                with self.assertRaises(ValueError):
                    installer.main()
                assert_kept_files(self, root, original_env, original_tls)
                calls["compose"].assert_not_called()
                calls["initialize"].assert_not_called()

    def test_invalid_admin_identity_fails_before_environment_write_or_startup(self):
        def answers(question, default=None):
            return "admin@local" if question == "Email for the MSSP administrator" else default or ""

        with isolated_project() as root, mocked_flow([], answer=answers) as calls:
            with self.assertRaises(ValueError):
                installer.main()
            self.assertFalse((root / ".env").exists())
            calls["compose"].assert_not_called()
            calls["initialize"].assert_not_called()


class ResetConfigurationTests(unittest.TestCase):
    def test_explicit_reset_requests_configured_login_defaults_without_password_arguments(self):
        with mock.patch.object(installer, "run_compose") as compose:
            installer.run_factory_reset(
                ["docker", "compose"], False, "admin@demo.local", "super@detectmap.local",
                mode="multi_tenant", sample_data="sample")
        arguments = compose.call_args.args[1]
        self.assertIn("--use-login-defaults", arguments)
        self.assertIn("--yes", arguments)
        self.assertNotIn("--admin-password", arguments)
        self.assertNotIn("--super-password", arguments)
        self.assertEqual(arguments[-6:], [
            "--deployment-mode", "multi_tenant", "--sample-data", "sample",
            "--admin-email", "admin@demo.local",
        ])


class InitialDeploymentProbeTests(unittest.TestCase):
    def test_status_requires_a_boolean_response(self):
        for invalid_status in ('{"empty": "false"}', '[]', 'bad status'):
            with self.subTest(status=invalid_status), mock.patch.object(
                installer.subprocess, "check_output", return_value=invalid_status,
            ), self.assertRaises(RuntimeError):
                installer.deployment_is_empty(["docker", "compose"], False)

    def test_valid_status_is_read_without_running_initialization(self):
        with mock.patch.object(installer.subprocess, "check_output", return_value='{"empty": false}\n') as check:
            self.assertFalse(installer.deployment_is_empty(["docker", "compose"], False))
        self.assertEqual(check.call_args.args[0][-3:], ["-m", "app.scripts.initialize_admins", "--status-only"])


class CertificateCopyTests(unittest.TestCase):
    def test_already_placed_byo_certificate_and_key_are_accepted(self):
        with isolated_project() as root, redirect_stdout(io.StringIO()):
            tls = root / "tls"
            tls.mkdir()
            cert, key = tls / "cert.pem", tls / "key.pem"
            cert.write_bytes(b"existing supplied certificate")
            key.write_bytes(b"existing supplied key")
            installer.copy_user_cert(cert, key)
            self.assertEqual(cert.read_bytes(), b"existing supplied certificate")
            self.assertEqual(key.read_bytes(), b"existing supplied key")


if __name__ == "__main__":
    unittest.main()
