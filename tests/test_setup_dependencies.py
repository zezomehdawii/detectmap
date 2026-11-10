"""Mocked installer prerequisite checks; never install packages/start services."""
from __future__ import annotations

from contextlib import ExitStack
import subprocess
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

import setup_dependencies as deps


def result(code=0, stdout="linux\n", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class DependencyRuntimeTests(unittest.TestCase):
    def ready(self, **overrides):
        defaults = {
            "_docker_path": "docker",
            "_compose_prefix": ["docker", "compose"],
            "_engine_result": result(),
        }
        defaults.update(overrides)
        stack = ExitStack()
        self.addCleanup(stack.close)
        mocks = {}
        for name, value in defaults.items():
            mocks[name] = stack.enter_context(patch.object(deps, name, return_value=value))
        return mocks

    def callbacks(self):
        return {"confirm": Mock(return_value=False), "prompt": Mock(return_value="q"), "log": Mock()}

    def test_ready_system_needs_no_install_start_or_prompts(self):
        self.ready()
        callbacks = self.callbacks()
        with patch.object(deps, "install_runtime") as install, patch.object(deps, "_start_daemon") as start:
            self.assertEqual(deps.ensure_runtime(**callbacks), ["docker", "compose"])
        install.assert_not_called()
        start.assert_not_called()
        callbacks["confirm"].assert_not_called()
        callbacks["prompt"].assert_not_called()

    def test_old_python_stops_before_any_dependency_change(self):
        with patch.object(deps.sys, "version_info", (3, 9)), patch.object(deps, "install_runtime") as install:
            with self.assertRaisesRegex(deps.DependencyError, "Python 3.10"):
                deps.ensure_runtime(**self.callbacks())
        install.assert_not_called()

    def test_missing_docker_is_installed_then_rechecked(self):
        mocks = self.ready()
        mocks["_docker_path"].side_effect = [None, "docker"]
        with patch.object(deps, "install_runtime") as install:
            self.assertEqual(deps.ensure_runtime(**self.callbacks()), ["docker", "compose"])
        self.assertFalse(install.call_args.kwargs["compose_only"])

    def test_install_needing_restart_gives_resume_message(self):
        self.ready(_docker_path=None)
        with patch.object(deps, "install_runtime"):
            with self.assertRaisesRegex(deps.DependencyError, "restart.*reopen the terminal"):
                deps.ensure_runtime(**self.callbacks())

    def test_compose_only_install_is_offered_when_engine_already_present(self):
        mocks = self.ready()
        mocks["_compose_prefix"].side_effect = [None, ["docker", "compose"]]
        with patch.object(deps, "install_runtime") as install:
            self.assertEqual(deps.ensure_runtime(**self.callbacks()), ["docker", "compose"])
        self.assertTrue(install.call_args.kwargs["compose_only"])

    def test_unavailable_compose_after_install_stops(self):
        self.ready(_compose_prefix=None)
        with patch.object(deps, "install_runtime"):
            with self.assertRaisesRegex(deps.DependencyError, "Compose v2"):
                deps.ensure_runtime(**self.callbacks())

    def test_fresh_desktop_first_start_does_not_run_installer_twice(self):
        mocks = self.ready(_compose_prefix=None)
        mocks["_docker_path"].side_effect = [None, "docker"]
        with patch.object(deps.platform, "system", return_value="Windows"), patch.object(deps, "install_runtime") as install:
            with self.assertRaisesRegex(deps.DependencyError, "first-start setup"):
                deps.ensure_runtime(**self.callbacks())
        install.assert_called_once()

    def test_stopped_daemon_start_and_wait_are_bounded(self):
        self.ready(_engine_result=result(1))
        with patch.object(deps, "_start_daemon", return_value=True), patch.object(deps, "_wait_for_engine", return_value=result()) as wait:
            self.assertEqual(deps.ensure_runtime(**self.callbacks()), ["docker", "compose"])
        wait.assert_called_once_with(["docker"])

    def test_declined_daemon_start_allows_user_to_stop_without_waiting(self):
        self.ready(_engine_result=result(1))
        with patch.object(deps, "_start_daemon", return_value=False), patch.object(deps, "_wait_for_engine") as wait:
            with self.assertRaisesRegex(deps.DependencyError, "Docker is not ready"):
                deps.ensure_runtime(**self.callbacks())
        wait.assert_not_called()

    def test_manual_daemon_retry_rechecks(self):
        self.ready(_engine_result=result(1))
        callbacks = self.callbacks()
        callbacks["prompt"].return_value = ""
        with patch.object(deps, "_start_daemon", return_value=False), patch.object(deps, "_wait_for_engine", return_value=result()) as wait:
            self.assertEqual(deps.ensure_runtime(**callbacks), ["docker", "compose"])
        wait.assert_called_once_with(["docker"], seconds=30)

    def test_daemon_still_unavailable_has_clear_failure(self):
        self.ready(_engine_result=result(1))
        callbacks = self.callbacks()
        callbacks["prompt"].return_value = ""
        with patch.object(deps, "_start_daemon", return_value=False), patch.object(deps, "_wait_for_engine", return_value=result(1)):
            with self.assertRaisesRegex(deps.DependencyError, "still unreachable"):
                deps.ensure_runtime(**callbacks)

    def test_windows_container_mode_is_rejected(self):
        self.ready(_engine_result=result(stdout="windows\n"))
        with self.assertRaisesRegex(deps.DependencyError, "Linux containers"):
            deps.ensure_runtime(**self.callbacks())

    def test_linux_permission_fallback_is_explicit_and_scopes_sudo_to_docker(self):
        mocks = self.ready()
        mocks["_engine_result"].side_effect = [result(1, stderr="permission denied"), result()]
        mocks["_compose_prefix"].side_effect = [["docker", "compose"], ["sudo", "docker", "compose"]]
        callbacks = self.callbacks()
        callbacks["confirm"].return_value = True
        with patch.object(deps.platform, "system", return_value="Linux"), patch.object(deps.shutil, "which", return_value="sudo"), patch.object(deps.subprocess, "run") as authorize:
            self.assertEqual(deps.ensure_runtime(**callbacks), ["sudo", "docker", "compose"])
        authorize.assert_called_once_with(["sudo", "-v"], check=True)
        self.assertEqual(mocks["_engine_result"].call_args_list, [call(["docker"]), call(["sudo", "docker"])])
        self.assertFalse(callbacks["confirm"].call_args.kwargs["default"])

    def test_failed_visible_sudo_authorization_stops_before_captured_probes(self):
        mocks = self.ready(_engine_result=result(1, stderr="permission denied"))
        callbacks = self.callbacks()
        callbacks["confirm"].return_value = True
        with patch.object(deps.platform, "system", return_value="Linux"), patch.object(deps.shutil, "which", return_value="sudo"), patch.object(deps.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["sudo", "-v"])) as authorize:
            with self.assertRaisesRegex(deps.DependencyError, "Could not authorize sudo"):
                deps.ensure_runtime(**callbacks)
        authorize.assert_called_once_with(["sudo", "-v"], check=True)
        mocks["_engine_result"].assert_called_once_with(["docker"])
        mocks["_compose_prefix"].assert_called_once_with("docker", [])

    def test_declined_sudo_does_not_attempt_service_changes(self):
        self.ready(_engine_result=result(1, stderr="permission denied"))
        with patch.object(deps.platform, "system", return_value="Linux"), patch.object(deps.shutil, "which", return_value="sudo"), patch.object(deps, "_start_daemon") as start:
            with self.assertRaisesRegex(deps.DependencyError, "access was denied"):
                deps.ensure_runtime(**self.callbacks())
        start.assert_not_called()


class InstallPlanTests(unittest.TestCase):
    def test_windows_offers_winget_without_accepting_agreements(self):
        with patch.object(deps.platform, "system", return_value="Windows"), patch.object(deps.shutil, "which", side_effect=lambda name: name if name == "winget" else None):
            plan = deps.installation_plan()
        self.assertEqual(plan, [deps.InstallStep(("winget", "install", "--exact", "--id", "Docker.DockerDesktop"))])
        self.assertNotIn("--accept-package-agreements", plan[0].argv)

    def test_macos_offers_current_desktop_cask(self):
        with patch.object(deps.platform, "system", return_value="Darwin"), patch.object(deps.shutil, "which", side_effect=lambda name: name if name == "brew" else None):
            self.assertEqual(deps.installation_plan()[0].argv, ("brew", "install", "--cask", "docker-desktop"))

    def test_missing_package_manager_has_official_manual_install_url(self):
        with patch.object(deps.platform, "system", return_value="Windows"), patch.object(deps.shutil, "which", return_value=None):
            with self.assertRaisesRegex(deps.DependencyError, "docs.docker.com/desktop/setup/install/windows-install"):
                deps.installation_plan()

    def linux_plan(self, compose_only=False, release=None):
        release = release or {"ID": "ubuntu", "VERSION_CODENAME": "noble"}
        with patch.object(deps, "_read_os_release", return_value=release), patch.object(deps, "_privilege_prefix", return_value=["sudo"]), patch.object(deps, "_probe", return_value=result(stdout="amd64\n")), patch.object(deps.shutil, "which", return_value="apt-get"):
            return deps._linux_install_plan(compose_only=compose_only)

    def test_linux_full_install_includes_signed_repo_engine_compose_and_buildx(self):
        plan = self.linux_plan()
        source_step = next(step for step in plan if step.stdin)
        self.assertIn("https://download.docker.com/linux/ubuntu", source_step.stdin)
        self.assertIn("Signed-By: /etc/apt/keyrings/docker.asc", source_step.stdin)
        self.assertEqual(source_step.argv, ("sudo", "tee", "/etc/apt/sources.list.d/docker.sources"))
        self.assertIn("docker-ce", plan[-1].argv)
        self.assertIn("docker-buildx-plugin", plan[-1].argv)
        self.assertIn("docker-compose-plugin", plan[-1].argv)
        self.assertTrue(all("remove" not in step.argv for step in plan))
        package_installs = [step for step in plan if "apt-get" in step.argv and "install" in step.argv]
        self.assertEqual(len(package_installs), 2)
        self.assertTrue(all("--no-remove" in step.argv for step in package_installs))

    def test_linux_compose_only_does_not_reinstall_engine(self):
        packages = self.linux_plan(compose_only=True)[-1].argv
        self.assertIn("docker-compose-plugin", packages)
        self.assertNotIn("docker-ce", packages)

    def test_debian_uses_its_own_repo(self):
        plan = self.linux_plan(release={"ID": "debian", "VERSION_CODENAME": "bookworm"})
        self.assertTrue(any(step.stdin and "linux/debian" in step.stdin and "bookworm" in step.stdin for step in plan))

    def test_distribution_and_suite_are_not_shell_input(self):
        for release in [{"ID": "fedora", "VERSION_CODENAME": "x"}, {"ID": "ubuntu", "VERSION_CODENAME": "noble\nInjected: true"}]:
            with patch.object(deps, "_read_os_release", return_value=release), patch.object(deps.shutil, "which", return_value="apt-get"):
                with self.assertRaises(deps.DependencyError):
                    deps._linux_install_plan(compose_only=False)

    def test_install_decline_runs_nothing_and_defaults_no(self):
        confirm = Mock(return_value=False)
        with patch.object(deps, "installation_plan", return_value=[deps.InstallStep(("fake-package-manager", "install", "docker"))]), patch.object(deps.subprocess, "run") as run:
            with self.assertRaisesRegex(deps.DependencyError, "declined"):
                deps.install_runtime(compose_only=False, confirm=confirm, log=Mock())
        run.assert_not_called()
        self.assertFalse(confirm.call_args.kwargs["default"])

    def test_confirmed_install_passes_repo_text_as_stdin_not_shell(self):
        step = deps.InstallStep(("sudo", "tee", "/etc/apt/sources.list.d/docker.sources"), "Types: deb\n")
        log = Mock()
        with patch.object(deps, "installation_plan", return_value=[step]), patch.object(deps.subprocess, "run") as run:
            deps.install_runtime(compose_only=True, confirm=Mock(return_value=True), log=log)
        run.assert_called_once_with(list(step.argv), input=step.stdin, text=True, check=True)
        self.assertTrue(log.called)

    def test_install_failure_reports_resume_instead_of_continuing(self):
        with patch.object(deps, "installation_plan", return_value=[deps.InstallStep(("fake", "install"))]), patch.object(deps.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["fake"])):
            with self.assertRaisesRegex(deps.DependencyError, "installation did not complete"):
                deps.install_runtime(compose_only=False, confirm=Mock(return_value=True), log=Mock())


class ProbeTests(unittest.TestCase):
    def test_compose_v1_is_rejected_but_modern_major_versions_work(self):
        for version, valid in [("1.29.2", False), ("v2.40.0", True), ("5.6.0", True), ("", False)]:
            with self.subTest(version=version), patch.object(deps, "_probe", return_value=result(stdout=version)):
                self.assertEqual(deps._modern_compose(["docker", "compose"]), valid)

    def test_probe_turns_timeout_into_unavailable(self):
        with patch.object(deps.subprocess, "run", side_effect=subprocess.TimeoutExpired(["docker"], 1)):
            self.assertNotEqual(deps._probe(["docker"]).returncode, 0)

    def test_engine_wait_has_a_deadline(self):
        with patch.object(deps.time, "monotonic", side_effect=[0, 0, 10, 10]), patch.object(deps.time, "sleep") as sleep, patch.object(deps, "_engine_result", return_value=result(1)) as probe:
            self.assertEqual(deps._wait_for_engine(["docker"], seconds=10).returncode, 1)
        self.assertEqual(probe.call_count, 2)
        sleep.assert_called_once()


class DaemonStartTests(unittest.TestCase):
    def test_declining_start_never_runs_service_commands(self):
        confirm = Mock(return_value=False)
        with patch.object(deps.platform, "system", return_value="Linux"), patch.object(deps.shutil, "which", return_value="systemctl"), patch.object(deps, "_privilege_prefix", return_value=["sudo"]), patch.object(deps.subprocess, "run") as run:
            self.assertFalse(deps._start_daemon(confirm=confirm, log=Mock()))
        run.assert_not_called()
        self.assertFalse(confirm.call_args.kwargs["default"])

    def test_linux_start_does_not_enable_service_or_change_groups(self):
        with patch.object(deps.platform, "system", return_value="Linux"), patch.object(deps.shutil, "which", return_value="systemctl"), patch.object(deps, "_privilege_prefix", return_value=["sudo"]), patch.object(deps.subprocess, "run") as run:
            self.assertTrue(deps._start_daemon(confirm=Mock(return_value=True), log=Mock()))
        run.assert_called_once_with(["sudo", "systemctl", "start", "docker"], check=True)

    def test_macos_start_uses_existing_desktop_app(self):
        with patch.object(deps.platform, "system", return_value="Darwin"), patch.object(deps.shutil, "which", return_value="open"), patch.object(deps.subprocess, "run") as run:
            self.assertTrue(deps._start_daemon(confirm=Mock(return_value=True), log=Mock()))
        run.assert_called_once_with(["open", "-a", "Docker"], check=True)

    def test_windows_start_requests_hidden_window(self):
        startup = SimpleNamespace(dwFlags=0, wShowWindow=1)
        with patch.object(deps.platform, "system", return_value="Windows"), patch.object(deps, "_desktop_path", return_value=Path("Docker Desktop.exe")), patch.object(deps.subprocess, "STARTUPINFO", return_value=startup, create=True), patch.object(deps.subprocess, "STARTF_USESHOWWINDOW", 1, create=True), patch.object(deps.subprocess, "CREATE_NO_WINDOW", 8, create=True), patch.object(deps.subprocess, "Popen") as run:
            self.assertTrue(deps._start_daemon(confirm=Mock(return_value=True), log=Mock()))
        self.assertEqual(startup.wShowWindow, 0)
        run.assert_called_once_with(["Docker Desktop.exe"], startupinfo=startup, creationflags=8)


if __name__ == "__main__":
    unittest.main()
