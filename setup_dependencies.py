"""Interactive Docker prerequisites for setup.py (standard library only).

Installation and service startup are opt-in. Application dependencies are
installed by the project's Dockerfiles, not into the host Python environment.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Callable


class DependencyError(RuntimeError):
    """An actionable prerequisite failure, without terminating the caller."""


INSTALL_URLS = {
    "Windows": "https://docs.docker.com/desktop/setup/install/windows-install/",
    "Darwin": "https://docs.docker.com/desktop/setup/install/mac-install/",
    "Linux": "https://docs.docker.com/engine/install/",
}
COMPOSE_URL = "https://docs.docker.com/compose/install/linux/"


@dataclass(frozen=True)
class InstallStep:
    argv: tuple[str, ...]
    stdin: str | None = None


def _probe(argv: list[str], *, timeout: float = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(argv, 1, "", "command unavailable or timed out")


def _docker_path() -> str | None:
    found = shutil.which("docker")
    if found:
        return found
    candidates: list[Path] = []
    if platform.system() == "Windows":
        for env_name, suffix in [
            ("ProgramFiles", "Docker/Docker/resources/bin/docker.exe"),
            ("LOCALAPPDATA", "Programs/DockerDesktop/resources/bin/docker.exe"),
        ]:
            if os.environ.get(env_name):
                candidates.append(Path(os.environ[env_name]) / suffix)
    elif platform.system() == "Darwin":
        candidates.append(Path("/Applications/Docker.app/Contents/Resources/bin/docker"))
    return next((str(path) for path in candidates if path.is_file()), None)


def _modern_compose(argv: list[str]) -> bool:
    result = _probe(argv + ["version", "--short"])
    if result.returncode:
        return False
    match = re.search(r"(?:^|\s)v?(\d+)\.\d+", result.stdout or "")
    return bool(match and int(match.group(1)) >= 2)


def _compose_prefix(docker: str, privilege: list[str]) -> list[str] | None:
    plugin = privilege + [docker, "compose"]
    if _modern_compose(plugin):
        return plugin
    standalone = shutil.which("docker-compose")
    if standalone and _modern_compose(privilege + [standalone]):
        return privilege + [standalone]
    return None


def _read_os_release() -> dict[str, str]:
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    return values


def _privilege_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    raise DependencyError("Administrator privileges are required to install Docker. Install it using your system administrator, then rerun python3 setup.py.")


def _linux_install_plan(*, compose_only: bool) -> list[InstallStep]:
    release = _read_os_release()
    distro = release.get("ID", "")
    suite = release.get("UBUNTU_CODENAME") or release.get("VERSION_CODENAME", "")
    if distro not in {"ubuntu", "debian"} or not shutil.which("apt-get") or not re.fullmatch(r"[A-Za-z0-9._-]+", suite):
        raise DependencyError("Automatic Linux dependency installation supports Ubuntu and Debian. Follow https://docs.docker.com/engine/install/ for this distribution, then rerun python3 setup.py.")
    architecture = _probe(["dpkg", "--print-architecture"])
    arch = (architecture.stdout or "").strip()
    if architecture.returncode or not re.fullmatch(r"[A-Za-z0-9_-]+", arch):
        raise DependencyError("Could not determine the package architecture. Install Docker using its distribution guide, then rerun setup.")
    privilege = _privilege_prefix()
    source = (
        "Types: deb\n"
        f"URIs: https://download.docker.com/linux/{distro}\n"
        f"Suites: {suite}\n"
        "Components: stable\n"
        f"Architectures: {arch}\n"
        "Signed-By: /etc/apt/keyrings/docker.asc\n"
    )
    packages = ["docker-compose-plugin"] if compose_only else [
        "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin",
    ]
    commands = [
        (["apt-get", "update"], None),
        (["apt-get", "--no-remove", "install", "-y", "ca-certificates", "curl"], None),
        (["install", "-m", "0755", "-d", "/etc/apt/keyrings"], None),
        (["curl", "-fsSL", f"https://download.docker.com/linux/{distro}/gpg", "-o", "/etc/apt/keyrings/docker.asc"], None),
        (["chmod", "a+r", "/etc/apt/keyrings/docker.asc"], None),
        (["tee", "/etc/apt/sources.list.d/docker.sources"], source),
        (["apt-get", "update"], None),
        (["apt-get", "--no-remove", "install", "-y", *packages], None),
    ]
    return [InstallStep(tuple(privilege + cmd), stdin) for cmd, stdin in commands]


def installation_plan(*, compose_only: bool = False) -> list[InstallStep]:
    """Build an explicit package-manager plan; never execute it here."""
    system = platform.system()
    if system == "Windows" and shutil.which("winget"):
        return [InstallStep(("winget", "install", "--exact", "--id", "Docker.DockerDesktop"))]
    if system == "Darwin" and shutil.which("brew"):
        return [InstallStep(("brew", "install", "--cask", "docker-desktop"))]
    if system == "Linux":
        return _linux_install_plan(compose_only=compose_only)
    url = INSTALL_URLS.get(system, INSTALL_URLS["Linux"])
    raise DependencyError(f"No supported package manager was found for automatic Docker installation. Install Docker Desktop/Engine and Compose using {url}, then rerun python3 setup.py.")


def _show_command(argv: tuple[str, ...] | list[str]) -> str:
    return subprocess.list2cmdline(argv) if platform.system() == "Windows" else shlex.join(argv)


def install_runtime(*, compose_only: bool, confirm: Callable, log: Callable = print) -> None:
    plan = installation_plan(compose_only=compose_only)
    label = "Docker Compose" if compose_only else "Docker and Docker Compose"
    log(f"Missing: {label}. Proposed installation commands:")
    for step in plan:
        log("  " + _show_command(step.argv))
        if step.stdin:
            log("  Repository configuration supplied to the command above:\n" + step.stdin.rstrip())
    log("Package managers may request administrator approval and display their own license prompts. No conflicting packages will be removed automatically.")
    if not confirm(f"Install {label} using these commands?", default=False):
        raise DependencyError(f"{label} installation was declined. Install the prerequisites and rerun python3 setup.py.")
    for step in plan:
        try:
            subprocess.run(list(step.argv), input=step.stdin, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise DependencyError(f"Dependency installation did not complete. Review the package-manager error, follow {INSTALL_URLS.get(platform.system(), INSTALL_URLS['Linux'])}, and rerun setup. No application configuration has been changed.") from exc


def _desktop_path() -> Path | None:
    for env_name, suffix in [
        ("ProgramFiles", "Docker/Docker/Docker Desktop.exe"),
        ("LOCALAPPDATA", "Programs/DockerDesktop/Docker Desktop.exe"),
    ]:
        if os.environ.get(env_name):
            candidate = Path(os.environ[env_name]) / suffix
            if candidate.is_file():
                return candidate
    return None


def _start_daemon(*, confirm: Callable, log: Callable) -> bool:
    system = platform.system()
    if system == "Linux" and shutil.which("systemctl"):
        command = _privilege_prefix() + ["systemctl", "start", "docker"]
    elif system == "Darwin" and shutil.which("open"):
        command = ["open", "-a", "Docker"]
    elif system == "Windows" and _desktop_path():
        command = [str(_desktop_path())]
    else:
        return False
    log("Docker is not reachable. Proposed start command: " + _show_command(command))
    if not confirm("Start Docker now?", default=False):
        return False
    try:
        if system == "Windows":
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
            subprocess.Popen(command, startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.run(command, check=True)
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        log(f"Docker could not be started automatically: {type(exc).__name__}.")
        return False


def _engine_result(prefix: list[str]) -> subprocess.CompletedProcess:
    return _probe(prefix + ["info", "--format", "{{.OSType}}"], timeout=10)


def _wait_for_engine(prefix: list[str], *, seconds: float = 60) -> subprocess.CompletedProcess:
    deadline = time.monotonic() + seconds
    result = _engine_result(prefix)
    while result.returncode and time.monotonic() < deadline:
        time.sleep(min(2, max(0, deadline - time.monotonic())))
        result = _engine_result(prefix)
    return result


def ensure_runtime(*, confirm: Callable, prompt: Callable, log: Callable = print) -> list[str]:
    """Check/install prerequisites and return a working Compose command prefix.

    All install and daemon-start actions require affirmative user confirmation.
    Windows virtualization/WSL, license acceptance, and reboots stay with the
    operator. Linux permissions can use a separately approved sudo prefix.
    """
    if sys.version_info < (3, 10):
        raise DependencyError("Python 3.10 or newer is required. Install Python first, then run python3 setup.py.")
    log(f"Python {platform.python_version()}: ready")
    docker = _docker_path()
    installed_now = False
    if not docker:
        install_runtime(compose_only=False, confirm=confirm, log=log)
        installed_now = True
        docker = _docker_path()
        if not docker:
            raise DependencyError("Docker was installed but is not available yet. Complete Docker Desktop setup, restart if requested, reopen the terminal, then rerun python3 setup.py.")
    log("Docker CLI: found")
    privilege: list[str] = []
    compose = _compose_prefix(docker, privilege)
    if compose is None:
        if installed_now and platform.system() in {"Windows", "Darwin"}:
            raise DependencyError("Docker Desktop installation finished, but Compose is not available yet. Open Docker Desktop, finish its first-start setup and any requested restart, reopen the terminal, then rerun python3 setup.py.")
        install_runtime(compose_only=True, confirm=confirm, log=log)
        docker = _docker_path() or docker
        compose = _compose_prefix(docker, privilege)
        if compose is None:
            raise DependencyError(f"Docker Compose v2 or newer is still unavailable. Complete Docker Desktop setup or follow {COMPOSE_URL}, reopen the terminal if PATH changed, then rerun setup.")
    log("Docker Compose: ready")
    engine_prefix = [docker]
    result = _engine_result(engine_prefix)
    if result.returncode and platform.system() == "Linux" and "permission denied" in (result.stderr or "").lower():
        log("The Docker daemon requires elevated access. Setup can prefix Docker commands with sudo; it will not change Docker group membership.")
        if shutil.which("sudo") and confirm("Use sudo for Docker commands during this setup?", default=False):
            # Authorize on the operator's terminal before captured readiness
            # probes, so an uncached sudo password prompt stays visible.
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                raise DependencyError("Could not authorize sudo for Docker commands. Complete administrator authentication and rerun setup. No permissions or group memberships were changed.") from exc
            privilege = ["sudo"]
            engine_prefix = privilege + [docker]
            result = _engine_result(engine_prefix)
            compose = _compose_prefix(docker, privilege)
            if compose is None:
                raise DependencyError("Docker Compose is not available through sudo. Install the system-wide Compose plugin and rerun setup.")
        else:
            raise DependencyError("Docker access was denied. Ask your administrator to provide Docker access, or rerun setup and approve sudo for Docker commands. No permissions or group memberships were changed.")
    if result.returncode:
        if _start_daemon(confirm=confirm, log=log):
            log("Waiting up to 60 seconds for Docker to become ready...")
            result = _wait_for_engine(engine_prefix)
        if result.returncode:
            log("Start Docker and finish any Desktop, virtualization, WSL, permission, or restart steps it requests. Setup has not changed the application's environment or data.")
            answer = prompt("After Docker is ready, press Enter to retry, or enter q to stop", default="")
            if answer.strip().lower() in {"q", "quit", "exit"}:
                raise DependencyError("Docker is not ready. Complete its setup and rerun python3 setup.py.")
            result = _wait_for_engine(engine_prefix, seconds=30)
    if result.returncode:
        raise DependencyError("Docker is still unreachable. Check Docker Desktop/service and permissions, then rerun python3 setup.py.")
    if (result.stdout or "").strip().lower() != "linux":
        raise DependencyError("Detect Map requires Linux containers. Switch Docker Desktop to Linux containers and rerun setup.")
    log("Docker daemon: ready (Linux containers)")
    log("Node.js, PostgreSQL, Redis, and application Python/Node packages will be installed inside Docker during the application build.")
    return compose
