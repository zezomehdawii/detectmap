#!/usr/bin/env python3
"""Interactive Detect Map installation (Python 3.10+).

Run python3 setup.py from the repository root. The wizard checks Docker and
Compose, offers supported dependency installation, suggests host/port values,
builds application dependencies inside Docker, and initializes an empty tenant
deployment with optional sample data. Existing environment keys and data are kept
by default. --reset requires an explicit confirmation before any changes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from urllib.parse import urlsplit
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from setup_dependencies import DependencyError, ensure_runtime

REPO_ROOT = Path(__file__).resolve().parent
ENV_PATH = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
TLS_DIR = REPO_ROOT / "tls"
CADDYFILE = TLS_DIR / "Caddyfile"
CERT_PATH = TLS_DIR / "cert.pem"
KEY_PATH = TLS_DIR / "key.pem"
DEFAULT_LOGIN_EMAIL = "admin@demo.local"
DEFAULT_LOGIN_PASSWORD = "change-me"

# ---- terminal helpers ----------------------------------------------------

_IS_TTY = sys.stdout.isatty()


def _color(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _IS_TTY else s


def b(s: str) -> str:
    return _color("1", s)


def g(s: str) -> str:
    return _color("32", s)


def y(s: str) -> str:
    return _color("33", s)


def r(s: str) -> str:
    return _color("31", s)


def d(s: str) -> str:
    return _color("2", s)


def header(s: str) -> None:
    print()
    print(b(s))
    print(d("─" * min(len(s), 60)))


def prompt(question: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{question}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    return ans or (default or "")


def choose(question: str, options: list[tuple[str, str]], default: str | None = None) -> str:
    """Numbered menu. `options` = list of (key, label). Returns the key."""
    print(question)
    for i, (key, label) in enumerate(options, start=1):
        print(f"  {i}) {label}" + (" (default)" if key == default else ""))
    while True:
        try:
            raw = input("Choice (Enter for default): " if default else "Choice: ").strip()
            if not raw and default:
                return default
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        print(r("  invalid choice — pick a number from the list above"))


def confirm(question: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"{question} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    if not ans:
        return default
    return ans in ("y", "yes")


# ---- environment helpers -------------------------------------------------


def detect_compose_command() -> list[str]:
    """Compatibility entry point; checks and optional installs are interactive."""
    return ensure_runtime(confirm=confirm, prompt=prompt, log=print)


def detect_host_ip() -> str:
    """Suggest a route-selected IPv4 address without sending any traffic."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("10.255.255.255", 1))
            return connection.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def gen_secret(length: int = 64) -> str:
    return secrets.token_urlsafe(length)


def gen_fernet_key() -> str:
    import base64
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def read_env_values(path: Path = None) -> dict[str, str]:
    """Read configuration for defaults; never print environment secret values."""
    path = path or ENV_PATH
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def deployment_from_env(values: dict[str, str]) -> dict:
    origin = next((v.strip() for v in values.get("CORS_ORIGINS", "").split(",") if v.strip()), "")
    parsed = urlsplit(origin)
    tls_mode = values.get("DETECTMAP_TLS_MODE") or ("byo" if parsed.scheme == "https" else "none")
    if tls_mode not in {"none", "self-signed", "byo"}:
        raise ValueError("Saved DETECTMAP_TLS_MODE is invalid; reconfigure the network settings.")
    host = values.get("DETECTMAP_SERVER_HOST") or parsed.hostname
    if not host:
        api = urlsplit(values.get("NEXT_PUBLIC_API_BASE", ""))
        host = api.hostname or "localhost"
    if tls_mode == "none":
        port = values.get("DETECTMAP_HTTP_PORT") or values.get("DETECTMAP_LISTEN_PORT") or parsed.port or 3000
    else:
        port = values.get("TLS_LISTEN_PORT") or values.get("DETECTMAP_LISTEN_PORT") or parsed.port or 8443
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Saved listen port must be between 1 and 65535.")
    scheme = "http" if tls_mode == "none" else "https"
    return {"server_host": host, "listen_port": port, "tls_mode": tls_mode,
            "public_url": f"{scheme}://{host}:{port}"}


def update_network_env(*, server_host: str, listen_port: int, tls_mode: str,
                       cors_origin: str, api_base: str) -> None:
    """Replace only network settings; leave all other lines/keys intact."""
    changes = {
        "CORS_ORIGINS": cors_origin, "NEXT_PUBLIC_API_BASE": api_base,
        "DETECTMAP_SERVER_HOST": server_host, "DETECTMAP_LISTEN_PORT": str(listen_port),
        "DETECTMAP_TLS_MODE": tls_mode,
        "DETECTMAP_HTTP_PORT": str(listen_port if tls_mode == "none" else 3000),
        "TLS_LISTEN_PORT": str(listen_port if tls_mode != "none" else 8443),
    }
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    output = []
    network_keys = set(changes)
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in network_keys:
            if key in changes:
                output.append(f"{key}={changes.pop(key)}")
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in changes.items())
    ENV_PATH.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(g("  updated network configuration; existing credentials and encryption keys retained"))


# ---- .env generation -----------------------------------------------------


def write_env(
    *,
    server_host: str,
    listen_port: int,
    tls_mode: str,
    cors_origin: str,
    api_base: str,
    admin_email: str = DEFAULT_LOGIN_EMAIL,
) -> None:
    """Generate credentials for a new configuration only."""
    if ENV_PATH.exists():
        raise ValueError("Refusing to replace an existing .env; update network settings instead.")
    contents = f"""# Generated by setup.py on {datetime.now(timezone.utc).isoformat()}
# Re-running setup keeps this configuration and encryption keys by default.

# Postgres
POSTGRES_USER=detectmap
POSTGRES_PASSWORD={gen_secret(24)}
POSTGRES_DB=detectmap
DATABASE_URL=postgresql+asyncpg://detectmap:${{POSTGRES_PASSWORD}}@db:5432/detectmap
DATABASE_URL_SYNC=postgresql+psycopg2://detectmap:${{POSTGRES_PASSWORD}}@db:5432/detectmap

# Redis / Celery
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# JWT — two separate secrets per the spec.
JWT_TENANT_SECRET={gen_secret(64)}
JWT_SUPERADMIN_SECRET={gen_secret(64)}
JWT_ALGORITHM=HS256
JWT_ACCESS_TTL_MINUTES=60
JWT_REFRESH_TTL_DAYS=14

# Fernet key for encrypting connector / LDAP / SMTP / AI secrets at rest.
FERNET_KEY={gen_fernet_key()}

# Bootstrap-only key for internal endpoints.
INTERNAL_API_KEY={gen_secret(32)}

# App
APP_ENV=production
APP_DEBUG=false
APP_NAME=The Detection Map

# Default dashboard administrator, shown on the sign-in page for the lab.
# Hide the card under Settings -> Branding when it is no longer needed.
DEFAULT_LOGIN_EMAIL={admin_email}
DEFAULT_LOGIN_PASSWORD={DEFAULT_LOGIN_PASSWORD}

# CORS: browsers loading the frontend must match this origin.
CORS_ORIGINS={cors_origin}

# Frontend → API base. Set at build time; rebuild the frontend image to
# change.
NEXT_PUBLIC_API_BASE={api_base}

# Setup-script metadata (read by docker-compose.tls.yml when TLS is on).
DETECTMAP_SERVER_HOST={server_host}
DETECTMAP_LISTEN_PORT={listen_port}
DETECTMAP_HTTP_PORT={listen_port if tls_mode == 'none' else 3000}
DETECTMAP_TLS_MODE={tls_mode}
TLS_LISTEN_PORT={listen_port if tls_mode != 'none' else 8443}
"""
    ENV_PATH.write_text(contents, encoding="utf-8")
    os.chmod(ENV_PATH, 0o600)
    print(g(f"  wrote {ENV_PATH.relative_to(REPO_ROOT)} (0600)"))


# ---- TLS handling --------------------------------------------------------


def generate_self_signed(server_host: str, compose: list[str]) -> None:
    TLS_DIR.mkdir(exist_ok=True)
    run_compose(compose, ["build", "backend"], tls=False)
    run_compose(compose, ["run", "--rm", "--no-deps", "--volume",
                         f"{TLS_DIR.resolve()}:/tls", "backend", "python", "-m",
                         "app.scripts.generate_tls", "--host", server_host, "--output", "/tls"], tls=False)
    print(g("  generated TLS certificate using the backend container; no host Python packages installed"))


def copy_user_cert(cert_src: Path, key_src: Path) -> None:
    TLS_DIR.mkdir(exist_ok=True)
    for source, destination, private in [(cert_src, CERT_PATH, False), (key_src, KEY_PATH, True)]:
        if source.resolve() == destination.resolve():
            continue
        temporary = TLS_DIR / (destination.name + "." + secrets.token_hex(6) + ".tmp")
        try:
            shutil.copyfile(source, temporary)
            if private:
                os.chmod(temporary, 0o600)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    print(g(f"  copied cert + key into {TLS_DIR.relative_to(REPO_ROOT)}/"))


def write_caddyfile() -> None:
    """Caddy config — terminates TLS on :8443 in-container, strips /api
    when proxying to the backend so the backend's routes stay clean."""
    TLS_DIR.mkdir(exist_ok=True)
    CADDYFILE.write_text(
        """# Generated by setup.py. Edit and re-run setup to regenerate.
{
    auto_https off
}

:8443 {
    tls /etc/caddy/cert.pem /etc/caddy/key.pem

    # Backend API: strip /api so backend routes stay at /auth, /detections, …
    handle_path /api/* {
        reverse_proxy backend:8000
    }

    # Everything else → Next.js frontend.
    handle {
        reverse_proxy frontend:3000
    }
}
""", encoding="utf-8"
    )
    print(g(f"  wrote {CADDYFILE.relative_to(REPO_ROOT)}"))


# ---- deployment ----------------------------------------------------------


def compose_command(compose: list[str], tls: bool) -> list[str]:
    command = list(compose) + ["-f", "docker-compose.yml"]
    if tls:
        command += ["-f", "docker-compose.tls.yml"]
    return command


def run_compose(compose: list[str], extra_args: list[str], tls: bool) -> None:
    command = compose_command(compose, tls) + extra_args
    print(d("  $ " + subprocess.list2cmdline(command)))
    subprocess.check_call(command, cwd=REPO_ROOT)


def wait_for_backend(compose: list[str], tls: bool) -> None:
    import time
    print(d("  waiting for backend health..."))
    deadline = time.monotonic() + 60
    command = compose_command(compose, tls) + [
        "exec", "-T", "backend", "curl", "-sf", "http://localhost:8000/health",
    ]
    while time.monotonic() < deadline:
        try:
            subprocess.check_output(command, cwd=REPO_ROOT, stderr=subprocess.DEVNULL, timeout=10)
            print(g("  backend is ready"))
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            time.sleep(2)
    raise RuntimeError("Backend did not become healthy; inspect docker compose logs backend and rerun setup.")


def deployment_is_empty(compose: list[str], tls: bool) -> bool:
    command = compose_command(compose, tls) + [
        "exec", "-T", "backend", "python", "-m",
        "app.scripts.initialize_admins", "--status-only",
    ]
    try:
        status = json.loads(subprocess.check_output(command, cwd=REPO_ROOT, text=True, timeout=30))
    except (ValueError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not determine whether the deployment is empty; check backend health and rerun setup.") from exc
    if not isinstance(status, dict) or type(status.get("empty")) is not bool:
        raise RuntimeError("The backend returned an invalid initialization status; rerun setup after checking backend health.")
    return status["empty"]


def choose_initial_data() -> str:
    return choose("What data should Detect Map start with?", [
        ("fresh", "Fresh deployment (ATT&CK reference catalog and empty tenant coverage and inventory)"),
        ("sample", "Sample data deployment (example tenants with mapped use cases, gaps, networks, and assets)"),
    ], default="fresh")


def run_initialization(compose: list[str], tls: bool, admin_email: str | None,
                       super_email: str, *, sample_data: str) -> None:
    arguments = ["exec", "-T", "backend", "python", "-m",
                 "app.scripts.initialize_admins", "--super-email", super_email,
                 "--sample-data", sample_data]
    if admin_email is not None:
        arguments += ["--admin-email", admin_email]
    run_compose(compose, arguments, tls=tls)


def run_factory_reset(compose: list[str], tls: bool, admin_email: str | None,
                      super_email: str, *, sample_data: str) -> None:
    arguments = ["exec", "-T", "backend", "python", "-m", "app.scripts.factory_reset",
                 "--yes", "--use-login-defaults", "--super-email", super_email,
                 "--sample-data", sample_data]
    if admin_email is not None:
        arguments += ["--admin-email", admin_email]
    run_compose(compose, arguments, tls=tls)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-env", action="store_true", help="Keep existing configuration and keys without prompting")
    reset_options = parser.add_mutually_exclusive_group()
    reset_options.add_argument("--skip-reset", action="store_true", help="Keep existing data (also the default); initialize only an empty deployment")
    reset_options.add_argument("--reset", action="store_true", help="Factory-reset tenant data; requires confirmation")
    args = parser.parse_args()
    print(b("The Detection Map — interactive setup"))
    print(d("Press Enter to accept a suggested default; Ctrl-C cancels."))
    if args.reset and not confirm("Factory reset deletes all customer schemas, users, and MSSP organizations. Proceed?", default=False):
        print("Cancelled; no installation or deployment changes were made.")
        return

    header("1. Dependencies")
    compose = ensure_runtime(confirm=confirm, prompt=prompt, log=print)
    print("Application Python packages, Node.js, PostgreSQL and Redis are installed inside Docker.")
    print("Host Python packages are not installed or upgraded by this wizard.")

    existing = read_env_values() if ENV_PATH.exists() else None
    keep = bool(existing is not None and (args.keep_env or confirm("Existing .env found. Keep its current configuration and encryption keys?", default=True)))
    try:
        saved = deployment_from_env(existing) if existing is not None else None
    except (ValueError, TypeError):
        if keep:
            raise ValueError("Saved network settings are invalid; rerun without --keep-env and choose to reconfigure.") from None
        saved = None
    if keep:
        deployment = saved
        print(g("  retaining existing .env, application data, and TLS files"))
        server_host = deployment["server_host"]
        listen_port = deployment["listen_port"]
        tls_mode = deployment["tls_mode"]
        if tls_mode != "none" and not all(path.is_file() for path in (CERT_PATH, KEY_PATH, CADDYFILE)):
            raise ValueError("Saved TLS configuration is incomplete. Restore tls/cert.pem, key.pem and Caddyfile, or rerun and reconfigure transport.")
    else:
        header("2. Server reachability")
        guessed_ip = saved["server_host"] if saved else detect_host_ip()
        print(d(f"  detected hostname: {socket.gethostname()}"))
        server_host = prompt("Hostname or IP this server will be reached on", default=guessed_ip)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", server_host):
            raise ValueError("Invalid hostname/IP; enter a hostname or IPv4 address without a scheme or port.")
        header("3. Transport")
        tls_mode = choose("How should the dashboard be served?", [
            ("none", "HTTP"), ("self-signed", "HTTPS with a self-signed certificate"),
            ("byo", "HTTPS using a certificate I provide"),
        ], default=saved["tls_mode"] if saved else "none")
        default_port = str(saved["listen_port"]) if saved and saved["tls_mode"] == tls_mode else ("8080" if tls_mode == "none" else "8443")
        while True:
            try:
                listen_port = int(prompt("Listen port", default=default_port))
                if not 1 <= listen_port <= 65535 or (tls_mode == "none" and listen_port == 8000) or (tls_mode != "none" and listen_port in {3000, 8000}):
                    raise ValueError
                break
            except ValueError:
                print(r("Choose a port from 1–65535; ports used by the direct frontend/API cannot also serve TLS."))
        scheme = "http" if tls_mode == "none" else "https"
        deployment = {"server_host": server_host, "listen_port": listen_port,
                      "tls_mode": tls_mode, "public_url": f"{scheme}://{server_host}:{listen_port}"}
        # Collect BYO paths before writing any application configuration.
        if tls_mode == "byo":
            cert_src = Path(prompt("Path to PEM-encoded certificate (cert.pem)")).expanduser()
            key_src = Path(prompt("Path to PEM-encoded private key (key.pem)")).expanduser()
            if not cert_src.is_file() or not key_src.is_file():
                raise ValueError("Certificate or private key file was not found.")

    header("4. Administrator identities")
    print(d("  Used only when initializing an empty deployment or when --reset was confirmed."))
    admin_email = None
    if existing is None:
        admin_email = prompt("Email for the MSSP administrator", default=DEFAULT_LOGIN_EMAIL).strip().lower()
    else:
        print(d("  The backend uses the dashboard identity from its existing configuration."))
    super_email = prompt("Email for the product super admin", default="super@detectmap.local")
    emails = [super_email] if admin_email is None else [admin_email, super_email]
    if not all(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) and len(value) <= 255 for value in emails):
        raise ValueError("Enter valid administrator email addresses.")

    if not keep:
        header("5. Environment")
        kwargs = dict(server_host=server_host, listen_port=listen_port, tls_mode=tls_mode,
                      cors_origin=deployment["public_url"],
                      api_base="/api" if tls_mode != "none" else f"http://{server_host}:8000")
        if existing is not None:
            update_network_env(**kwargs)
        else:
            write_env(**kwargs, admin_email=admin_email or DEFAULT_LOGIN_EMAIL)
        if tls_mode == "self-signed":
            generate_self_signed(server_host, compose)
            write_caddyfile()
        elif tls_mode == "byo":
            copy_user_cert(cert_src, key_src)
            write_caddyfile()
        # HTTP mode keeps existing TLS files; no certificate/key deletion.

    # Also honor pre-update .env files without the new HTTP mapping variable.
    # This changes only this setup process, not the preserved .env contents.
    os.environ["DETECTMAP_HTTP_PORT"] = str(listen_port if tls_mode == "none" else (existing or {}).get("DETECTMAP_HTTP_PORT", "3000"))
    os.environ["TLS_LISTEN_PORT"] = str(listen_port if tls_mode != "none" else "8443")
    header("6. Build and start the application")
    use_tls = tls_mode != "none"
    run_compose(compose, ["up", "-d", "--build"], tls=use_tls)
    wait_for_backend(compose, use_tls)
    header("7. Initial deployment")
    if args.reset or deployment_is_empty(compose, use_tls):
        sample_data = choose_initial_data()
        initialize = run_factory_reset if args.reset else run_initialization
        initialize(compose, use_tls, admin_email, super_email, sample_data=sample_data)
    else:
        print(d("  Using the existing tenant workspaces, accounts, and settings."))
    header("Done")
    print(f"  Dashboard: {deployment['public_url']}")
    print("  Fresh installs use the default dashboard administrator shown on the sign-in page.")
    print("  Hide that credential card under Settings -> Branding; this does not disable the account.")
    print("  A new product super admin receives a generated temporary password and must change it on first sign-in.")
    print("  Manage sample workspaces in the dashboard under Settings -> Environment.")
    if tls_mode == "self-signed":
        print("  Configure trust for your generated certificate before browser access.")


if __name__ == "__main__":
    try:
        main()
    except (DependencyError, RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(r(f"Setup stopped: {exc}"), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Setup cancelled.", file=sys.stderr)
        sys.exit(130)
