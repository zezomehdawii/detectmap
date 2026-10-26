#!/usr/bin/env python3
"""Interactive installer for The Detection Map.

Run from the repo root:

    python3 setup.py

Walks the operator through:
  * server hostname / IP (used by both CORS and the frontend's API base)
  * listen port
  * TLS mode (none / self-signed / use my certificate)
  * generates a strong .env if one doesn't already exist
  * generates a self-signed cert via Python's `cryptography` if requested
  * brings up the docker stack (with the TLS overlay if needed)
  * factory-resets the database into a single-admin clean slate, with a
    generated random password and `must_change_password=True`
  * prints the initial credentials ONCE

Re-running setup is safe: pass --skip-reset to keep your existing data
or --reset to force the wipe.

REQUIREMENTS
============
- Docker + Docker Compose v2 on the host
- Python 3.10+ on the host
- `cryptography` (only needed for the self-signed cert path; installed
   on demand if missing)
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
ENV_PATH = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
TLS_DIR = REPO_ROOT / "tls"
CADDYFILE = TLS_DIR / "Caddyfile"
CERT_PATH = TLS_DIR / "cert.pem"
KEY_PATH = TLS_DIR / "key.pem"

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


def choose(question: str, options: list[tuple[str, str]]) -> str:
    """Numbered menu. `options` = list of (key, label). Returns the key."""
    print(question)
    for i, (_, label) in enumerate(options, start=1):
        print(f"  {i}) {label}")
    while True:
        try:
            raw = input("Choice: ").strip()
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
    """Return the docker-compose command tuple. Errors out if missing."""
    if shutil.which("docker") is None:
        print(r("docker is not on PATH — install Docker first."))
        sys.exit(1)
    # Prefer `docker compose` (v2 plugin) over the legacy `docker-compose`.
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    print(r("neither `docker compose` nor `docker-compose` works — install Docker Compose."))
    sys.exit(1)


def detect_host_ip() -> str:
    """Best-effort guess at the LAN IP we'd be reachable on."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # never actually transmits
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def gen_secret(length: int = 64) -> str:
    return secrets.token_urlsafe(length)


def gen_fernet_key() -> str:
    # 32 raw bytes → 44 char url-safe base64. The Fernet spec requires
    # exactly this shape.
    import base64

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


# ---- .env generation -----------------------------------------------------


def write_env(
    *,
    server_host: str,
    listen_port: int,
    tls_mode: str,
    cors_origin: str,
    api_base: str,
) -> None:
    """Write .env from scratch (overwriting any existing file).

    JWT secrets, the Fernet key, and the internal API key are freshly
    generated every run — operators who want stable values across runs
    should keep their .env around (we skip write when --keep-env is set).
    """
    contents = f"""# Generated by setup.py on {datetime.now(timezone.utc).isoformat()}
# Re-running setup will OVERWRITE this file unless you pass --keep-env.

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

# CORS: browsers loading the frontend must match this origin.
CORS_ORIGINS={cors_origin}

# Frontend → API base. Set at build time; rebuild the frontend image to
# change.
NEXT_PUBLIC_API_BASE={api_base}

# Setup-script metadata (read by docker-compose.tls.yml when TLS is on).
DETECTMAP_SERVER_HOST={server_host}
DETECTMAP_LISTEN_PORT={listen_port}
DETECTMAP_TLS_MODE={tls_mode}
TLS_LISTEN_PORT={listen_port if tls_mode != 'none' else 8443}
"""
    ENV_PATH.write_text(contents)
    os.chmod(ENV_PATH, 0o600)
    print(g(f"  wrote {ENV_PATH.relative_to(REPO_ROOT)} (0600)"))


# ---- TLS handling --------------------------------------------------------


def ensure_cryptography() -> None:
    """Install `cryptography` on the host if missing — needed for the
    self-signed cert path. Already a backend dependency; we use Python
    here to keep setup.py portable across hosts that don't have openssl."""
    try:
        import cryptography  # noqa: F401
        return
    except ImportError:
        pass
    print(d("  installing `cryptography` (one-time)..."))
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "cryptography"]
    )


def generate_self_signed(server_host: str) -> None:
    """Produce a self-signed RSA-2048 cert valid for 825 days (the cap
    most browsers accept) covering the operator's hostname + IP."""
    ensure_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    TLS_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, server_host),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Detection Map"),
        ]
    )
    sans = [x509.DNSName(server_host)]
    # If they typed an IP literal, also stash it as an IP SAN.
    try:
        import ipaddress

        ip = ipaddress.ip_address(server_host)
        sans.append(x509.IPAddress(ip))
    except ValueError:
        pass
    # Always include localhost / 127.0.0.1 so the operator can hit the
    # cert from the host even when they accessed via the LAN hostname.
    sans.extend([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(KEY_PATH, 0o600)
    CERT_PATH.write_bytes(
        cert.public_bytes(encoding=serialization.Encoding.PEM)
    )
    print(g(f"  wrote {CERT_PATH.relative_to(REPO_ROOT)} + {KEY_PATH.relative_to(REPO_ROOT)}"))


def copy_user_cert(cert_src: Path, key_src: Path) -> None:
    TLS_DIR.mkdir(exist_ok=True)
    shutil.copyfile(cert_src, CERT_PATH)
    shutil.copyfile(key_src, KEY_PATH)
    os.chmod(KEY_PATH, 0o600)
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
"""
    )
    print(g(f"  wrote {CADDYFILE.relative_to(REPO_ROOT)}"))


# ---- main ----------------------------------------------------------------


def run_compose(compose: list[str], extra_args: list[str], tls: bool) -> None:
    cmd = list(compose)
    cmd += ["-f", "docker-compose.yml"]
    if tls:
        cmd += ["-f", "docker-compose.tls.yml"]
    cmd += extra_args
    print(d(f"  $ {' '.join(cmd)}"))
    subprocess.check_call(cmd, cwd=REPO_ROOT)


def run_factory_reset(
    compose: list[str], tls: bool, admin_email: str, super_email: str
) -> None:
    cmd = list(compose) + ["-f", "docker-compose.yml"]
    if tls:
        cmd += ["-f", "docker-compose.tls.yml"]
    cmd += [
        "exec",
        "-T",
        "backend",
        "python",
        "-m",
        "app.scripts.factory_reset",
        "--yes",
        "--admin-email",
        admin_email,
        "--super-email",
        super_email,
    ]
    print(d(f"  $ {' '.join(cmd)}"))
    subprocess.check_call(cmd, cwd=REPO_ROOT)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--keep-env",
        action="store_true",
        help="Don't regenerate .env if it already exists",
    )
    p.add_argument(
        "--skip-reset",
        action="store_true",
        help="Bring the stack up but don't wipe existing data",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Force factory_reset without prompting again",
    )
    args = p.parse_args()

    print()
    print(b("The Detection Map — interactive setup"))
    print(d("Press Ctrl-C at any prompt to cancel."))

    compose = detect_compose_command()

    # ---- 1. Server reachability ----
    header("1. Server reachability")
    guessed_ip = detect_host_ip()
    server_host = prompt(
        "Hostname or IP this server will be reached on",
        default=guessed_ip,
    )
    if not re.match(r"^[A-Za-z0-9.\-_]+$", server_host):
        print(r("invalid hostname — only letters, digits, dot, dash, underscore"))
        sys.exit(1)

    # ---- 2. Port + TLS ----
    header("2. Transport")
    tls_mode = choose(
        "How should the dashboard be served?",
        [
            ("none", "HTTP (unencrypted — local network demos only)"),
            ("self-signed", "HTTPS with a self-signed certificate (no public CA needed)"),
            ("byo", "HTTPS using a certificate I provide"),
        ],
    )
    default_port = "8443" if tls_mode != "none" else "8080"
    port_raw = prompt("Listen port", default=default_port)
    try:
        listen_port = int(port_raw)
        if not (1 <= listen_port <= 65535):
            raise ValueError
    except ValueError:
        print(r("invalid port"))
        sys.exit(1)

    if tls_mode == "self-signed":
        generate_self_signed(server_host)
        write_caddyfile()
    elif tls_mode == "byo":
        cert_path_str = prompt("Path to PEM-encoded certificate (cert.pem)")
        key_path_str = prompt("Path to PEM-encoded private key (key.pem)")
        cert_src = Path(cert_path_str).expanduser()
        key_src = Path(key_path_str).expanduser()
        if not cert_src.is_file() or not key_src.is_file():
            print(r("certificate or key not found at the given paths"))
            sys.exit(1)
        copy_user_cert(cert_src, key_src)
        write_caddyfile()
    else:
        # Strip any old TLS material so a previous TLS setup doesn't
        # leak files into the new HTTP-only deployment.
        for p in (CERT_PATH, KEY_PATH, CADDYFILE):
            if p.exists():
                p.unlink()

    # ---- 3. Admin identities ----
    header("3. Initial administrator")
    admin_email = prompt(
        "Email for the MSSP administrator", default="admin@detectmap.local"
    )
    super_email = prompt(
        "Email for the product super admin", default="super@detectmap.local"
    )

    # ---- 4. Write .env ----
    header("4. Environment")
    scheme = "https" if tls_mode != "none" else "http"
    public_url = f"{scheme}://{server_host}:{listen_port}"
    cors_origin = public_url
    # When TLS is on we route through Caddy and the API lives under /api.
    # In HTTP mode the backend is exposed directly on its own host port,
    # which we keep at 8000 (untouched by the listen_port choice — that
    # one belongs to the frontend / Caddy).
    if tls_mode != "none":
        api_base = "/api"
    else:
        api_base = f"http://{server_host}:8000"

    if ENV_PATH.exists() and args.keep_env:
        print(d(f"  keeping existing {ENV_PATH.relative_to(REPO_ROOT)}"))
    else:
        write_env(
            server_host=server_host,
            listen_port=listen_port,
            tls_mode=tls_mode,
            cors_origin=cors_origin,
            api_base=api_base,
        )

    # ---- 5. Stack up ----
    header("5. Bringing up the stack")
    use_tls_overlay = tls_mode != "none"
    run_compose(compose, ["up", "-d", "--build"], tls=use_tls_overlay)

    # Wait for the backend to be ready before factory-resetting.
    import time

    print(d("  waiting for backend health..."))
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            # Use compose exec to hit health from inside the network so
            # we don't depend on the public URL being reachable yet.
            subprocess.check_output(
                list(compose)
                + [
                    "-f",
                    "docker-compose.yml",
                ]
                + (["-f", "docker-compose.tls.yml"] if use_tls_overlay else [])
                + [
                    "exec",
                    "-T",
                    "backend",
                    "curl",
                    "-sf",
                    "http://localhost:8000/health",
                ],
                cwd=REPO_ROOT,
                stderr=subprocess.DEVNULL,
            )
            print(g("  backend is up"))
            break
        except subprocess.CalledProcessError:
            time.sleep(2)
    else:
        print(r("  backend never reported healthy after 60s — check `docker compose logs backend`"))
        sys.exit(1)

    # ---- 6. Factory reset ----
    header("6. Initial data")
    if args.skip_reset:
        print(d("  --skip-reset passed; leaving existing data in place"))
    else:
        if not args.reset:
            print(
                y(
                    "  About to wipe every customer schema, every user, and every"
                )
            )
            print(
                y(
                    "  MSSP org. Reference data (ATT&CK, GRC, SigmaHQ, D3FEND,"
                )
            )
            print(y("  sector profiles) is preserved."))
            if not confirm("  Proceed with factory reset?", default=False):
                print(d("  skipped — re-run with --reset to do this later"))
                return
        run_factory_reset(compose, use_tls_overlay, admin_email, super_email)

    # ---- 7. Final ----
    header("Done")
    print(f"  Dashboard:  {b(public_url)}")
    if tls_mode == "self-signed":
        print(
            d(
                "  (your browser will warn about the self-signed certificate —"
            )
        )
        print(d("   accept the exception to proceed)"))
    print()
    print(
        d(
            "Credentials were printed above by the factory-reset step. Save"
        )
    )
    print(d("them now — they are not recoverable, and both accounts must change"))
    print(d("their password on first login."))
    print()


if __name__ == "__main__":
    main()
