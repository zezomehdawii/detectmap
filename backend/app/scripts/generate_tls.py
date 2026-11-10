"""Generate a local setup certificate using the backend's cryptography dependency.

    python -m app.scripts.generate_tls --host 192.0.2.10 --output /tls

The setup wizard mounts its TLS directory at /tls. No host Python package
installation is needed, and private-key contents are never printed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import re
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _host(value: str) -> str:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not value or len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise ValueError("Host must be a hostname or IP address without a scheme, path, or port")
        return value


def generate_certificate(host: str, output: Path) -> tuple[Path, Path]:
    host = _host(host)
    names: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        address = ipaddress.ip_address(host)
        extra: x509.GeneralName = x509.IPAddress(address)
    except ValueError:
        extra = x509.DNSName(host)
    if extra not in names:
        names.insert(0, extra)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Detection Map"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = output / "cert.pem", output / "key.pem"
    pending: list[tuple[Path, Path]] = []
    try:
        for target, content, mode in (
            (key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600),
            (cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644),
        ):
            with tempfile.NamedTemporaryFile(dir=output, prefix=".detectmap-tls-", delete=False) as handle:
                temporary = Path(handle.name)
                pending.append((temporary, target))
                os.chmod(temporary, mode)
                handle.write(content)
        for temporary, target in pending:
            temporary.replace(target)
    finally:
        for temporary, _ in pending:
            if temporary.exists():
                temporary.unlink()
    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--output", type=Path, default=Path("/tls"))
    args = parser.parse_args()
    try:
        cert_path, key_path = generate_certificate(args.host, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Generated {cert_path} and {key_path}; private key restricted to its owner.")


if __name__ == "__main__":
    main()
