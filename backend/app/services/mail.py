"""Outbound mail / SMTP.

Instance-wide config lives on the `app_settings` singleton (super-admin
managed); the SMTP password is Fernet-encrypted at rest. Used today by the
Settings → Mail server test button; report delivery / notifications can call
`send_email` later.

All smtplib calls are synchronous, so we run them in a worker thread to keep
the event loop unblocked (same pattern as `ldap_auth`).
"""
from __future__ import annotations

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr
from typing import Optional

from app.core.crypto import decrypt

_TIMEOUT = 10  # seconds


class MailError(Exception):
    """Connection / authentication / send failure."""


@dataclass
class MailSettings:
    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    from_address: str
    from_name: str
    use_tls: bool  # STARTTLS
    use_ssl: bool  # implicit TLS


def settings_from_row(row) -> MailSettings:
    """Build MailSettings from an AppSettings row, decrypting the SMTP password."""
    password: Optional[str] = None
    if row.mail_password_encrypted:
        try:
            password = decrypt(row.mail_password_encrypted)
        except ValueError as e:  # tampered / wrong key
            raise MailError(f"stored SMTP password could not be decrypted: {e}")
    from_address = (row.mail_from_address or row.mail_username or "").strip()
    return MailSettings(
        host=(row.mail_host or "").strip(),
        port=int(row.mail_port or 587),
        username=(row.mail_username or None),
        password=password,
        from_address=from_address,
        from_name=row.mail_from_name or "The Detection Map",
        use_tls=bool(row.mail_use_tls),
        use_ssl=bool(row.mail_use_ssl),
    )


def _send_sync(cfg: MailSettings, to: str, subject: str, body: str) -> None:
    if not cfg.host:
        raise MailError("SMTP host is not configured")
    if not cfg.from_address:
        raise MailError("set a 'from' address (or SMTP username) first")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((cfg.from_name, cfg.from_address))
    msg["To"] = to
    msg.set_content(body)

    try:
        if cfg.use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=_TIMEOUT, context=context) as smtp:
                if cfg.username:
                    smtp.login(cfg.username, cfg.password or "")
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=_TIMEOUT) as smtp:
                smtp.ehlo()
                if cfg.use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                if cfg.username:
                    smtp.login(cfg.username, cfg.password or "")
                smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise MailError(f"authentication failed: {e}")
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise MailError(f"SMTP error: {e}")


async def send_email(cfg: MailSettings, to: str, subject: str, body: str) -> None:
    """Async wrapper — runs the blocking smtplib flow in a thread."""
    await asyncio.to_thread(_send_sync, cfg, to, subject, body)


__all__ = ["MailError", "MailSettings", "settings_from_row", "send_email"]
