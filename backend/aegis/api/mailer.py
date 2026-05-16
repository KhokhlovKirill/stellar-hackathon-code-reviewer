"""Transactional email sender (SMTP + async).

Used for the welcome email sent right after a successful registration. Reads
SMTP credentials from environment variables; if any of the required vars is
missing the mailer silently no-ops (so dev/test environments don't fail
registration). The template is `email_templates/welcome.html` and supports two
placeholders: `{{user_name}}` and `{{dashboard_url}}`.

Env vars (all required to actually send mail):
    AEGIS_SMTP_HOST       e.g. smtp.mail.ru
    AEGIS_SMTP_PORT       e.g. 465 (SSL) or 587 (STARTTLS)
    AEGIS_SMTP_USER       login / from address
    AEGIS_SMTP_PASSWORD   app password
Optional:
    AEGIS_SMTP_FROM       display "Name <addr>"; defaults to AEGIS_SMTP_USER
    AEGIS_SMTP_SECURITY   "ssl" (default) | "starttls" | "none"
    AEGIS_PUBLIC_URL      base URL for {{dashboard_url}}; defaults to
                          https://aegis.khokhlovkirill.ru
"""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from html import escape
from pathlib import Path

from aegis.config import get_settings
from aegis.obs import get_logger

log = get_logger("aegis.api.mailer")

_TEMPLATE_PATH = Path(__file__).parent / "email_templates" / "welcome.html"


def _render_welcome(user_name: str, dashboard_url: str) -> str:
    raw = _TEMPLATE_PATH.read_text(encoding="utf-8")
    return (
        raw.replace("{{user_name}}", escape(user_name, quote=True))
        .replace("{{dashboard_url}}", escape(dashboard_url, quote=True))
    )


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    user: str
    password: str
    from_addr: str
    security: str
    public_url: str


def _smtp_config() -> SMTPConfig | None:
    settings = get_settings()
    host = settings.smtp_host.strip()
    user = settings.smtp_user.strip()
    password = settings.smtp_password.strip()
    if not host or not user or not password:
        return None
    from_addr = settings.smtp_from.strip() or user
    return SMTPConfig(
        host=host,
        port=settings.smtp_port,
        user=user,
        password=password,
        from_addr=from_addr,
        security=settings.smtp_security,
        public_url=settings.public_url.rstrip("/"),
    )


async def send_welcome_email(*, to_email: str, user_name: str) -> bool:
    """Send the welcome email. Returns True on success, False on no-op/failure.

    Failures are logged but never raised — registration must not fail because
    SMTP is down or misconfigured.
    """
    cfg = _smtp_config()
    if cfg is None:
        log.info("mailer.skip", reason="smtp not configured", to=to_email)
        return False
    dashboard_url = f"{cfg.public_url}/dashboard"
    resolved_name = (user_name or to_email.split("@")[0]).strip()

    try:
        body = _render_welcome(resolved_name, dashboard_url)
    except FileNotFoundError:
        log.warning("mailer.template_missing", path=str(_TEMPLATE_PATH))
        return False

    msg = EmailMessage()
    msg["Subject"] = "Добро пожаловать в Aegis"
    # Normalize the From header: if AEGIS_SMTP_FROM is "Name <addr>", keep
    # as-is; otherwise wrap user in a sensible display name.
    name, addr = parseaddr(cfg.from_addr)
    if not addr:
        addr = cfg.user
    msg["From"] = formataddr((name or "Aegis Security", addr))
    msg["To"] = to_email
    msg.set_content(
        f"Привет, {resolved_name}!\n\n"
        f"Добро пожаловать в Aegis. Откройте дашборд: {dashboard_url}\n\n"
        "Если вы не регистрировались — просто проигнорируйте это письмо."
    )
    msg.add_alternative(body, subtype="html")

    try:
        import aiosmtplib

        if cfg.security == "starttls":
            await aiosmtplib.send(
                msg,
                hostname=cfg.host,
                port=cfg.port,
                username=cfg.user,
                password=cfg.password,
                start_tls=True,
                timeout=15,
            )
        elif cfg.security == "none":
            await aiosmtplib.send(
                msg,
                hostname=cfg.host,
                port=cfg.port,
                username=cfg.user,
                password=cfg.password,
                timeout=15,
            )
        else:  # ssl (implicit TLS)
            await aiosmtplib.send(
                msg,
                hostname=cfg.host,
                port=cfg.port,
                username=cfg.user,
                password=cfg.password,
                use_tls=True,
                timeout=15,
            )
    except Exception as exc:
        log.warning("mailer.send_failed", to=to_email, error=str(exc))
        return False
    log.info("mailer.sent", to=to_email, template="welcome")
    return True
