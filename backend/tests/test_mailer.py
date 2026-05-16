from __future__ import annotations

import sys
from email.message import EmailMessage
from types import SimpleNamespace
from typing import Any

import pytest

from aegis.config import reset_caches


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
    monkeypatch.setenv("AEGIS_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")


@pytest.mark.asyncio
async def test_welcome_email_noops_when_smtp_is_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("AEGIS_SMTP_HOST", "")
    monkeypatch.setenv("AEGIS_SMTP_USER", "")
    monkeypatch.setenv("AEGIS_SMTP_PASSWORD", "")
    reset_caches()

    from aegis.api.mailer import send_welcome_email

    assert not await send_welcome_email(to_email="dev@example.com", user_name="Dev")
    reset_caches()


@pytest.mark.asyncio
async def test_welcome_email_sends_html_over_implicit_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "https://aegis.khokhlovkirill.ru")
    monkeypatch.setenv("AEGIS_SMTP_HOST", "smtp.mail.ru")
    monkeypatch.setenv("AEGIS_SMTP_PORT", "465")
    monkeypatch.setenv("AEGIS_SMTP_SECURITY", "ssl")
    monkeypatch.setenv("AEGIS_SMTP_USER", "aegis@example.com")
    monkeypatch.setenv("AEGIS_SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("AEGIS_SMTP_FROM", "Aegis Security <aegis@example.com>")
    reset_caches()

    sent: list[tuple[EmailMessage, dict[str, Any]]] = []

    async def fake_send(message: EmailMessage, **kwargs: Any) -> None:
        sent.append((message, kwargs))

    monkeypatch.setitem(sys.modules, "aiosmtplib", SimpleNamespace(send=fake_send))

    from aegis.api.mailer import send_welcome_email

    assert await send_welcome_email(
        to_email="dev@example.com",
        user_name="<Dev>",
    )
    assert len(sent) == 1
    message, kwargs = sent[0]
    assert kwargs["hostname"] == "smtp.mail.ru"
    assert kwargs["port"] == 465
    assert kwargs["username"] == "aegis@example.com"
    assert kwargs["password"] == "app-password"
    assert kwargs["use_tls"] is True
    assert message["From"] == "Aegis Security <aegis@example.com>"
    assert message["To"] == "dev@example.com"
    html_part = message.get_body(preferencelist=("html",))
    assert html_part is not None
    html = html_part.get_content()
    assert "&lt;Dev&gt;" in html
    assert 'href="https://aegis.khokhlovkirill.ru/dashboard"' in html
    reset_caches()
