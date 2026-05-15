"""Webhook signature/token verification (criterion C1).

Always verify against the RAW request body, before JSON parsing, constant-time,
fail-closed (empty configured secret => reject).
"""

from __future__ import annotations

import hashlib
import hmac

from aegis.errors import WebhookVerificationError
from aegis.schemas import Provider


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def verify_github(body: bytes, headers: dict[str, str], secret: str) -> None:
    if not secret:
        raise WebhookVerificationError("github webhook secret not configured")
    sig = headers.get("x-hub-signature-256", "")
    if not sig.startswith("sha256="):
        raise WebhookVerificationError("missing X-Hub-Signature-256")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not _eq(sig, expected):
        raise WebhookVerificationError("github signature mismatch")


def verify_gitlab(body: bytes, headers: dict[str, str], secret: str) -> None:
    if not secret:
        raise WebhookVerificationError("gitlab webhook secret not configured")
    token = headers.get("x-gitlab-token", "")
    if not token or not _eq(token, secret):
        raise WebhookVerificationError("gitlab token mismatch")


def verify_bitbucket(body: bytes, headers: dict[str, str], secret: str) -> None:
    """Bitbucket Server/DC sends X-Hub-Signature (HMAC); Bitbucket Cloud has no HMAC,
    so we require the shared secret via the X-Aegis-Secret header set on the webhook
    URL/proxy (documented in docs/04 §2; combined with IP allowlist at the edge)."""
    if not secret:
        raise WebhookVerificationError("bitbucket webhook secret not configured")
    hub = headers.get("x-hub-signature", "")
    if hub.startswith("sha256="):
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not _eq(hub, expected):
            raise WebhookVerificationError("bitbucket signature mismatch")
        return
    shared = headers.get("x-aegis-secret", "")
    if not shared or not _eq(shared, secret):
        raise WebhookVerificationError("bitbucket shared-secret mismatch")


def verify(provider: Provider, body: bytes, headers: dict[str, str], secret: str) -> None:
    {
        Provider.GITHUB: verify_github,
        Provider.GITLAB: verify_gitlab,
        Provider.BITBUCKET: verify_bitbucket,
    }[provider](body, headers, secret)
