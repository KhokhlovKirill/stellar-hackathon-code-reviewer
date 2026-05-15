"""Typed error hierarchy. Every failure path raises one of these, never a bare Exception."""

from __future__ import annotations


class AegisError(Exception):
    """Base for all Aegis errors."""


class ConfigError(AegisError):
    """Invalid or missing configuration. Raised fail-fast at startup."""


class WebhookVerificationError(AegisError):
    """Webhook signature/token verification failed. Maps to HTTP 401."""


class WebhookPayloadError(AegisError):
    """Webhook body malformed or event not understood. Maps to HTTP 400."""


class ProviderError(AegisError):
    """A VCS provider API call failed."""

    def __init__(self, provider: str, message: str, status: int | None = None) -> None:
        self.provider = provider
        self.status = status
        super().__init__(f"[{provider}] {message}" + (f" (HTTP {status})" if status else ""))


class ProviderRateLimited(ProviderError):
    """VCS provider rate-limited the request; retry with backoff."""


class LLMError(AegisError):
    """An LLM tier call failed."""

    def __init__(self, tier: str, message: str) -> None:
        self.tier = tier
        super().__init__(f"[llm:{tier}] {message}")


class LLMUnavailable(LLMError):
    """An LLM tier is unreachable; router should fall back."""


class LLMOutputError(LLMError):
    """LLM produced output that could not be parsed even after repair."""


class BudgetExceeded(AegisError):
    """Per-scan token/cost budget exhausted; degrade gracefully."""


class VaultError(AegisError):
    """Token vault encrypt/decrypt failure."""
