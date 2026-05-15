"""LLM client contracts shared by OpenRouter and LM Studio tiers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ChatMessage = dict[str, str]
JSONSchema = dict[str, Any]


class LLMError(RuntimeError):
    """Raised when a model tier cannot complete a request."""


@dataclass(frozen=True, slots=True)
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0


@dataclass(frozen=True, slots=True)
class LLMCompletion:
    tier: str
    model: str
    role: str
    content: str
    usage: LLMUsage = field(default_factory=LLMUsage)
    latency_ms: int = 0
    degraded: bool = False


class LLMClient:
    tier: str
    model: str

    async def healthy(self) -> bool:
        raise NotImplementedError

    async def complete(
        self,
        *,
        messages: list[ChatMessage],
        schema: JSONSchema,
        role: str,
        timeout_seconds: int,
        max_tokens: int,
    ) -> LLMCompletion:
        raise NotImplementedError
