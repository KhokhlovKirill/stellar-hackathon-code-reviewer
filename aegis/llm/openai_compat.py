"""OpenAI-compatible chat-completions client.

Both OpenRouter and LM Studio expose `/v1/chat/completions`; only auth headers and
structured-output support differ. This client keeps provider quirks localized.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from aegis.llm.base import ChatMessage, JSONSchema, LLMClient, LLMCompletion, LLMError, LLMUsage


class OpenAICompatibleClient(LLMClient):
    def __init__(
        self,
        *,
        tier: str,
        base_url: str,
        model: str,
        api_key: str = "",
        strict_schema: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.tier = tier
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.strict_schema = strict_schema
        self.extra_headers = extra_headers or {}

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def healthy(self) -> bool:
        if "openrouter.ai" in self.base_url and not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/models", headers=self._headers())
            return r.status_code < 500
        except httpx.HTTPError:
            return False

    async def complete(
        self,
        *,
        messages: list[ChatMessage],
        schema: JSONSchema,
        role: str,
        timeout_seconds: int,
        max_tokens: int,
    ) -> LLMCompletion:
        if "openrouter.ai" in self.base_url and not self.api_key:
            raise LLMError(f"{self.tier}: OPENROUTER_API_KEY is not configured")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": max_tokens,
        }
        if self.strict_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "aegis_security_findings",
                    "strict": True,
                    "schema": schema,
                },
            }
        else:
            # LM Studio currently accepts `json_schema` or `text`, not OpenAI's
            # legacy `json_object`. Local models still receive the schema in the
            # prompt and are validated by our parser after completion.
            payload["response_format"] = {"type": "text"}

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise LLMError(f"{self.tier}: request failed: {exc}") from exc

        latency_ms = int((time.monotonic() - t0) * 1000)
        if r.status_code >= 400:
            raise LLMError(f"{self.tier}: HTTP {r.status_code}: {r.text[:500]}")

        data = r.json()
        content = _message_content(data)
        usage = data.get("usage") or {}
        return LLMCompletion(
            tier=self.tier,
            model=self.model,
            role=role,
            content=content,
            usage=LLMUsage(
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                cost_usd=float((usage.get("cost") or usage.get("total_cost") or 0.0) or 0.0),
            ),
            latency_ms=latency_ms,
        )


def _message_content(data: dict[str, Any]) -> str:
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("malformed chat-completions response") from exc
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "\n".join(parts)
    raise LLMError("chat-completions response content is not text")
