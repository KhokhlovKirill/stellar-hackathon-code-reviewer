"""Tier selection, health checks and fallback for LLM analysis."""

from __future__ import annotations

import time

from aegis.config import get_config, get_settings
from aegis.llm.base import ChatMessage, JSONSchema, LLMClient, LLMCompletion, LLMError
from aegis.llm.openai_compat import OpenAICompatibleClient
from aegis.obs import get_logger, metrics

log = get_logger("aegis.llm.router")


class LLMRouter:
    def __init__(self) -> None:
        self.cfg = get_config().llm
        self.settings = get_settings()
        self._health_cache: dict[str, tuple[float, bool]] = {}

    def _clients(self) -> dict[str, LLMClient]:
        s = self.settings
        return {
            "local-secure": OpenAICompatibleClient(
                tier="local-secure",
                base_url=s.lmstudio_base_url,
                model=s.lmstudio_secure_model,
                api_key="",
                strict_schema=False,
            ),
            "local-base": OpenAICompatibleClient(
                tier="local-base",
                base_url=s.lmstudio_base_url,
                model=s.lmstudio_base_model,
                api_key="",
                strict_schema=False,
            ),
            "cloud-generalist": OpenAICompatibleClient(
                tier="cloud-generalist",
                base_url=s.openrouter_base_url,
                model=s.openrouter_generalist_model,
                api_key=s.openrouter_api_key,
                strict_schema=False,  # deepseek / qwen don't support json_schema format
                extra_headers={"HTTP-Referer": "https://aegis.local", "X-Title": "Aegis"},
            ),
            "cloud-judge": OpenAICompatibleClient(
                tier="cloud-judge",
                base_url=s.openrouter_base_url,
                model=s.openrouter_judge_model,
                api_key=s.openrouter_api_key,
                strict_schema=False,  # use prompt-based JSON for reliability across models
                extra_headers={"HTTP-Referer": "https://aegis.local", "X-Title": "Aegis"},
            ),
        }

    async def _healthy(self, client: LLMClient) -> bool:
        now = time.monotonic()
        cached = self._health_cache.get(client.tier)
        if cached and now - cached[0] < self.cfg.tier_health_ttl_seconds:
            return cached[1]
        ok = await client.healthy()
        self._health_cache[client.tier] = (now, ok)
        metrics.llm_tier_down.labels(client.tier).set(0 if ok else 1)
        return ok

    def _fallback_order(self, role: str) -> list[str]:
        if role == "detector_a":
            primary = self.cfg.detector_a
            return [primary, "cloud-generalist", "local-base", "cloud-judge"]
        if role == "detector_b":
            primary = self.cfg.detector_b
            return [primary, "local-base", "cloud-generalist", "local-secure"]
        if role == "judge":
            primary = self.cfg.judge
            return [primary, "cloud-judge", "local-secure", "cloud-generalist"]
        raise ValueError(f"unknown llm role: {role}")

    async def complete(
        self,
        *,
        role: str,
        messages: list[ChatMessage],
        schema: JSONSchema,
        max_tokens: int = 4096,
    ) -> LLMCompletion:
        clients = self._clients()
        last_error: Exception | None = None
        attempted: list[str] = []

        for tier in dict.fromkeys(self._fallback_order(role)):
            client = clients.get(tier)
            if client is None:
                continue
            attempted.append(tier)
            if not await self._healthy(client):
                last_error = LLMError(f"{tier}: health check failed")
                continue
            try:
                out = await client.complete(
                    messages=messages,
                    schema=schema,
                    role=role,
                    timeout_seconds=self.cfg.request_timeout_seconds,
                    max_tokens=max_tokens,
                )
                if tier != attempted[0]:
                    metrics.llm_fallback_total.labels(attempted[0], tier).inc()
                    log.warning("llm.fallback", role=role, from_tier=attempted[0], to_tier=tier)
                metrics.llm_tokens_total.labels(tier, "prompt").inc(out.usage.prompt_tokens)
                metrics.llm_tokens_total.labels(tier, "completion").inc(out.usage.completion_tokens)
                metrics.llm_cost_usd_total.labels(tier).inc(out.usage.cost_usd)
                metrics.llm_latency.labels(tier).observe(out.latency_ms / 1000)
                return out
            except Exception as exc:
                last_error = exc
                self._health_cache[tier] = (time.monotonic(), False)
                metrics.llm_tier_down.labels(tier).set(1)
                log.warning("llm.tier_failed", role=role, tier=tier, error=str(exc))

        raise LLMError(f"all LLM tiers failed for {role}: {last_error}")
