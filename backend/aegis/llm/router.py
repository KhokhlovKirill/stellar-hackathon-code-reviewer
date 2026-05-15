"""Tier selection, health checks and fallback for LLM analysis.

Local-swap mode (LMSTUDIO_SWAP_MODELS=true):
  All roles run on local LM Studio models. Only one model is loaded at a time;
  the manager unloads the previous before loading the next. Role → model mapping:
    detector_a  → LMSTUDIO_GENERALIST_MODEL  (qwen3.6-35b, large reasoning model)
    detector_b  → LMSTUDIO_SECURE_MODEL      (don-agent-v3, infosec specialist)
    judge       → LMSTUDIO_JUDGE_MODEL       (defaults to generalist model)

Cloud tiers (LMSTUDIO_SWAP_MODELS=false):
    detector_a  → cloud-generalist (DeepSeek V4 Flash free)  → cloud-mimo  → local-secure
    detector_b  → cloud-mimo (MiMo-V2-Flash)  → cloud-generalist  → local-secure
    judge       → cloud-judge (Qwen3 Coder free)  → cloud-generalist  → local-secure
"""

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

    def _swap_enabled(self) -> bool:
        return self.settings.lmstudio_swap_models

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
            "local-generalist": OpenAICompatibleClient(
                tier="local-generalist",
                base_url=s.lmstudio_base_url,
                model=s.lmstudio_generalist_model,
                api_key="",
                strict_schema=False,
            ),
            "local-judge": OpenAICompatibleClient(
                tier="local-judge",
                base_url=s.lmstudio_base_url,
                model=s.lmstudio_judge_model,
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
                strict_schema=False,
                extra_headers={"HTTP-Referer": "https://aegis.local", "X-Title": "Aegis"},
            ),
            "cloud-judge": OpenAICompatibleClient(
                tier="cloud-judge",
                base_url=s.openrouter_base_url,
                model=s.openrouter_judge_model,
                api_key=s.openrouter_api_key,
                strict_schema=False,
                extra_headers={"HTTP-Referer": "https://aegis.local", "X-Title": "Aegis"},
            ),
            "cloud-mimo": OpenAICompatibleClient(
                tier="cloud-mimo",
                base_url=s.openrouter_base_url,
                model=s.openrouter_mimo_model,
                api_key=s.openrouter_api_key,
                strict_schema=False,
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
        if self._swap_enabled():
            # Local-first with cloud fallback when local models hit context limits
            if role == "detector_a":
                return ["local-generalist", "local-base", "cloud-generalist"]
            if role == "detector_b":
                return ["local-secure", "local-generalist", "cloud-generalist"]
            if role == "judge":
                return ["local-judge", "local-generalist", "cloud-judge"]
            raise ValueError(f"unknown llm role: {role}")

        # Cloud-first; don-agent-v3 (local-secure) is last-resort fallback only
        if role == "detector_a":
            return ["cloud-generalist", "cloud-mimo", "local-secure"]
        if role == "detector_b":
            return ["cloud-mimo", "cloud-generalist", "local-secure"]
        if role == "judge":
            return ["cloud-judge", "cloud-generalist", "local-secure"]
        raise ValueError(f"unknown llm role: {role}")

    def _model_for_tier(self, tier: str) -> str | None:
        """Return the LM Studio model ID for a tier (local-* tiers only)."""
        s = self.settings
        return {
            "local-secure": s.lmstudio_secure_model,
            "local-generalist": s.lmstudio_generalist_model,
            "local-judge": s.lmstudio_judge_model,
            "local-base": s.lmstudio_base_model,
        }.get(tier)

    async def _ensure_local_model(self, tier: str) -> str | None:
        """Ensure the right model is loaded. Returns active model ID or None."""
        model_id = self._model_for_tier(tier)
        if model_id is None:
            return None
        from aegis.llm.lmstudio_manager import ensure_model
        return await ensure_model(self.settings.lmstudio_base_url, model_id)

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

            # Swap model before health check (swap mode only)
            active_model: str | None = None
            if self._swap_enabled() and tier.startswith("local-"):
                try:
                    active_model = await self._ensure_local_model(tier)
                except Exception as exc:
                    log.warning("llm.swap_failed", tier=tier, error=str(exc))
                    last_error = LLMError(f"{tier}: model swap failed: {exc}")
                    continue

            # If swap manager returned a different active model, use an ad-hoc client
            if active_model and active_model != client.model:
                client = OpenAICompatibleClient(
                    tier=tier,
                    base_url=self.settings.lmstudio_base_url,
                    model=active_model,
                    api_key="",
                    strict_schema=False,
                )

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
