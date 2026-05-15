"""LLM router — selects between Anthropic Claude (primary) and OpenRouter (fallback)."""

from __future__ import annotations

import time
from typing import Any

from aegis.config import settings
from aegis.observability.logging import get_logger
from aegis.observability.metrics import llm_errors_total, llm_latency_seconds, llm_requests_total, llm_tokens_used_total

log = get_logger(__name__)


def _get_anthropic_client():
    from langchain_anthropic import ChatAnthropic
    return ChatAnthropic(
        model=settings.primary_llm_model,
        anthropic_api_key=settings.anthropic_api_key,
        max_tokens=settings.llm_max_tokens,
        temperature=settings.llm_temperature,
        timeout=settings.llm_timeout,
        max_retries=settings.llm_max_retries,
    )


def _get_openrouter_client():
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=settings.fallback_llm_model,
        openai_api_key=settings.openrouter_api_key,
        openai_api_base=settings.openrouter_base_url,
        max_tokens=settings.llm_max_tokens,
        temperature=settings.llm_temperature,
        timeout=settings.llm_timeout,
        max_retries=1,
        default_headers={"HTTP-Referer": "https://aegis.devsecops", "X-Title": "Aegis"},
    )


async def call_llm(
    system_prompt: str,
    user_prompt: str,
    agent_name: str = "unknown",
    use_fallback: bool = False,
    tools: list | None = None,
) -> dict[str, Any]:
    """Invoke the primary or fallback LLM and return structured result.

    Args:
        system_prompt: Role/context instructions.
        user_prompt: The actual task/content to analyse.
        agent_name: Name of the calling agent (for metrics).
        use_fallback: Force OpenRouter instead of Anthropic.
        tools: Optional list of LangChain tools.

    Returns:
        {content, model, prompt_tokens, completion_tokens, latency_ms}
    """
    # Sanitize inputs to prevent prompt injection
    system_prompt = _sanitize_prompt(system_prompt)
    user_prompt = _sanitize_prompt(user_prompt)

    model_name = settings.fallback_llm_model if use_fallback else settings.primary_llm_model

    start = time.perf_counter()
    llm_requests_total.labels(model=model_name, agent=agent_name).inc()

    from langchain_core.messages import HumanMessage, SystemMessage

    try:
        if use_fallback or not settings.anthropic_api_key:
            llm = _get_openrouter_client()
        else:
            llm = _get_anthropic_client()

        if tools:
            llm = llm.bind_tools(tools)

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]

        response = await llm.ainvoke(messages)

        latency_ms = int((time.perf_counter() - start) * 1000)
        usage = getattr(response, "usage_metadata", {}) or {}
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)

        llm_tokens_used_total.labels(model=model_name, type="prompt").inc(prompt_tokens)
        llm_tokens_used_total.labels(model=model_name, type="completion").inc(completion_tokens)
        llm_latency_seconds.labels(model=model_name).observe(latency_ms / 1000)

        log.debug(
            "llm.response",
            agent=agent_name,
            model=model_name,
            tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
        )

        return {
            "content": response.content,
            "model": model_name,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
            "tool_calls": getattr(response, "tool_calls", []),
        }

    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        error_type = type(exc).__name__
        llm_errors_total.labels(model=model_name, error_type=error_type).inc()

        # Automatic fallback if primary failed and we weren't already on fallback
        if not use_fallback and settings.openrouter_api_key:
            log.warning("llm.primary_failed_fallback", error=str(exc), agent=agent_name)
            return await call_llm(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                agent_name=agent_name,
                use_fallback=True,
                tools=tools,
            )

        log.error("llm.failed", error=str(exc), agent=agent_name, latency_ms=latency_ms)
        raise


def _sanitize_prompt(text: str) -> str:
    """Basic prompt injection mitigation."""
    # Remove common injection patterns
    dangerous = [
        "Ignore previous instructions",
        "Disregard all prior",
        "You are now",
        "SYSTEM OVERRIDE",
    ]
    for pattern in dangerous:
        if pattern.lower() in text.lower():
            text = text.replace(pattern, "[REDACTED]")
    return text
