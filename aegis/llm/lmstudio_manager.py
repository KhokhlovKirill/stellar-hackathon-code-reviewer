"""LM Studio model lifecycle manager.

Strategy:
  1. Try LM Studio load/unload API (supported in newer builds).
  2. If the API is not available or returns a body-level error, fall back to
     "use whatever is currently loaded" — the user selects models in the UI.

The asyncio.Lock ensures completions are serialised when swap_models=True so only
one large model occupies VRAM at a time.
"""

from __future__ import annotations

import asyncio

import httpx

from aegis.obs import get_logger

log = get_logger("aegis.llm.lmstudio_manager")

_lock = asyncio.Lock()


def _v0_base(base_url: str) -> str:
    """http://localhost:1234/v1  →  http://localhost:1234/api/v0"""
    return base_url.rstrip("/").removesuffix("/v1") + "/api/v0"


def _root(base_url: str) -> str:
    """http://localhost:1234/v1  →  http://localhost:1234"""
    return base_url.rstrip("/").removesuffix("/v1")


async def _get_models(base_url: str) -> list[dict]:
    """Return full model list from /api/v0/models."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{_v0_base(base_url)}/models")
        if r.status_code == 200:
            return r.json().get("data", [])
    except Exception as exc:
        log.warning("lmstudio.get_models_error", error=str(exc))
    return []


async def loaded_llm_ids(base_url: str) -> list[str]:
    """IDs of currently loaded LLM/VLM models."""
    return [
        m["id"] for m in await _get_models(base_url)
        if m.get("state") == "loaded" and m.get("type") in ("llm", "vlm")
    ]


def _is_body_error(resp: httpx.Response) -> bool:
    """Return True if LM Studio returned HTTP 200 but body contains an error."""
    try:
        body = resp.json()
        return "error" in body and "choices" not in body
    except Exception:
        return False


async def _try_load(base_url: str, model_id: str) -> bool:
    """Attempt to load model via LM Studio API. Returns True on success."""
    v0 = _v0_base(base_url)
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            r = await client.post(
                f"{v0}/models/load",
                json={"identifier": model_id, "ttl": 0},
            )
        if r.status_code in (200, 201) and not _is_body_error(r):
            log.info("lmstudio.api_load_ok", model=model_id)
            return True
        # Body error = endpoint not supported in this LM Studio version
        err = r.text[:120]
        log.warning("lmstudio.api_load_unsupported", model=model_id, body=err)
        return False
    except Exception as exc:
        log.warning("lmstudio.api_load_error", model=model_id, error=str(exc))
        return False


async def _try_unload(base_url: str, model_id: str) -> bool:
    """Attempt to unload model via LM Studio API. Returns True on success."""
    v0 = _v0_base(base_url)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{v0}/models/unload",
                json={"identifier": model_id},
            )
        if r.status_code in (200, 201, 404) and not _is_body_error(r):
            log.info("lmstudio.api_unload_ok", model=model_id)
            return True
        return False
    except Exception:
        return False


async def ensure_model(base_url: str, model_id: str) -> str:
    """Ensure model_id is loaded in LM Studio. Returns the model ID to use.

    If programmatic load is available: unloads others, loads target.
    If not: returns whatever LLM is currently loaded (user manages via UI).
    Falls back to model_id itself so the completion request can still be made.
    """
    async with _lock:
        currently = await loaded_llm_ids(base_url)

        if model_id in currently:
            log.info("lmstudio.already_loaded", model=model_id)
            return model_id

        # Try API-based swap
        api_works = await _try_load(base_url, model_id)

        if api_works:
            # Unload all others to free memory
            for m in currently:
                if m != model_id:
                    await _try_unload(base_url, m)
            return model_id

        # API not supported — use what's loaded
        if currently:
            active = currently[0]
            log.info(
                "lmstudio.api_unavailable_using_loaded",
                requested=model_id,
                using=active,
            )
            return active

        # Nothing loaded and API unavailable
        log.warning(
            "lmstudio.no_model_loaded",
            requested=model_id,
            hint="Load the model in LM Studio UI first",
        )
        return model_id  # let the completion fail with a clear model-not-loaded error


async def unload_all(base_url: str) -> None:
    """Try to unload every loaded LLM to free memory."""
    async with _lock:
        for m in await loaded_llm_ids(base_url):
            await _try_unload(base_url, m)
