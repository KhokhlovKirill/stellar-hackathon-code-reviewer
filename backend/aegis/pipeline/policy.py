"""Merge policy stage: publish the security gate status and request changes."""

from __future__ import annotations

from aegis.errors import ProviderError
from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState
from aegis.providers import get_provider
from aegis.schemas import MergePolicyDecision, Severity

log = get_logger("aegis.policy")


async def apply_merge_policy(state: PipelineState) -> None:
    decision = decide(state)
    state.result.decision = decision
    if not state.ctx.access_token:
        state.result.degraded.append("policy:no_token")
        return

    provider = get_provider(state.ev.provider)
    target_url = f"https://aegis.local/scans/{state.scan_id}"
    # The status-check / request-changes calls run AFTER inline comments and the
    # summary are already posted. A failure here (e.g. token lacks the
    # commit-status scope, external statuses disabled, instance quirk) must NOT
    # discard an otherwise-successful, already-published review by bubbling a
    # ProviderError up to the orchestrator (which would mark the whole scan
    # `provider_error`). Degrade gracefully instead.
    try:
        await provider.set_status_check(
            state.pr, state.ctx.access_token, decision, target_url
        )
        if decision.block:
            await provider.request_changes(
                state.pr, state.ctx.access_token, decision.reason
            )
    except ProviderError as exc:
        state.result.degraded.append("policy:status_check_failed")
        log.warning(
            "policy.status_check_failed",
            scan_id=state.scan_id,
            error=str(exc),
            block=decision.block,
            state=decision.state,
        )
        return

    log.info(
        "policy.applied",
        scan_id=state.scan_id,
        block=decision.block,
        state=decision.state,
        reason=decision.reason,
    )


def decide(state: PipelineState) -> MergePolicyDecision:
    critical = any(f.severity is Severity.CRITICAL for f in state.findings)
    high = any(f.severity is Severity.HIGH for f in state.findings)
    mode = state.ctx.merge_block
    block = False
    reason = "Aegis security review passed"

    if mode == "off":
        block = False
    elif critical:
        block = True
        reason = "Critical security finding detected by Aegis"
    elif mode == "high" and high:
        block = True
        reason = "High severity security finding detected by Aegis"
    elif state.risk_score > 60:
        block = True
        reason = f"Aegis Risk Score is {state.risk_score}/100"

    return MergePolicyDecision(
        block=block,
        state="failure" if block else "success",
        context="aegis/security-gate",
        reason=reason,
    )
