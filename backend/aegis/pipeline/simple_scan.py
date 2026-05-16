"""Pull-mode scanner: fetch public GitHub PR diff → run analysis → return findings.

No webhook, no token required. Works on any public repo.
For private repos: pass access_token (optional).
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegis.config import get_settings
from aegis.llm.base import LLMCompletion
from aegis.llm.parser import finding_schema, parse_findings
from aegis.llm.prompt import judge_messages, review_messages
from aegis.llm.router import LLMRouter
from aegis.obs import get_logger
from aegis.pipeline.deterministic.secrets import scan_secrets
from aegis.pipeline.i18n import localize_findings_inplace
from aegis.providers.diffparse import parse_unified_diff
from aegis.schemas import FileChange, Finding, FindingSource, Severity

log = get_logger("aegis.simple_scan")

_GH_API = "https://api.github.com"
_GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

# Files to skip in analysis (too large or irrelevant)
_SKIP_EXTENSIONS = {".lock", ".sum", ".mod", ".min.js", ".min.css", ".map", ".svg",
                    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"}
_MAX_DIFF_BYTES = 300_000


@dataclass
class SimpleScanResult:
    repo: str
    pr_number: int
    pr_title: str
    pr_url: str
    pr_author: str
    scan_id: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    files_scanned: int = 0
    degraded: bool = False  # True if LLM was skipped
    degraded_reasons: list[str] = field(default_factory=list)
    files_scanned_paths: list[str] = field(default_factory=list)
    head_sha: str = ""
    summary: str = ""
    finding_labels: dict[str, str] = field(default_factory=dict)


def _parse_github_url(url: str) -> tuple[str, int | None]:
    """Return (owner/repo, pr_number_or_None) from any GitHub URL."""
    url = url.strip().rstrip("/")
    # PR URL: github.com/owner/repo/pull/123
    m = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", url)
    if m:
        return m.group(1).removesuffix(".git"), int(m.group(2))
    # Repo URL: github.com/owner/repo
    m = re.search(r"github\.com/([^/]+/[^/]+)", url)
    if m:
        return m.group(1).removesuffix(".git"), None
    # bare slug: owner/repo
    if re.match(r"^[^/]+/[^/]+$", url):
        return url, None
    raise ValueError(f"Cannot parse GitHub URL: {url!r}")


def _gh_headers(token: str | None) -> dict[str, str]:
    h = dict(_GH_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h



async def _fetch_latest_pr(slug: str, token: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls",
            params={"state": "open", "per_page": 1, "sort": "updated", "direction": "desc"},
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"GitHub API {r.status_code}: {r.json().get('message', 'error')}")
    prs = r.json()
    if not prs:
        # No open PRs — try fetching closed ones
        async with httpx.AsyncClient(timeout=20) as client:
            r2 = await client.get(
                f"{_GH_API}/repos/{slug}/pulls",
                params={"state": "closed", "per_page": 1, "sort": "updated", "direction": "desc"},
                headers=_gh_headers(token),
            )
        prs = r2.json() if r2.status_code == 200 else []
    if not prs:
        raise ValueError("No pull requests found in this repository")
    return prs[0]  # type: ignore[no-any-return]


async def _fetch_pr(slug: str, pr_number: int, token: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls/{pr_number}",
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"GitHub API {r.status_code}: {r.json().get('message', 'error')}")
    return r.json()  # type: ignore[no-any-return]


async def _fetch_diff(slug: str, pr_number: int, token: str | None) -> str:
    """Fetch PR diff via /files endpoint (works for all visibility levels)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls/{pr_number}/files",
            params={"per_page": 100},
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"Diff fetch failed: HTTP {r.status_code}: {r.json().get('message', '')}")

    files = r.json()
    if not isinstance(files, list):
        raise ValueError("Unexpected GitHub API response format")

    # Reconstruct unified diff from per-file patches
    parts: list[str] = []
    total_bytes = 0
    for f in files:
        patch = f.get("patch", "")
        if not patch:
            continue
        filename = f.get("filename", "")
        old_name = f.get("previous_filename", filename)
        header = f"--- a/{old_name}\n+++ b/{filename}\n{patch}\n"
        total_bytes += len(header)
        if total_bytes > _MAX_DIFF_BYTES:
            break
        parts.append(header)

    return "\n".join(parts)


def _filter_files(files: list[FileChange]) -> list[FileChange]:
    out = []
    for f in files:
        if any(f.path.endswith(ext) for ext in _SKIP_EXTENSIONS):
            continue
        if not f.hunks:
            continue
        out.append(f)
    return out


async def _get_local_context_tokens() -> int:
    """Return loaded context tokens from LM Studio, or a safe default."""
    try:
        v0_base = get_settings().lmstudio_base_url.rstrip("/").removesuffix("/v1")
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{v0_base}/api/v0/models")
        for m in r.json().get("data", []):
            if m.get("state") == "loaded" and m.get("type") in ("llm", "vlm"):
                return int(m.get("loaded_context_length", 8192))
    except Exception as exc:
        log.warning("simple_scan.context_probe_failed", error=str(exc))
    return 8192


def _trim_files_to_budget(files: list[FileChange], char_budget: int) -> list[FileChange]:
    """Return as many files as fit within char_budget (rough token proxy: 3 chars/token).

    Size includes formatting overhead from _format_diff (hunk headers, line prefixes).
    """
    out: list[FileChange] = []
    used = 0
    for f in files:
        # Match _format_diff: file header + hunk headers + "ADD old=X new=Y: content" per line
        file_header = len(f"FILE {f.path} language={f.language or 'unknown'} status={f.status}") + 1
        hunk_text = sum(
            len(h.header) + 1 +
            sum(len(f"ADD old= new=: {ln.content}") + 10 for ln in h.lines)
            for h in f.hunks
        )
        size = file_header + hunk_text
        if used + size > char_budget:
            break
        out.append(f)
        used += size
    return out or files[:1]  # always send at least 1 file


async def _run_llm(
    slug: str,
    pr_number: int,
    files: list[FileChange],
    det_findings: list[Finding],
    lang: str = "ru",
) -> tuple[list[Finding], list[str]]:
    """Run cloud + mandatory Don detector, then judge.

    OpenRouter and local Don are launched concurrently. Don is forced to the
    `local-secure` tier so it cannot be silently replaced by another model.
    Returns (findings, degraded_reasons).
    """
    if not files:
        return [], []

    router = LLMRouter()
    schema = finding_schema()

    # Limit diff to local model's loaded context (reserve 4096 for response + ~500 system/meta)
    # Empirical: Qwen tokenizer ~2 chars/token for mixed code content (conservative)
    ctx_tokens = await _get_local_context_tokens()
    available_tokens = max(ctx_tokens - 4096 - 500, 2048)
    char_budget = int(available_tokens * 2.0)
    trimmed_files = _trim_files_to_budget(files, char_budget)
    if len(trimmed_files) < len(files):
        log.info(
            "simple_scan.diff_trimmed",
            total=len(files),
            sent=len(trimmed_files),
            ctx_tokens=ctx_tokens,
        )

    messages = review_messages(
        repo=slug,
        pr_id=str(pr_number),
        files=trimmed_files,
        deterministic_findings=det_findings,
        context_map={},
        lang=lang,
    )
    don_messages = [
        {
            "role": "system",
            "content": (
                messages[0]["content"]
                + "\n\nYou are Don, the mandatory local security specialist for this "
                "review. Use your offensive-security knowledge to find exploitable "
                "issues in the changed code, but do not use action tags. Return only "
                "the JSON object requested above."
            ),
        },
        messages[1],
    ]

    degraded_reasons: list[str] = []

    async def _run_cloud() -> LLMCompletion:
        # Bounded so a slow/queued fallback to the local model can't make the
        # whole scan hang — deterministic + Don findings still return.
        return await asyncio.wait_for(
            router.complete(
                role="detector_a",
                messages=messages,
                schema=schema,
                max_tokens=4096,
            ),
            timeout=_CLOUD_DETECTOR_BUDGET_SECONDS,
        )

    async def _run_don() -> LLMCompletion:
        # Don runs on the Mac via the reverse tunnel; a saturated LM Studio
        # queue must not stall the request indefinitely.
        return await asyncio.wait_for(
            router.complete_on_tier(
                tier="local-secure",
                role="detector_b",
                messages=don_messages,
                schema=schema,
                max_tokens=4096,
            ),
            timeout=_DON_DETECTOR_BUDGET_SECONDS,
        )

    cloud_result, don_result = await asyncio.gather(
        _run_cloud(),
        _run_don(),
        return_exceptions=True,
    )

    llm_findings: list[Finding] = []
    cloud_findings: list[Finding] = []
    don_findings: list[Finding] = []
    if isinstance(cloud_result, BaseException):
        degraded_reasons.append("cloud-detector")
        log.warning("simple_scan.cloud_detector_failed", error=str(cloud_result))
    else:
        raw = parse_findings(cloud_result.content, source=FindingSource.LLM_B)
        cloud_findings = [f for f in raw if f.severity in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
        )]
        llm_findings.extend(cloud_findings)
        log.info(
            "simple_scan.cloud_detector_ok",
            tier=cloud_result.tier,
            count=len(cloud_findings),
            chars=len(cloud_result.content),
            completion_tokens=cloud_result.usage.completion_tokens,
        )

    if isinstance(don_result, BaseException):
        degraded_reasons.append("local-secure")
        log.warning("simple_scan.don_detector_failed", error=str(don_result))
    else:
        raw = parse_findings(don_result.content, source=FindingSource.LLM_A)
        don_findings = [f for f in raw if f.severity in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
        )]
        llm_findings.extend(don_findings)
        log.info(
            "simple_scan.don_detector_ok",
            tier=don_result.tier,
            count=len(don_findings),
            chars=len(don_result.content),
            completion_tokens=don_result.usage.completion_tokens,
        )

    if not llm_findings and degraded_reasons:
        return det_findings, degraded_reasons

    # Judge pass — consolidate + deduplicate
    all_candidates = det_findings + llm_findings
    if all_candidates:
        try:
            j_messages = judge_messages(
                repo=slug,
                pr_id=str(pr_number),
                files=trimmed_files,
                candidates=all_candidates,
                context_map={},
                lang=lang,
            )
            j_completion = await asyncio.wait_for(
                router.complete(
                    role="judge",
                    messages=j_messages,
                    schema=schema,
                    max_tokens=4096,
                ),
                timeout=_JUDGE_BUDGET_SECONDS,
            )
            judged = parse_findings(j_completion.content, source=FindingSource.JUDGE)
            log.info("simple_scan.judge_ok", tier=j_completion.tier, count=len(judged))
            return _merge_judged_with_sources(judged, all_candidates), degraded_reasons
        except Exception as exc:
            log.warning("simple_scan.judge_failed", error=str(exc))
            # Return merged without judging
            degraded_reasons.append("judge")
            return _dedupe_findings(all_candidates), degraded_reasons

    return _dedupe_findings(all_candidates), degraded_reasons


def _finding_key(f: Finding) -> tuple[str, int, str]:
    return (f.file, f.line, (f.cwe or f.title).lower())


def _same_finding(a: Finding, b: Finding) -> bool:
    if a.file != b.file or a.line != b.line:
        return False
    if a.cwe and b.cwe and a.cwe == b.cwe:
        return True
    return a.title.strip().lower() == b.title.strip().lower()


def _higher_severity(a: Severity, b: Severity) -> Severity:
    return a if a.rank >= b.rank else b


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        match_idx = next((i for i, existing in enumerate(out) if _same_finding(existing, f)), None)
        if match_idx is None:
            out.append(f)
            continue
        existing = out[match_idx]
        if f.confidence > existing.confidence or f.source is FindingSource.LLM_A:
            out[match_idx] = f.model_copy(
                update={
                    "severity": _higher_severity(existing.severity, f.severity),
                    "confidence": max(existing.confidence, f.confidence),
                }
            )
    return out


def _merge_judged_with_sources(judged: list[Finding], candidates: list[Finding]) -> list[Finding]:
    """Keep judge filtering while preserving Don/cloud source and wording.

    The judge is best at deduplication, but its canonical JSON loses which
    detector found the issue. For display and auditability we map each judged
    finding back to the closest candidate, preferring Don when it participated.
    """
    if not judged:
        return _dedupe_findings(candidates)

    merged: list[Finding] = []
    for jf in judged:
        matches = [c for c in candidates if _same_finding(jf, c)]
        if not matches:
            merged.append(jf)
            continue
        preferred = (
            next((c for c in matches if c.source is FindingSource.LLM_A), None)
            or matches[0]
        )
        merged.append(
            preferred.model_copy(
                update={
                    "severity": _higher_severity(jf.severity, preferred.severity),
                    "confidence": max(jf.confidence, preferred.confidence),
                    "diff_position": jf.diff_position or preferred.diff_position,
                }
            )
        )
    return _dedupe_findings(merged)


def _fallback_summary(
    slug: str,
    pr_number: int,
    files_scanned: int,
    findings: list[Finding],
    degraded_reasons: list[str],
    lang: str = "ru",
) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    ordered = ", ".join(
        f"{counts[sev]} {sev}" for sev in ("critical", "high", "medium", "low", "info")
        if counts.get(sev)
    ) or "0 findings"
    top = findings[:5]
    if lang == "ru":
        lines = [
            f"Aegis проверил {files_scanned} изменённых файлов в {slug} PR #{pr_number}.",
            f"Подтверждённый результат: {ordered}.",
        ]
        if degraded_reasons:
            lines.append(f"Модули с деградацией: {', '.join(degraded_reasons)}.")
        if top:
            lines.append("Самые приоритетные пункты:")
            lines.extend(
                f"- {f.severity.value.upper()} {f.file}:{f.line} {f.cwe or ''} - {f.title}"
                for f in top
            )
        else:
            lines.append(
                "Подтверждённых эксплуатируемых security проблем "
                "на изменённых строках не найдено."
            )
    else:
        lines = [
            f"Aegis reviewed {files_scanned} changed file(s) in {slug} PR #{pr_number}.",
            f"Confirmed result: {ordered}.",
        ]
        if degraded_reasons:
            lines.append(f"Degraded modules: {', '.join(degraded_reasons)}.")
        if top:
            lines.append("Highest priority items:")
            lines.extend(
                f"- {f.severity.value.upper()} {f.file}:{f.line} {f.cwe or ''} - {f.title}"
                for f in top
            )
        else:
            lines.append("No confirmed exploitable security issues were found on changed lines.")
    return "\n".join(lines)


def _fallback_finding_labels(findings: list[Finding]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for f in findings:
        words = re.findall(r"[\w#./-]+", f.title, flags=re.UNICODE)[:5]
        labels[f.fingerprint()] = " ".join(words) or (f.cwe or f.severity.value)
    return labels


# Time budgets: the pull-mode scan must return a result even when cloud judge
# tiers are rate-limited and the request falls back to the local Don model
# (which can take minutes for a large prompt). Without these the endpoint
# appears to hang. On timeout the pipeline degrades gracefully.
_CLOUD_DETECTOR_BUDGET_SECONDS = 90
_DON_DETECTOR_BUDGET_SECONDS = 150
_JUDGE_BUDGET_SECONDS = 90
_REVIEW_BUDGET_SECONDS = 90

# Deterministic finding localization lives in aegis.pipeline.i18n (shared
# with the webhook render path). `_localize_findings_inplace` is the resilient
# fallback so per-finding text is always in the configured language even if
# the LLM review pass times out or skips a finding.
_localize_findings_inplace = localize_findings_inplace


async def _generate_scan_review(
    slug: str,
    pr_number: int,
    pr_title: str,
    files_scanned: int,
    findings: list[Finding],
    degraded_reasons: list[str],
    lang: str = "ru",
) -> tuple[str, dict[str, str]]:
    fallback = _fallback_summary(
        slug,
        pr_number,
        files_scanned,
        findings,
        degraded_reasons,
        lang=lang,
    )
    fallback_labels = _fallback_finding_labels(findings)
    language_name = "Russian" if lang == "ru" else "English"

    findings_payload = [
        {
            "fingerprint": f.fingerprint(),
            "severity": f.severity.value,
            "file": f.file,
            "line": f.line,
            "cwe": f.cwe,
            "source": f.source.value,
            "title": f.title,
            "rationale": f.rationale,
        }
        for f in findings[:14]
    ]
    messages = [
        {
            "role": "system",
            "content": (
                "You are Aegis coordinator. Produce two deliverables, both "
                f"written in {language_name}.\n"
                "1) `summary` — clear production security review prose for the "
                "whole pull request: concrete risk, affected files, priority, "
                "whether merge should wait, what happens next. No checklist "
                "templates, no boilerplate.\n"
                "2) `finding_labels` — a 1-5 word UI label per finding (by "
                "fingerprint).\n"
                "Preserve every fingerprint exactly. Return only JSON:\n"
                "{\"summary\":\"...\","
                "\"finding_labels\":[{\"fingerprint\":\"...\",\"label\":\"...\"}]}."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "repo": slug,
                    "pr_number": pr_number,
                    "pr_title": pr_title,
                    "files_scanned": files_scanned,
                    "degraded_modules": degraded_reasons,
                    "findings": findings_payload,
                },
                ensure_ascii=False,
            ),
        },
    ]
    schema = {
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"],
    }
    try:
        completion = await asyncio.wait_for(
            LLMRouter().complete(
                role="judge",
                messages=messages,
                schema=schema,
                max_tokens=1500,
            ),
            timeout=_REVIEW_BUDGET_SECONDS,
        )
        text = completion.content.strip()
        start = text.find("{")
        end = text.rfind("}")
        data = json.loads(text[start:end + 1] if start >= 0 and end > start else text)
        summary = str(data.get("summary") or "").strip()

        labels: dict[str, str] = {}
        raw_labels = data.get("finding_labels") or []
        if isinstance(raw_labels, list):
            for item in raw_labels:
                if not isinstance(item, dict):
                    continue
                fp = str(item.get("fingerprint") or "").strip()
                label = str(item.get("label") or "").strip()
                if fp and label:
                    labels[fp] = " ".join(label.split()[:5])

        # LLM findings are already produced in the target language by the
        # detector/judge prompts. Deterministic findings carry fixed English
        # template text — translate those in place.
        _localize_findings_inplace(findings, lang)

        return summary or fallback, labels or fallback_labels
    except Exception as exc:
        log.warning("simple_scan.summary_failed", error=str(exc))
        _localize_findings_inplace(findings, lang)
        return fallback, fallback_labels


async def _generate_scan_summary(
    slug: str,
    pr_number: int,
    pr_title: str,
    files_scanned: int,
    findings: list[Finding],
    degraded_reasons: list[str],
    lang: str = "ru",
) -> str:
    summary, _labels = await _generate_scan_review(
        slug,
        pr_number,
        pr_title,
        files_scanned,
        findings,
        degraded_reasons,
        lang=lang,
    )
    return summary


async def run_simple_scan(
    url: str,
    token: str | None = None,
    lang: str = "ru",
) -> SimpleScanResult:
    """Main entry point: GitHub URL → analysis result."""
    try:
        slug, pr_number = _parse_github_url(url)
    except ValueError as exc:
        return SimpleScanResult(
            repo="", pr_number=0, pr_title="", pr_url=url, pr_author="",
            error=str(exc),
        )

    # Fetch PR metadata
    try:
        if pr_number is None:
            pr_data = await _fetch_latest_pr(slug, token)
            pr_number = int(pr_data["number"])
        else:
            pr_data = await _fetch_pr(slug, pr_number, token)
    except ValueError as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number or 0, pr_title="", pr_url=url, pr_author="",
            error=str(exc),
        )

    pr_title = pr_data.get("title", f"PR #{pr_number}")
    pr_url = pr_data.get("html_url", url)
    pr_author = (pr_data.get("user") or {}).get("login", "unknown")
    head_sha = ((pr_data.get("head") or {}).get("sha") or "")

    # Fetch unified diff
    try:
        diff_text = await _fetch_diff(slug, pr_number, token)
    except ValueError as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number, pr_title=pr_title,
            pr_url=pr_url, pr_author=pr_author, error=str(exc),
        )

    # Parse diff
    try:
        all_files = parse_unified_diff(diff_text)
    except Exception as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number, pr_title=pr_title,
            pr_url=pr_url, pr_author=pr_author, error=f"Diff parse error: {exc}",
        )

    code_files = _filter_files(all_files)
    files_scanned = len(code_files)

    # Deterministic scan (always)
    det_findings = scan_secrets(code_files)

    # LLM scan (local models with sequential swap, or cloud fallback)
    findings, degraded_reasons = await _run_llm(
        slug, pr_number, code_files, det_findings, lang=lang
    )

    # Free memory — unload LLM after scan completes
    try:
        from aegis.llm.lmstudio_manager import unload_all
        s = get_settings()
        if s.lmstudio_swap_models:
            await unload_all(s.lmstudio_base_url)
    except Exception as exc:
        log.warning("simple_scan.unload_failed", error=str(exc))

    # Sort by severity
    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    findings.sort(key=lambda f: _sev_order.get(f.severity, 9))
    summary, finding_labels = await _generate_scan_review(
        slug,
        pr_number,
        pr_title,
        files_scanned,
        findings,
        degraded_reasons,
        lang=lang,
    )

    return SimpleScanResult(
        repo=slug,
        pr_number=pr_number,
        pr_title=pr_title,
        pr_url=pr_url,
        pr_author=pr_author,
        findings=findings,
        files_scanned=files_scanned,
        degraded=bool(degraded_reasons),
        degraded_reasons=degraded_reasons,
        files_scanned_paths=[f.path for f in code_files],
        head_sha=head_sha,
        summary=summary,
        finding_labels=finding_labels,
    )
