"""Render agent — formats findings into human-readable comments."""

from __future__ import annotations

from urllib.parse import quote

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    # Aggregate risk labels
    "green": "✅",
    "yellow": "🟡",
    "red": "🔴",
}

_SEVERITY_RU = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Инфо",
}

_POLICY_BADGE_RU = {
    "block": "Блокировка",
    "warn": "Предупреждение",
    "pass": "Ок",
}

# shields.io named colors that render as proper badge colors.
_BADGE_COLORS = {
    "critical": "critical",
    "high": "important",
    "medium": "yellow",
    "low": "informational",
    "info": "lightgrey",
    "green": "success",
    "yellow": "yellow",
    "red": "critical",
}


def _shield_badge(label: str, message: str, color: str) -> str:
    """shields.io badge with URL-encoded UTF-8 label/message."""
    return f"https://img.shields.io/badge/{quote(label)}-{quote(str(message))}-{color}"


async def render_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Render findings as Markdown for PR comment publication.

    Updates:
        - state["pr_comment_body"]: main comment markdown string
        - state["inline_comments"]: list[{path, line, body}] for inline comments
        - state["status_check"]: {state, description, context} for GitHub status
    """
    filtered_final_findings = state.get("filtered_final_findings") or state.get("final_findings", [])
    autofix_suggestions = state.get("autofix_suggestions", [])
    risk_score = state.get("risk_score", 0)
    risk_label = state.get("risk_label", "green")
    risk_breakdown = state.get("risk_breakdown", {})
    policy_decision = state.get("policy_decision", "pass")
    policy_reasons = state.get("policy_reasons", [])
    blast_radius = state.get("blast_radius", {})
    pr_metadata = state.get("pr_metadata", {})
    llm_a_summary = state.get("llm_a_summary", "")
    scan_id = state.get("scan_id", "")

    log.info("render.start", findings=len(filtered_final_findings), risk=risk_label)

    # Build main comment
    comment_body = _render_main_comment(
        findings=filtered_final_findings,
        risk_score=risk_score,
        risk_label=risk_label,
        risk_breakdown=risk_breakdown,
        policy_decision=policy_decision,
        policy_reasons=policy_reasons,
        blast_radius=blast_radius,
        summary=llm_a_summary,
        autofix_suggestions=autofix_suggestions,
        scan_id=scan_id,
    )

    # Build inline comments for high/critical findings with line numbers
    inline_comments = _render_inline_comments(filtered_final_findings, autofix_suggestions)

    # Build status check
    status_check = _render_status_check(risk_label, risk_score, policy_decision)

    log.info("render.complete", inline_comments=len(inline_comments))

    return {
        **state,
        "pr_comment_body": comment_body,
        "inline_comments": inline_comments,
        "status_check": status_check,
    }


def _render_main_comment(
    findings: list[dict],
    risk_score: int,
    risk_label: str,
    risk_breakdown: dict,
    policy_decision: str,
    policy_reasons: list[str],
    blast_radius: dict,
    summary: str,
    autofix_suggestions: list[dict],
    scan_id: str,
) -> str:
    emoji = _SEVERITY_EMOJI.get(risk_label, "⚪")
    badge_color = _BADGE_COLORS.get(risk_label, "informational")
    policy_ru = _POLICY_BADGE_RU.get(policy_decision, policy_decision)
    policy_color = {"block": "critical", "warn": "yellow", "pass": "success"}.get(
        policy_decision, "success"
    )

    lines = [
        f"## {emoji} Обзор безопасности Aegis",
        "",
        f"![Оценка риска]({_shield_badge('Оценка риска', str(risk_score), badge_color)})",
        f"![Решение политики]({_shield_badge('Решение политики', policy_ru, policy_color)})",
        "",
    ]

    if summary:
        lines += ["### Резюме", "", summary, ""]

    # Risk breakdown
    lines += ["### Распределение по серьёзности", ""]
    lines.append("| Серьёзность | Количество |")
    lines.append("|-------------|--------------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = risk_breakdown.get(sev, 0)
        if count > 0:
            sev_emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            sev_ru = _SEVERITY_RU.get(sev, sev)
            lines.append(f"| {sev_emoji} {sev_ru} | {count} |")
    lines.append("")

    # Findings
    if findings:
        lines += ["### Находки", ""]
        for i, finding in enumerate(findings[:20], 1):  # limit display
            sev = finding.get("severity", "info")
            sev_emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            sev_ru = _SEVERITY_RU.get(sev, sev.upper())
            file_path = finding.get("file_path", "")
            line_no = finding.get("line_number", "?")
            vuln_type = finding.get("vuln_type", "Неизвестно")
            cwe = finding.get("cwe", "")
            desc = finding.get("description", "")

            lines.append(f"#### {i}. {sev_emoji} [{sev_ru}] {vuln_type}")
            lines.append(f"- **Файл**: `{file_path}` (строка {line_no})")
            if cwe:
                lines.append(f"- **CWE**: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)")
            lines.append(f"- **Описание**: {desc}")

            # Check for autofix
            fix = next((s for s in autofix_suggestions if s.get("file") == file_path), None)
            if fix:
                lines.append("- **Доступно исправление** ✨")
                lines.append("```suggestion")
                lines.append(fix.get("fix", ""))
                lines.append("```")

            lines.append("")

        if len(findings) > 20:
            lines.append(f"_…и ещё {len(findings) - 20} находок. Полный список — в БД или через `@secbot findings`._")
            lines.append("")

    # Blast radius
    affected_count = blast_radius.get("affected_count", 0)
    if affected_count > 0:
        lines += [
            "### Зона влияния (blast radius)",
            "",
            f"**{affected_count} файлов** потенциально затронуты обнаруженными уязвимостями.",
            "",
        ]

    # Policy decision
    if policy_decision == "block":
        lines += [
            "---",
            "### ❌ Слияние PR заблокировано",
            "",
            "Этот PR нельзя слить, пока не устранены следующие проблемы:",
        ]
        for reason in policy_reasons[:5]:
            lines.append(f"- {reason}")
        lines.append("")
    elif policy_decision == "warn":
        lines += [
            "---",
            "### ⚠️ Предупреждения по PR",
            "",
            "Обнаружены следующие проблемы; слияние не блокируется:",
        ]
        for reason in policy_reasons[:5]:
            lines.append(f"- {reason}")
        lines.append("")

    # Footer
    lines += [
        "---",
        f"_ID скана: `{scan_id}` | Aegis DevSecOps | команды: `@secbot help`_",
    ]

    return "\n".join(lines)


def _render_inline_comments(findings: list[dict], autofix_suggestions: list[dict]) -> list[dict]:
    inline: list[dict] = []
    for finding in findings:
        sev = finding.get("severity", "")
        if sev not in ("critical", "high"):
            continue
        line_no = finding.get("line_number")
        if not line_no:
            continue

        file_path = finding.get("file_path", "")
        vuln_type = finding.get("vuln_type", "")
        desc = finding.get("description", "")
        cwe = finding.get("cwe", "")

        fix = next((s for s in autofix_suggestions if s.get("file") == file_path), None)

        body_parts = [
            f"🔐 **{vuln_type}**",
            f"> {desc}",
        ]
        if cwe:
            body_parts.append(f"**{cwe}**")
        if fix:
            body_parts.append(f"\n**Предлагаемое исправление:**\n```suggestion\n{fix.get('fix', '')}\n```")

        inline.append({
            "path": file_path,
            "line": line_no,
            "body": "\n".join(body_parts),
        })

    return inline


def _render_status_check(risk_label: str, risk_score: int, policy_decision: str) -> dict:
    if policy_decision == "block":
        state = "failure"
        description = f"Найдены проблемы безопасности (оценка риска: {risk_score}/100)"
    elif policy_decision == "warn":
        state = "pending"
        description = f"Есть предупреждения безопасности (оценка риска: {risk_score}/100)"
    else:
        state = "success"
        description = f"Критических проблем безопасности нет (оценка риска: {risk_score}/100)"

    return {
        "state": state,
        "description": description[:140],
        "context": "aegis/security-review",
    }
