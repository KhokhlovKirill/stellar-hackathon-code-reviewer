"""Shared localization for findings and rendered PR comments.

Two concerns:

1. Deterministic findings carry fixed English template text. When the
   configured comment language is Russian we translate the stable fragments
   in place; dynamic parts (names, masked values, paths) are preserved.
   LLM findings are localized by the model itself.

2. Posted PR review comments (`render.py`) have static section labels
   ("Suggested fix", "Risk Score", …) — `t(key, lang)` returns the label in
   the configured language.

Used by both the pull-mode scanner (`simple_scan`) and the webhook pipeline
(`render`), so there is one source of truth for output language.
"""

from __future__ import annotations

from aegis.schemas import Finding, FindingSource

# ── Deterministic finding template fragments (en → ru) ─────────────────────────
_DET_PHRASES_RU: list[tuple[str, str]] = [
    ("appears on an added line", "обнаружен в добавленной строке"),
    ("in a secrets-bearing file", "в файле с секретами"),
    ("Masked value:", "Маскированное значение:"),
    (
        "Committed credentials are retrievable from history even if later removed.",
        "Закоммиченные учётные данные извлекаемы из истории git даже после удаления.",
    ),
    (
        "Anyone with repo/history access obtains the live credential.",
        "Любой, у кого есть доступ к репозиторию или его истории, получает "
        "действующие учётные данные.",
    ),
    (
        "Remove the literal; load from env/secret manager and rotate the "
        "exposed credential immediately.",
        "Удалите литерал из кода, загружайте значение из переменных окружения "
        "или менеджера секретов и немедленно ротируйте скомпрометированные данные.",
    ),
    (
        "High-entropy token on an added line",
        "Высокоэнтропийный токен в добавленной строке",
    ),
    (
        "likely a key/token committed to source.",
        "вероятно, ключ или токен, попавший в исходный код.",
    ),
    (
        "If this is a live secret, it is exposed in history.",
        "Если это действующий секрет, он раскрыт в истории репозитория.",
    ),
    (
        "Move to a secret store; rotate if real.",
        "Перенесите значение в хранилище секретов; ротируйте, если секрет реальный.",
    ),
]


def localize_text(text: str | None, lang: str) -> str | None:
    if not text or lang != "ru":
        return text
    out = text
    for en, ru in _DET_PHRASES_RU:
        out = out.replace(en, ru)
    return out


def localize_findings_inplace(findings: list[Finding], lang: str) -> None:
    """Translate fixed-template (deterministic) finding text into `lang`.

    Only touches deterministic-source findings; LLM findings are localized by
    the model. No-op for English. Idempotent.
    """
    if lang != "ru":
        return
    for f in findings:
        if f.source != FindingSource.DETERMINISTIC:
            continue
        f.rationale = localize_text(f.rationale, lang) or f.rationale
        f.exploit = localize_text(f.exploit, lang)
        f.fix = localize_text(f.fix, lang)


# ── Static UI labels for rendered PR comments ─────────────────────────────────
_LABELS: dict[str, dict[str, str]] = {
    "finding_header": {
        "en": "Aegis security finding",
        "ru": "Находка безопасности Aegis",
    },
    "cwe": {"en": "CWE", "ru": "CWE"},
    "confidence": {"en": "Confidence", "ru": "Уверенность"},
    "exploit_scenario": {"en": "Exploit scenario", "ru": "Сценарий эксплуатации"},
    "suggested_fix": {"en": "Suggested fix", "ru": "Рекомендуемое исправление"},
    "fingerprint": {"en": "Finding fingerprint", "ru": "Отпечаток находки"},
    "review_title": {
        "en": "Aegis security review",
        "ru": "Обзор безопасности Aegis",
    },
    "risk_score": {"en": "Risk Score", "ru": "Оценка риска"},
    "scan_id": {"en": "Scan ID", "ru": "ID сканирования"},
    "head_sha": {"en": "Head SHA", "ru": "Head SHA"},
    "severity": {"en": "Severity", "ru": "Серьёзность"},
    "count": {"en": "Count", "ru": "Количество"},
    "scanned_files": {"en": "Scanned files", "ru": "Просканированные файлы"},
    "skipped_files": {"en": "Skipped files", "ru": "Пропущенные файлы"},
    "risk_breakdown": {"en": "Risk breakdown", "ru": "Разбивка риска"},
    "blast_radius": {"en": "Blast Radius", "ru": "Радиус поражения"},
    "recurring_patterns": {
        "en": "Recurring patterns (Security KB)",
        "ru": "Повторяющиеся паттерны (база знаний)",
    },
    "degraded_components": {
        "en": "Degraded components",
        "ru": "Деградировавшие компоненты",
    },
    "none": {"en": "none", "ru": "нет"},
    "similar_to": {
        "en": "similar to confirmed",
        "ru": "похоже на подтверждённую",
    },
    "in_pr": {"en": "in PR", "ru": "в PR"},
    "suppressed_by_feedback": {
        "en": "Suppressed by team feedback",
        "ru": "Подавлено отзывом команды",
    },
    "no_findings": {
        "en": "No confirmed security findings on changed code lines.",
        "ru": "Подтверждённых проблем безопасности в изменённых строках не найдено.",
    },
    "reply_hint": {
        "en": "Reply to an Aegis thread with `@secbot why` for details.",
        "ru": "Ответьте в ветке Aegis командой `@secbot why` для подробностей.",
    },
}


def t(key: str, lang: str) -> str:
    """Return the localized static label for `key` (falls back to English)."""
    entry = _LABELS.get(key)
    if entry is None:
        return key
    return entry.get(lang) or entry["en"]
