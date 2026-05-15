# 09 — Наблюдаемость и аналитика

Требование task.md: полное логирование поведения бота, что уходит в LLM, что в VCS API,
+ аналитика для прозрачной оценки корректности. Это также **доказательство критериев
C2/C3** на демо.

## 1. Структурное логирование

- `structlog` → JSON. Сквозной `scan_id` (correlation-id) во всех записях одного прогона;
  доп. `repo`, `pr`, `head_sha`, `provider`, `stage`.
- Логируем стадии: `webhook.received` (provider, event, delivery, sig_ok),
  `diff.fetched` (files, added_lines, removed_lines, diff_bytes, est_tokens,
  est_full_repo_tokens), `filter.applied` (kept[], skipped[] с причиной),
  `deterministic.done` (semgrep/secrets/sca findings), `llm.request`/`llm.response`
  (tier, model, prompt_tokens, completion_tokens, latency_ms, cost_usd, **тело
  редактируется**), `judge.done` (in/out findings, dropped_as_fp),
  `vcs.comment_posted` (path, line, finding_id), `policy.decision` (merge_block, reason),
  `scan.completed` (duration, totals).
- **Redaction:** секреты/токены/значения находок-секретов маскируются фильтром логгера
  до сериализации (никогда не пишем raw token/diff-секрет).

## 2. Метрики (Prometheus, `/metrics`)

- `aegis_scans_total{provider,result}`, `aegis_scan_duration_seconds` (histogram),
  `aegis_findings_total{severity,cwe,source}`, `aegis_llm_tokens_total{tier,kind}`,
  `aegis_llm_cost_usd_total{tier}`, `aegis_llm_latency_seconds{tier}`,
  `aegis_llm_tier_down{tier}`, `aegis_llm_fallback_total`,
  `aegis_vcs_calls_total{provider,op,code}`, `aegis_filter_skipped_total{reason}`,
  `aegis_tokens_saved_total` (est_full_repo − est_sent), `aegis_fp_feedback_total`,
  `aegis_queue_depth`, `aegis_dialog_turns_total`.

## 3. Аудит в БД

Таблицы: `scans`, `findings`, `llm_calls`, `vcs_calls`, `dialog_turns`,
`feedback` (реакция/ответ автора на комментарий бота → расчёт фактического FP-rate).
Полная трассируемость: по `scan_id` восстанавливается весь прогон, включая какие
hunks ушли в какую модель и что вернулось (с redaction).

## 4. Аналитический дашборд

Grafana (provisioned dashboards в `deploy/grafana/`) + страница Analytics в портале.
Ключевые панели — прямой ответ на критерии оценки:

- **«Ушло только diff»** (C2): средний/распределение `est_sent_tokens` vs
  `est_full_repo_tokens`, `tokens_saved_total`, % изменённых файлов от репо.
- **Детект** (C3): findings by severity/CWE/source (deterministic vs llm vs judge),
  recall/precision на golden-прогонах, FP-feedback rate.
- **Фильтрация** (C6): skipped-by-reason, доля не-кода.
- **Операционка:** latency p50/p95 по стадиям, LLM cost, tier-down/fallback, queue depth,
  ретраи/DLQ.

## 5. Трейсинг (опц., production-grade)

OpenTelemetry-спаны по стадиям (webhook→diff→deterministic→llm→judge→render→vcs),
экспорт в OTLP-коллектор; включается флагом конфига. По умолчанию off (хакатон), но код
инструментирован.
