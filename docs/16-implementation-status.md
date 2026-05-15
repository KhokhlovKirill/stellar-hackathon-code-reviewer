# 16 — Статус реализации

Дата сверки: 2026-05-15.

## 1. Готово в backend

| Блок | Статус | Файлы |
|---|---|---|
| FastAPI app | health/ready/metrics + webhook + admin REST API | `aegis/api/*` |
| Webhook gateway | raw body, content-type gate, parse, signature verify, idempotency, enqueue | `aegis/api/webhooks.py` |
| VCS providers | GitHub/GitLab/Bitbucket read/write: PR, diff, file, inline, summary, reply, status, request-changes | `aegis/providers/*` |
| Queue/worker | Redis + Arq enqueue, stale-head guard, scan/dialog entrypoints | `aegis/queue.py`, `aegis/worker/main.py` |
| Repo vault | access/webhook secrets encrypted by Fernet | `aegis/repos.py`, `aegis/vault.py` |
| Pipeline | filter → context → deterministic → LLM → suppression → risk → blast radius → render → policy | `aegis/pipeline/*` |
| Deterministic layer | regex/entropy secrets, Gitleaks, Semgrep, Bandit, OSV SCA | `aegis/pipeline/deterministic/*` |
| LLM layer | OpenRouter + LM Studio, fallback, JSON schema/parser, LM Studio `text` response_format compatibility | `aegis/llm/*` |
| ChatOps | `@secbot` explain / false positive / ignore / scan full command recognition, dialog persistence | `aegis/pipeline/dialog.py` |
| Admin backend API | login token, repo registration, scans, scan detail, stats | `aegis/api/admin.py`, `aegis/api/auth.py` |
| Eval | offline golden-set gate, CI-enforced | `eval/run.py`, `eval/golden/seed.jsonl` |
| Deployment | Docker includes Semgrep, Bandit, Gitleaks; compose has api/worker/postgres/redis/prometheus | `deploy/*` |

## 2. Проверка

Команды:

```bash
.venv/bin/ruff check .
.venv/bin/mypy aegis tests eval
.venv/bin/pytest -q
.venv/bin/pytest tests/test_lmstudio_live.py -v -s   # требует LM Studio
.venv/bin/python -m eval.run --gate
```

Текущий результат: ruff clean, pytest `51 passed`,
eval gate `precision=1.0`, `recall=1.0`, `line_accuracy=1.0`.

Верифицировано с реальным LM Studio API (2026-05-15):

- `GET http://localhost:1234/v1/models` видит `don-agent-v3`, `ctf-agent-sft-v3-fused`,
  `qwen3.6-35b-a3b-ud-mlx`, `qwen/qwen3-coder-30b` и ещё 5 моделей;
- `test_don_agent_security_analysis` — don-agent-v3 нашёл SQL injection (CWE-89,
  auth/login.py:12), hardcoded credentials (CWE-798, config/settings.py:1) и hardcoded
  JWT secret (CWE-798, auth/login.py:16) — 3/3, severity=high, confidence=high;
- обнаружено: don-agent-v3 возвращает нативную схему (`cwe: int`, `line_number`,
  `confidence: str`, `code_snippet`, `remediation`) — добавлен нормализатор
  `_normalise_finding()` в `aegis/llm/parser.py`, который прозрачно маппит в
  canonical Aegis Finding.

## 3. Реализовано в этой сессии (2026-05-15)

| Блок | Статус | Файлы |
|---|---|---|
| don-agent-v3 live test | Verified: SQL inj + secrets detected, 496 prompt tokens | `tests/test_lmstudio_live.py` |
| don-agent-v3 schema normaliser | Maps native fmt → Aegis canonical Finding | `aegis/llm/parser.py` |
| Autofix PR stage | secret→env + dep bump + open PR on all 3 providers | `aegis/pipeline/autofix.py` |
| VCS autofix methods | `create_branch`, `create_or_update_file`, `open_pull_request` | `aegis/providers/{github,gitlab,bitbucket}.py` |
| Grafana dashboards | Auto-provisioned: 14 panels (scans, findings, LLM cost, latency, fallbacks) | `deploy/grafana/` |
| docker-compose Grafana | Dashboard JSON volume + home dashboard env var | `deploy/docker-compose.yml` |

## 4. Остаётся до полного production-complete

| Gap | Следующий шаг |
|---|---|
| Full retro-scan | Добавить provider list-tree/full-file traversal с лимитами и отдельный `retro.scanner` |
| Comment dedup/update | Хранить и переиспользовать `comment_ref` между scan runs, resolve/update старые треды |
| PrimeVul/mythos golden-set | `eval/build_golden.py` из PrimeVul (vuln/fixed → PR-фикстуры) |
| Full e2e | Compose + тестовый GitHub/GitLab/Bitbucket PR flow с реальными API/mocks |

## 4. Использование mythos данных

`/Users/nikitasyzdykov/Desktop/Projects/mythos/SOLUTION.md` подтверждает, что
дообученная модель построена на security/CTF корпусе: PrimeVul, HackTricks, nuclei,
PayloadsAllTheThings, WSTG, ExploitDB, pwn-college и anti-refusal пары. Для Aegis эти
данные используются как источник:

- golden-set: vulnerable/fixed пары PrimeVul и CTF-Fixes → synthetic PR fixtures;
- few-shot: короткие diff→finding примеры для `eval/fewshot`;
- regression: негативные clean PR и test/fixture директории для FP-rate;
- RAG/KB позже: HackTricks/WSTG/Payloads reference snippets для объяснений.
