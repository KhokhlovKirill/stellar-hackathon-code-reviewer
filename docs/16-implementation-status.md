# 16 — Статус реализации

Дата сверки: 2026-05-15.

## 1. Что уже реализовано в коде

| Блок | Статус | Файлы |
|---|---|---|
| FastAPI app + health/ready/metrics | Готов базовый runtime | `aegis/api/app.py`, `aegis/obs/*` |
| Webhook gateway | Реализован security-order: raw body, parse, signature verify, idempotency, enqueue | `aegis/api/webhooks.py` |
| Провайдеры VCS | Parse webhook + fetch PR/diff/file для GitHub/GitLab/Bitbucket; write-ops ещё Phase 6 | `aegis/providers/*` |
| Diff parser | Unified diff → FileChange/Hunk/DiffLine/new_lineno/diff_position | `aegis/providers/diffparse.py` |
| Repo vault | Репозитории, webhook/access secrets, Fernet vault | `aegis/repos.py`, `aegis/vault.py` |
| Очередь | Redis + Arq-compatible enqueue, stale-head guard | `aegis/queue.py`, `aegis/worker/main.py` |
| Pipeline runner | resolve → fetch PR → fetch diff-only → token analytics → optional stages | `aegis/pipeline/runner.py` |
| File filter | non-code/binary/generated/manifest routing, skipped reasons | `aegis/pipeline/filter.py` |
| Deterministic layer | secrets + entropy, Semgrep wrapper, OSV SCA | `aegis/pipeline/deterministic/*` |
| БД и миграции | repositories/secrets/policies/scans/findings/llm_calls/vcs_calls/dialog/feedback/audit | `aegis/db/models.py`, `alembic/versions/0001_initial.py` |
| Docker/compose | API, worker, Postgres, Redis, Prometheus | `deploy/*` |
| Тесты | Unit-gates для health, signatures, diff parsing, LLM parser/prompt | `tests/*` |

## 2. Что добавлено в этой итерации

- LLM client contract: `aegis/llm/base.py`.
- OpenAI-compatible transport for OpenRouter and LM Studio: `aegis/llm/openai_compat.py`.
- Tier router with health cache and fallback: `aegis/llm/router.py`.
- Strict JSON schema + parser with changed-line enforcement: `aegis/llm/parser.py`.
- Security review and judge prompts with anti-prompt-injection framing: `aegis/llm/prompt.py`.
- `llm_stage`: detector A/B → judge → persist `LLMCall`/`FindingRow`.
- Config/docs updated to the target stack:
  `OpenRouter`, local `Qwen 3.6 35B A3B 4-bit MLX`, and SFT+ORPO
  `Qwen3-Coder-30B-A3B` (`don-agent-v3`).

## 3. Production-gaps до финальной готовности

| Gap | Почему критично | Следующий шаг |
|---|---|---|
| Smart Context Window + Code RAG ещё не в коде | Без ±50/AST выше FP/FN на multi-file flows | Добавить `pipeline/context.py`, расширить `PipelineState.context_map` |
| Risk Score / policy / render ещё не реализованы | Без этого нет C4/C5/C8 e2e | Добавить `risk_score.py`, `render.py`, `policy.py` |
| VCS write-ops заглушки | Бот пока не постит inline и не блокирует merge | Реализовать GitHub first, затем GitLab/Bitbucket |
| ChatOps | C7 и FP-learning пока только в схеме БД/docs | Добавить `dialog/handler.py`, команды и suppression |
| Admin Portal | Нет UI/API для подключения репозитория и политики | Реализовать REST auth/repos/scans/settings |
| Eval harness | Uplift SFT+ORPO модели пока не доказан метриками | Собрать golden fixtures из mythos PrimeVul/CTF-Fixes + негативы |
| E2E compose gate | Unit-тесты есть, полного сценария PR ещё нет | Поднять локальный test repo/provider mocks и прогнать C1-C8 |

## 4. Проверка после итерации

Команды выполнены из `.venv`:

```bash
.venv/bin/ruff check .
.venv/bin/mypy aegis
.venv/bin/pytest -q
```

Результат: ruff чисто, mypy чисто по 45 source-файлам, pytest — 12 passed.

## 5. Использование mythos данных

`/Users/nikitasyzdykov/Desktop/Projects/mythos/SOLUTION.md` подтверждает, что
дообученная модель построена на security/CTF корпусе: PrimeVul, HackTricks, nuclei,
PayloadsAllTheThings, WSTG, ExploitDB, pwn-college и anti-refusal пары. Для Aegis эти
данные нужны не для нового обучения в рамках этого репозитория, а для:

- golden-set: vulnerable/fixed пары PrimeVul и CTF-Fixes → synthetic PR fixtures;
- few-shot: короткие diff→finding примеры для `eval/fewshot`;
- regression: негативные чистые PR и тестовые/fixture директории для FP-rate;
- RAG/KB позже: HackTricks/WSTG/Payloads as reference snippets для объяснений.
