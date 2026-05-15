# 03 — Архитектура

## 1. Сводка

Aegis — это асинхронный микросервис на Python (FastAPI + Arq-воркер), упакованный в
Docker. Он принимает webhook о PR/MR, нормализует событие, выкачивает **только diff**,
прогоняет его через многослойный конвейер детекта (детерминированный SAST/secret/SCA →
LLM-ансамбль → judge-арбитр), и публикует построчные комментарии + summary + решение по
блокировке merge обратно в VCS от имени сервисного аккаунта. Всё логируется в Postgres
и отдаётся в аналитику.

## 2. Компоненты

```
                         ┌────────────────────────────────────────────────────┐
   GitHub / GitLab /     │                    AEGIS                            │
   Bitbucket  ──webhook──▶│  ┌──────────────┐                                  │
                         │  │ Webhook       │  verify sig, dedupe, classify    │
                         │  │ Gateway       │──enqueue──┐                       │
                         │  │ (FastAPI)     │           │                       │
                         │  └──────────────┘           ▼                       │
                         │                       ┌───────────┐                  │
                         │                       │ Redis     │ queue + cache    │
                         │                       │ + idem    │ + idempotency    │
                         │                       └─────┬─────┘                  │
                         │                             │ dequeue                │
                         │  ┌──────────────────────────▼───────────────────┐   │
                         │  │              Worker (Arq)                     │   │
                         │  │  1. VCS Provider  ── fetch diff (changed only)│   │
                         │  │  2. File Filter   ── drop README/img/lock/...  │   │
                         │  │  3. Deterministic ── Semgrep + secrets + SCA   │   │
                         │  │  4. LLM Ensemble  ── don-agent-v3 + generalist │   │
                         │  │  5. Judge/Arbiter ── consolidate, anti-FP      │   │
                         │  │  6. Renderer      ── inline + summary + fix    │   │
                         │  │  7. Policy        ── merge block / status      │   │
                         │  └───────┬───────────────────────────┬───────────┘   │
                         │          │                           │               │
                         │   ┌──────▼──────┐            ┌────────▼────────┐      │
                         │   │ Postgres    │            │ LLM Router      │      │
                         │   │ scans/      │            │  ├ LM Studio    │──────┼──▶ host:1234
                         │   │ findings/   │            │  │  don-agent-v3│      │   (SFT+ORPO Qwen3-Coder /
                         │   │ llm_calls/  │            │  │  Qwen 35B    │      │    Qwen 3.6 35B 4bit)
                         │   │ vcs_calls/  │            │  └ OpenRouter   │──────┼──▶ openrouter.ai
                         │   │ dialog/     │            └─────────────────┘      │
                         │   │ tokens(enc) │                                     │
                         │   └─────────────┘                                     │
                         │  ┌──────────────┐   ┌──────────────────────────────┐ │
                         │  │ Admin Portal │   │ Observability                │ │
                         │  │ (FastAPI+UI) │   │ structured logs + Prometheus │ │
                         │  │ repo binding │   │ + analytics dashboard        │ │
                         │  └──────────────┘   └──────────────────────────────┘ │
                         └────────────────────────────────────────────────────┘
```

### 2.1 Webhook Gateway (`aegis/api`)
- FastAPI. Эндпоинты `POST /webhooks/{github|gitlab|bitbucket}`, `GET /healthz`,
  `GET /readyz`, `GET /metrics`, плюс роуты Admin Portal.
- На каждый запрос: верификация подписи (см. `04-vcs-integration.md`), проверка размера
  тела, классификация события (PR opened/synchronize/reopened; MR open/update; Bitbucket
  pullrequest:created/updated; а также события комментариев для диалога C7), проверка
  идемпотентности по delivery-id, постановка задачи в очередь, ответ `202` < 1s.
- Никакой тяжёлой работы синхронно — только enqueue.

### 2.2 Очередь и воркер (`aegis/worker`)
- **Arq + Redis** (asyncio-native, ретраи, отложенные задачи, хранение результата) —
  совпадает с асинхронной природой FastAPI + httpx + LLM I/O.
- Конкурентность ограничивается per-repo (не молотить один репо параллельными прогонами
  на серию пушей — берём последний коммит, отменяем устаревшие).
- Ретраи с экспоненциальным backoff; dead-letter после N попыток; идемпотентность по
  (repo, pr, head_sha) — повторный webhook на тот же коммит не дублирует комментарии.

### 2.3 VCS Provider Abstraction (`aegis/providers`)
- `base.py` — протокол `VCSProvider`; реализации `github.py`, `gitlab.py`,
  `bitbucket.py`. Нормализованные модели: `PullRequest`, `FileChange`, `Hunk`,
  `DiffLine`, `Finding`, `ReviewComment`, `MergePolicyDecision`.
- Методы: `fetch_pull_request`, `fetch_diff`, `list_changed_files`,
  `post_inline_comment`, `post_summary`, `reply_in_thread`, `set_status_check` /
  `create_check_run`, `request_changes`, `get_thread`. Детали — `04-vcs-integration.md`.

### 2.4 File Filter (`aegis/pipeline/filter.py`)
- Отбрасывает по path/ext/glob: `*.md`, `.gitignore`, `LICENSE`, картинки/бинарь,
  локфайлы (анализируются отдельно через SCA, но не уходят в LLM как код), `node_modules`,
  vendored/generated, минифицированное, > N строк. Поддержка `.aegisignore` в репо.
- Определяет язык файла → выбирает language-aware правила и промпт-профиль.
- Список отфильтрованного попадает в summary (критерий C6) и в лог.

### 2.5 Deterministic Pre-Analysis (`aegis/pipeline/deterministic`)
- **Secrets:** gitleaks-стиль regex + entropy (detect-secrets-стиль) **только по
  добавленным строкам** → захардкоженные пароли/токены/ключи, `.env` с секретами.
- **SAST:** Semgrep OSS, рулсеты `p/owasp-top-ten`, `p/security-audit`, `p/secrets`,
  language-packs; результаты маппятся **только на изменённые строки**. Даёт SQLi / XSS /
  command-injection / path-traversal / SSRF / deserialization с низким FP.
- **SCA / supply-chain:** парс diff манифестов (`requirements.txt`, `pyproject.toml`,
  `package.json`, `go.mod`, `pom.xml`) → запрос OSV.dev + GitHub Advisory + deps.dev:
  известные CVE, отозванные/yanked версии, malware-advisories, typosquatting, свежо
  опубликованные рискованные пакеты → предложение замены по контексту.
- Эти находки — **факты** с confidence≈1: идут (а) напрямую в результат, (б) как
  grounded-контекст в промпт LLM (снижает галлюцинации и FP).

### 2.6 LLM Ensemble + Judge (`aegis/pipeline/llm`, `aegis/llm`)
- Подробно — `05-analysis-engine.md` и `06-model-strategy.md`. Кратко:
  - Детектор A: **don-agent-v3** (дообученная security-модель) через LM Studio.
  - Детектор B: генералист (OpenRouter strong-модель или локальный Qwen 3.6 35B A3B 4-bit MLX).
  - **Judge:** третий вызов (cloud strong) консолидирует, дедуплицирует, **режет FP**
    (требует точную изменённую строку + конкретный сценарий эксплуатации + CWE),
    выставляет severity/confidence, формирует fix-сниппет.
  - Self-consistency: финально остаются находки, подтверждённые ≥2 сигналами ИЛИ
    детерминированным слоем ИЛИ judge-high-confidence.

### 2.7 Renderer + Policy (`aegis/pipeline/render.py`, `policy.py`)
- Маппинг находки → файл + изменённая строка + position в diff.
- Inline-комментарий: severity-бейдж, CWE, абзац «почему эксплуатируемо здесь»,
  offending-сниппет, **suggestion-блок** (one-click apply).
- Summary-комментарий: таблица по severity, scanned/skipped файлы, использованные модели,
  scan-id, ссылка на аналитику, приглашение «ответь мне в треде».
- Policy: при Critical (политика на репо) → request-changes + падающий required-check
  → merge заблокирован до override тимлидом (C8).

### 2.8 Conversational Follow-up (`aegis/pipeline/dialog.py`)
- Webhook на reply/comment с упоминанием бота → достаём контекст треда (исходная находка
  + код + история) → LLM с тем же grounding → ответ in-thread. Состояние треда в БД.
  Guard: max turns, отвечаем только на @mention/direct-reply, игнорируем других ботов.

### 2.9 Admin Portal (`aegis/admin`)
- FastAPI + лёгкий UI: регистрация репо, провайдер, токен/GitHub App, webhook-secret,
  политика (severity-порог, merge-block, ignored paths, model-profile, prompt-overrides),
  просмотр сканов/находок/аналитики. Токены — в шифрованном vault.

### 2.10 Observability (`aegis/obs`)
- Структурный JSON-лог (correlation-id = scan-id) на каждой стадии; Prometheus-метрики;
  аудит-таблицы; аналитический дашборд (включая панель «ушло только diff vs весь репо»).
  Детали — `09-observability.md`.

## 3. Поток данных (happy path)

```
PR opened ─▶ Gateway: verify+classify+dedupe ─▶ enqueue(scan_id)
   ─▶ Worker: provider.fetch_diff (changed files+hunks only)
   ─▶ Filter: drop non-code; keep code hunks; record skipped
   ─▶ Deterministic: Semgrep + secrets + SCA  → findings_det[]
   ─▶ Build grounded prompt (hunks + narrow context + findings_det)
   ─▶ LLM A (don-agent-v3) ‖ LLM B (generalist)  → findings_a[], findings_b[]
   ─▶ Judge (cloud): merge(findings_det, a, b) → consolidate, anti-FP, severity, fix
   ─▶ Renderer: map to lines → inline comments + summary
   ─▶ provider.post_inline_comment[] + post_summary
   ─▶ Policy: if Critical → request_changes + failing required check
   ─▶ Persist scan + findings + llm_calls + vcs_calls; emit metrics
   ─▶ (optional) provider notifies author; author replies → dialog flow
```

## 4. Модель отказоустойчивости (деградация, а не падение)

| Сбой | Поведение |
|---|---|
| `/Volumes/SSD` не примонтирован → нет don-agent-v3 | Тир `local-secure` помечается down; ансамбль = генералист + judge через OpenRouter; в summary помечается «специализированная модель недоступна» |
| LM Studio не поднят (:1234 не отвечает) | Оба локальных тира down → fallback полностью на OpenRouter; метрика `llm_fallback_total` |
| OpenRouter недоступен | Если локальные тиры живы — работаем на них; если нет LLM вовсе — публикуем **детерминированные** находки (Semgrep/secrets/SCA) + честное «LLM-анализ недоступен, выполнен только статический» → P1-критерии всё равно закрыты |
| VCS API rate-limit / 5xx | Ретраи с backoff; при исчерпании — статус-чек `neutral` + лог, без потери задачи |
| Слишком большой PR | Map-reduce по hunks, лимиты, приоритет по риску файлов; не падаем |
| Prompt-injection в diff | Контент трактуется как данные, output — schema-constrained; см. `10-security-and-secrets.md` |

## 5. Технологический стек

- Python 3.12+ (целевой рантайм контейнера; на хосте — 3.14), FastAPI, Uvicorn, Arq,
  Redis, PostgreSQL, SQLAlchemy 2.x + Alembic, httpx, pydantic v2, `unidiff`,
  Semgrep (CLI в образе), `detect-secrets`/gitleaks-pattern-set, structlog,
  prometheus-client, cryptography (Fernet) для vault, pytest + respx (мок VCS/LLM).
- Деплой: multi-stage Docker, docker-compose (api, worker, postgres, redis,
  опц. prometheus+grafana). LM Studio — на хосте Apple Silicon, воркер ходит на
  `host.docker.internal:1234`. Детали — `11-deployment.md`.

## 6. Каркас репозитория

```
code-review/
├── docs/                      ← этот пакет документации
├── aegis/
│   ├── api/                   webhook gateway + admin routes
│   ├── worker/                arq worker + tasks
│   ├── providers/             github / gitlab / bitbucket + base
│   ├── pipeline/
│   │   ├── filter.py
│   │   ├── deterministic/     semgrep / secrets / sca
│   │   ├── llm/               ensemble + judge orchestration
│   │   ├── render.py  policy.py  dialog.py
│   ├── llm/                   router + openrouter + lmstudio clients
│   ├── admin/                 control plane + token vault
│   ├── obs/                   logging, metrics, analytics
│   ├── db/                    models, migrations
│   ├── config.py  schemas.py  errors.py
├── eval/                      golden-set, harness, scoring vs criteria
├── fixtures/                  vulnerable/clean PR fixtures (из PrimeVul и т.д.)
├── deploy/                    Dockerfile(s), compose, prometheus, grafana
├── tests/                     unit + integration
├── config.example.yaml  .env.example  Makefile  pyproject.toml
└── task.md
```
