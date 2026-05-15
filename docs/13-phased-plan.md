# 13 — Поэтапный план (с галочками)

Точка входа для реализации. Каждая фаза имеет **acceptance-гейт** — не переходим
дальше, пока гейт не зелёный. Принцип: этап делается на полную глубину, без MVP-срезов.
Маппинг на критерии оценки — в скобках (C1..C8, см. `01`).

Легенда: `[ ]` не начато · `[~]` в работе · `[x]` готово и проверено.

---

## Фаза 0 — Каркас и инфраструктура

- [x] Документация архитектуры и плана (`docs/`)
- [x] `pyproject.toml`, зависимости, ruff/mypy/pytest, `Makefile`
- [x] Структура пакета `aegis/` (`03 §6`), `config.py` (pydantic-settings, fail-fast),
      `schemas.py` (pydantic-модели: PullRequest/FileChange/Hunk/DiffLine/Finding/…),
      `errors.py`
- [x] `db/` модели + Alembic, базовые таблицы (`scans`, `findings`, `llm_calls`,
      `vcs_calls`, `repositories`, `repo_secrets`, `repo_policies`, `dialog_turns`,
      `feedback`, `admin_audit`)
- [x] `obs/` structlog (JSON, scan_id-correlation) + redaction-фильтр + Prometheus-реестр
- [x] `deploy/`: multi-stage Dockerfile, docker-compose (api, worker, postgres, redis),
      `.env.example`, `config.example.yaml`
- [x] CI-скелет: ruff + mypy + pytest + semgrep/pip-audit на свой код

**Гейт 0:** `docker compose up` поднимает api+worker+pg+redis; `/healthz` зелёный;
миграции применяются; пустой pytest проходит; лог в JSON со scan_id.
> Статус: каркас собран, `python3 -m compileall aegis alembic` — чисто; health/metrics/
> redaction покрыты `tests/test_scaffold.py`. Полный e2e-гейт (compose up на чистой
> машине) проверяется в Фазе 11.

---

## Фаза 1 — Webhook gateway + дифф (C1, C2)

- [ ] FastAPI `api/`: `POST /webhooks/{github,gitlab,bitbucket}`, `/healthz`,
      `/readyz`, `/metrics`
- [ ] Верификация подписи: GitHub HMAC-256, GitLab token, Bitbucket secret/HMAC —
      по сырому телу, constant-time, fail-closed (C1)
- [ ] Классификация события (PR opened/synchronize/reopened; MR open/update/reopen;
      Bitbucket created/updated; comment-события — задел под C7)
- [ ] Идемпотентность: Redis по delivery-id + (repo,pr,head_sha), TTL 24ч
- [ ] Постановка в очередь (Arq), ответ `202` < 1s; worker-task `run_scan(scan_id)`
- [ ] `providers/base.py` + `github.py`/`gitlab.py`/`bitbucket.py`: `fetch_diff`
      (только изменённые файлы/hunks), парсинг unified diff (`unidiff`) →
      new_lineno + diff_position (C2)
- [ ] Учёт в аналитике: added/removed lines, diff_bytes, est_tokens,
      est_full_repo_tokens, tokens_saved (C2)

**Гейт 1:** реальный/записанный webhook трёх провайдеров принят и верифицирован; битая
подпись → 401; replay не порождает второй scan; diff выкачан **только по изменённым
файлам**; в БД/метриках видно «sent vs full-repo».

---

## Фаза 2 — Фильтрация файлов (C6)

- [ ] `pipeline/filter.py`: path/ext/glob (README/*.md, .gitignore, LICENSE,
      картинки/бинарь, локфайлы, vendored/generated, minified, size-cap),
      `.aegisignore`
- [ ] Детект языка → выбор правил/промпт-профиля
- [ ] Запись kept/skipped(+reason) в лог, scan-record и summary

**Гейт 2:** README.md/.gitignore/*.png не уходят в анализ, попадают в skipped с причиной;
код-файлы проходят; список отфильтрованного виден в summary и логе.

---

## Фаза 3 — Детерминированный слой (C3, supply-chain)

- [ ] Secrets: gitleaks-набор + энтропия, только по `+`-строкам, маскирование
- [ ] Semgrep-обвязка: рулсеты в образе, запуск по изменённым файлам, фильтр находок
      на пересечение с изменёнными строками, маппинг → CWE/severity/line
- [ ] SCA: парс diff манифестов/локфайлов → OSV.dev + GHSA + deps.dev; CVE/yanked/
      malware/typosquat; предложение замены по контексту импортов
- [ ] Нормализация → `Finding(source=deterministic, confidence≈0.98)`; передача как
      grounded-фактов в промпт LLM

**Гейт 3:** на golden-фикстурах SQLi/secret/XSS/bad-dep детектятся детерминированно с
правильным CWE/строкой; FP на чистых фикстурах ≈ 0; работает без LLM.

---

## Фаза 4 — LLM-роутер и тиры (`06`)

- [~] `llm/base.py` единый `complete(messages, schema, budget)` + usage/cost/redaction
- [~] `llm/openai_compat.py` + `llm/router.py` (`local-secure`=SFT+ORPO
      Qwen3-Coder-30B-A3B, `local-base`=Qwen 3.6 35B A3B 4-bit MLX),
      health-probe `/v1/models` (TTL 30s)
- [~] OpenRouter generalist/judge слоты через OpenAI-compatible client, ретраи, бюджеты
- [~] `llm/router.py`: профиль ансамбля, авто-fallback при недоступном тире,
      метрики tier-down/fallback
- [~] Override-промпт для дообученной модели (CTF→JSON) + parser + schema-валидация

**Гейт 4:** при поднятом LM Studio оба локальных тира отвечают; при недоступном — авто-
fallback на cloud без падения; don-agent-v3 стабильно отдаёт валидный JSON находок;
полный отказ LLM → пайплайн продолжает на детерминированном слое.

---

## Фаза 5 — Движок анализа: ансамбль + judge + анти-FP (C3, C4)

- [ ] Построение grounded-промпта: hunks + узкий контекст + det-findings + few-shot
      (вкл. negative), anti-injection маркеры (`05 §4,§5`)
- [ ] Параллельные детекторы A (don) + B (generalist)
- [ ] Judge-арбитр: дедуп, анти-FP rubric, self-consistency, severity/confidence, fix
- [ ] Гейтинг публикации + дедуп против ранее оставленных комментариев (fingerprint)
- [ ] Кэш по `sha1(repo+head_sha+file+hunk)`; map-reduce для больших PR; бюджеты

**Гейт 5:** на golden-set per-class recall ≥0.90 / precision ≥0.85 по SQLi/secret/XSS;
FP-rate на негативах ниже baseline; деградированный (без LLM) recall ≥0.80 по этим
классам; находки привязаны к верной изменённой строке.

---

## Фаза 6 — Рендер, комментарии, политика merge (C4, C5, C8)

- [ ] `render.py`: inline-комментарий (severity-бейдж, CWE, «почему эксплуатируемо
      здесь», offending-сниппет) с привязкой к строке/position на каждом провайдере (C4)
- [ ] Suggestion-блоки (one-click apply) + fallback unified-diff патч (C5)
- [ ] Summary-комментарий: таблица по severity, scanned/skipped, модели, scan-id,
      ссылка в аналитику, приглашение к диалогу
- [ ] `policy.py`: при Critical (политика репо) → request-changes + падающий required
      status-check; override — только тимлид (C8)
- [ ] Идемпотентный постинг при `synchronize` (обновить/резолвить, не дублировать)

**Гейт 6:** на тестовом репо бот оставляет построчные комментарии с сутью и сниппетом;
suggestion применяется одним кликом и снимает находку; Critical блокирует merge до
ручного override; повторный push не плодит дубли.

---

## Фаза 7 — Диалог в треде (C7)

- [ ] Webhook comment-событий → фильтр (@mention/прямой reply, игнор ботов/себя)
- [ ] Контекст треда из БД (исходная находка + код + история) → LLM → reply in-thread
- [ ] Состояние треда, guard: max turns, rate-limit, anti-loop

**Гейт 7:** автор отвечает на комментарий бота — бот отвечает по существу в том же треде
с учётом находки и истории; не зацикливается, не отвечает другим ботам.

---

## Фаза 8 — Admin Portal + token vault (`08`)

- [ ] Регистрация репо (провайдер, токен/GitHub App, webhook-secret), Test-connection
- [ ] Token vault (Fernet/AES-GCM, ключ из env/KMS), ротация, redaction
- [ ] Политика per-repo (severity-gate, merge-block, ignore-globs, ensemble-profile,
      prompt-overrides, lang, budgets), `admin_audit`
- [ ] Страницы: Repos, Repo Detail, Scans, Scan Detail, Analytics, Audit; auth+CSRF

**Гейт 8:** админ привязывает репо через портал, Test-connection валидирует scope;
токены только в шифртексте, нет в логах; политика применяется к прогонам.

---

## Фаза 9 — Наблюдаемость и аналитика (`09`)

- [ ] Все стадии логируются (scan_id), Prometheus-метрики полностью
- [ ] Grafana provisioned-дашборды (`deploy/grafana/`): «diff-only» (C2), детект (C3),
      фильтрация (C6), операционка
- [ ] Аудит-таблицы заполняются; страница Analytics в портале
- [ ] (опц.) OpenTelemetry-спаны за флагом

**Гейт 9:** на дашборде видно «ушло только diff vs full-repo», детект по severity/CWE,
FP-rate, latency/cost/fallback; по scan_id восстановим весь прогон.

---

## Фаза 10 — Eval-харнесс и регрессия (`12`, `07`)

- [ ] `eval/build_golden.py` из PrimeVul (vuln/fixed → PR-фикстуры) + ручные + не-код +
      чистые (анти-FP ≥40%), в payload 3 провайдеров
- [ ] `eval/run.py`: метрики per-class P/R/F1, FP-rate, line-acc, fix-validity,
      latency/cost; `eval/results/<ts>.json` + markdown + графики
- [ ] `eval/score_criteria.py`: маппинг на C1..C8 с весами, ожидаемый балл из 96
- [ ] Сравнение ensemble-профилей (uplift don-agent-v3) → ADR-7 решён цифрами
- [ ] CI регресс-гейт против `eval/baseline.json`
- [ ] Нагрузочный скрипт (шторм webhook, дубли, деградация, grep-логов-на-секреты)

**Гейт 10:** харнесс воспроизводим из репозитория; цифры в `eval/results/`; профиль по
умолчанию выбран по данным и зафиксирован ADR; регресс-гейт активен в CI.

---

## Фаза 11 — Hardening и приёмка

- [ ] Модель угроз (`10`) реализована: anti-injection, allowlist исходящих, non-root
      контейнеры, redaction-тест зелёный
- [ ] e2e на локальном тестовом репо по всем C1..C8 (`12 §3`)
- [ ] `pip-audit`/`osv-scanner`/Semgrep на собственный код — чисто; SBOM на сборке
- [ ] Документация эксплуатации (`11`) и операторский ран-бук выверены на чистой машине
- [ ] Граничные случаи: rename, binary, empty diff, huge diff, force-push, deleted file,
      LLM down, SSD down, OpenRouter down — все проходят без падения

**Гейт 11 (финальная приёмка):** на чистой машине `docker compose up` + операторская
настройка LM Studio → реальный PR трёх провайдеров проходит весь цикл; все C1..C8 на
3/3 подтверждены e2e и на golden-set; деградационные сценарии не валят сервис; секретов
в логах нет; eval-цифры опубликованы.

---

## Сводный трекер по критериям

| Критерий | w | Фазы | Статус |
|---|---|---|---|
| C1 webhook | 6 | 1 | [ ] |
| C2 diff-only → LLM | 6 | 1,5 | [ ] |
| C3 детект SQLi/secret/XSS | 6 | 3,5,10 | [ ] |
| C4 inline-комментарий с сутью | 6 | 5,6 | [ ] |
| C5 fix-сниппет | 3 | 6 | [ ] |
| C6 фильтрация не-кода | 3 | 2 | [ ] |
| C7 диалог | 1 | 7 | [ ] |
| C8 блокировка merge | 1 | 6 | [ ] |
| Доп: supply-chain / аналитика / uplift | — | 3,9,10 | [ ] |
