# Aegis — Статус проекта

> Обновлено: 2026-05-16 (сессия 7)

---

## Что это

AI-система code review с акцентом на безопасность. Принимает PR от GitHub
(вебхук или ручная ссылка), прогоняет diff через детерминистические анализаторы
и LLM-ансамбль, затем оставляет комментарии/summary прямо в PR.

---

## Новая структура проекта

Проект разделён на две явные зоны:

```text
code-review/
├── backend/                         # Python/FastAPI/worker/pipeline/deploy/tests
│   ├── aegis/                       # основной backend-пакет
│   │   ├── api/                     # FastAPI app, REST API, webhooks
│   │   ├── web/                     # backend routes для server-rendered control plane
│   │   ├── pipeline/                # PR analysis pipeline
│   │   ├── llm/                     # OpenRouter + LM Studio clients/router/parser/cache
│   │   ├── providers/               # GitHub/GitLab/Bitbucket adapters
│   │   ├── db/                      # SQLAlchemy ORM/session
│   │   ├── kb/                      # Security Knowledge Base
│   │   ├── obs/                     # logging + Prometheus metrics
│   │   └── worker/                  # ARQ worker
│   ├── alembic/                     # DB migrations
│   ├── deploy/                      # Dockerfile, docker-compose, Prometheus, Grafana
│   ├── eval/                        # golden-set/eval harness
│   ├── tests/                       # pytest
│   ├── pyproject.toml
│   ├── Makefile
│   ├── config.example.yaml
│   └── .env.example
│
├── frontend/                        # React UI + legacy templates + VS Code extension
│   ├── src/                         # React/Vite production UI
│   ├── templates/                   # legacy Jinja2 templates
│   └── vscode-extension/            # VS Code extension
│
├── Makefile                         # root wrapper для backend/docker команд
├── STATUS.md
├── SPECIFICATION.md
├── docs/
├── AdditionalData/
├── task.md
├── start_tunnel.sh
└── .env                             # локальные секреты, не коммитить
```

Production UI теперь React/Vite из ветки `origin/frontend`, обслуживается nginx
контейнером `web` на `localhost:8099` и проксирует `/api/*` в backend. Legacy
Jinja2 routes/templates сохранены для совместимости и smoke/debug сценариев.
Backend читает legacy template path из `AEGIS_FRONTEND_TEMPLATES`.

Локально default: `../frontend/templates` относительно `backend/`.
В Docker default: `/app/frontend/templates`.

---

## Важные команды после разделения

Из root:

```bash
cd /Users/nikitasyzdykov/Desktop/code-review

make backend-check
make backend-test
make docker-build
make docker-up
make docker-logs
```

Из backend:

```bash
cd /Users/nikitasyzdykov/Desktop/code-review/backend

../.venv/bin/ruff check .
../.venv/bin/mypy aegis tests eval
../.venv/bin/pytest -q
../.venv/bin/python -m eval.run --gate

docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f api worker web
```

Root `.venv` пока сохранён. `backend/Makefile` использует `../.venv` по умолчанию.

---

## Docker

Compose-файл теперь:

```bash
backend/deploy/docker-compose.yml
```

Сборка из root:

```bash
docker compose -f backend/deploy/docker-compose.yml build
```

Сборка из `backend/`:

```bash
docker compose -f deploy/docker-compose.yml build
```

Compose использует build context root (`../..`). Backend image получает
`backend/` и legacy `frontend/templates`; отдельный `web` image собирает React UI
из `frontend/src` и отдаёт его через nginx.

- `backend/aegis`
- `backend/alembic`
- `backend/alembic.ini`
- `backend/config.example.yaml`
- `frontend/templates`
- `frontend/src` → `web` container build

В Docker env:

```text
AEGIS_DATABASE_URL=postgresql+asyncpg://aegis:aegis@postgres:5432/aegis
AEGIS_REDIS_URL=redis://redis:6379/0
AEGIS_FRONTEND_TEMPLATES=/app/frontend/templates
LMSTUDIO_BASE_URL=http://host.docker.internal:1234/v1
```

---

## Текущее состояние проверок

После разделения каталогов:

```text
ruff: зелёный
mypy: зелёный, 87 source files
pytest: 74 passed
frontend React build: зелёный
VS Code extension build/package: зелёный
eval gate: precision=1.0, recall=1.0, line_accuracy=1.0, tp=11
```

Docker build/up проверены:

```bash
docker compose -f backend/deploy/docker-compose.yml build api worker web
docker compose -f backend/deploy/docker-compose.yml up -d api worker web
curl http://localhost:8080/readyz
curl http://localhost:8099/
```

---

## LLM-тиры и маршрутизация

Текущий режим по `STATUS.md` предыдущего состояния:

```text
LMSTUDIO_SWAP_MODELS=false

role=detector_a  → cloud-generalist (DeepSeek V4 Flash free) → cloud-mimo → local-secure
role=detector_b  → cloud-mimo (MiMo-V2-Flash) → cloud-generalist → local-secure
role=judge       → cloud-judge (Qwen3 Coder free) → cloud-generalist → local-secure
```

Основные модели:

| Тир | Модель | Источник | Статус |
|---|---|---|---|
| `cloud-generalist` | `deepseek/deepseek-v4-flash:free` | OpenRouter | работает |
| `cloud-judge` | `qwen/qwen3-coder:free` | OpenRouter | возможен 429 |
| `cloud-mimo` | `xiaomi/mimo-v2-flash` | OpenRouter | работает |
| `local-secure` | `don-agent-v3` | LM Studio `:1234` | fallback |
| `local-generalist` | `qwen3.6-35b-a3b-ud-mlx` | LM Studio `:1234` | swap/local mode |

Для pull-mode scan из VS Code/API `don-agent-v3` больше не является только fallback:
OpenRouter detector и локальный Don запускаются параллельно, Don вызывается принудительно
как `local-secure`. Если Don недоступен, scan помечается degraded (`local-secure`).
Локальные LM Studio tiers больше не берутся из Redis cache: обязательный Don-запуск
идёт live, а findings от Don сохраняют source `llm_a` и отображаются в UI.

---

## Публичный доступ

```text
GitHub webhook  →  http://87.242.94.247:8099
                         ↓ nginx proxy
                   VPS 127.0.0.1:18099
                         ↓ SSH reverse tunnel
                   Mac localhost:8080  ←  uvicorn Aegis
```

Tunnel:

```bash
nohup bash start_tunnel.sh > /tmp/aegis_tunnel.log 2>&1 &
```

---

## Что работает

| Функция | Статус |
|---|---|
| Web UI routes + Jinja templates from `frontend/templates` | работает |
| React/Vite UI на `localhost:8099` | работает |
| REST API `/api/...` | работает |
| GitHub/GitLab/Bitbucket webhook gateway | работает |
| Quick Connect GitHub repo + webhook registration | работает |
| Pull-mode scan `/review` | работает |
| Deterministic scan: secrets/entropy/Semgrep/Gitleaks/Bandit/SCA wrappers | работает |
| LLM router: OpenRouter + LM Studio fallback/swap | работает |
| VS Code scan PR / scan URL / scan branch persistence | работает |
| Pull-mode OpenRouter + mandatory Don ensemble | работает |
| Agent review summary в VS Code и web | работает |
| Summary language ru/en из настроек VS Code | работает |
| 1-5-word finding labels от coordinator LLM | работает |
| Whole-PR Ask/Explain/Fix chat context | работает |
| VS Code Apply Patch (sanitize + recount + path-resolve + multi-strategy) | работает |
| Apply Patch recovery: Open scanned folder / Save / Copy при `target not in workspace` | работает |
| Web chat = extension (SSE `/api/ext/chat/stream`, structured finding/scan) | работает |
| Web finding/scan Ask/Explain/Fix + diff Copy/Download | работает |
| Web Settings page + ru/en language switch (i18n, lang threaded в API) | работает |
| ARQ worker queue | работает |
| Redis LLM cache | работает |
| Security Knowledge Base | работает |
| Autofix PR stage | реализован |
| Prometheus metrics + Grafana provisioning | реализовано |

---

## Известные замечания

- `.env` остаётся в root и не коммитится.
- `backend/eval/golden/full.jsonl` сейчас untracked; это сгенерированный golden-set.
- `origin/langgraph` — альтернативная архитектурная ветка, не слита: она сильно
  конфликтует с текущей `Nikita` и удаляет большую часть текущего pipeline/docs/eval слоя.
- Если `qwen/qwen3-coder:free` продолжает отдавать 429, judge нужно временно перевести
  на `xiaomi/mimo-v2-flash` или платный OpenRouter tier.

---

## Следующие шаги

1. Дождаться Docker build.
2. Запустить стек:

```bash
docker compose -f backend/deploy/docker-compose.yml up -d
```

3. Проверить:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

4. После проверки закоммитить перенос и fixes:

```bash
git add .github Makefile STATUS.md backend frontend start_tunnel.sh
git commit -m "reorganize project into backend and frontend directories"
```
