# Aegis — Статус проекта

> Обновлено: 2026-05-15 23:20

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
├── frontend/                        # frontend boundary
│   ├── templates/                   # текущие Jinja2 templates
│   └── README.md                    # место для будущего frontend-приложения
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

Текущий UI пока остаётся server-rendered Jinja2: Python routes находятся в
`backend/aegis/web/routes.py`, сами шаблоны вынесены в `frontend/templates/`.
Backend читает путь из `AEGIS_FRONTEND_TEMPLATES`.

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
docker compose -f deploy/docker-compose.yml logs -f api worker
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

Compose использует build context root (`../..`), чтобы контейнер получил и
`backend/`, и `frontend/`. В контейнер копируются:

- `backend/aegis`
- `backend/alembic`
- `backend/alembic.ini`
- `backend/config.example.yaml`
- `frontend/templates`

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
mypy: зелёный, 90 source files
pytest: 72 passed
eval gate: precision=1.0, recall=1.0, line_accuracy=1.0, tp=11
```

Docker build запущен:

```bash
docker compose -f backend/deploy/docker-compose.yml build
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
| REST API `/api/...` | работает |
| GitHub/GitLab/Bitbucket webhook gateway | работает |
| Quick Connect GitHub repo + webhook registration | работает |
| Pull-mode scan `/review` | работает |
| Deterministic scan: secrets/entropy/Semgrep/Gitleaks/Bandit/SCA wrappers | работает |
| LLM router: OpenRouter + LM Studio fallback/swap | работает |
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
