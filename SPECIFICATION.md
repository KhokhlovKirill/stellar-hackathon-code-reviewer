# Aegis — AI Security Code Review System

## Specification v1.0

---

## 1. Что это такое

**Aegis** — production-ready система автоматического security code review для Pull Request'ов.
Анализирует каждый PR на уязвимости (OWASP Top 10, CWE Top 25), оставляет инлайн-комментарии с объяснением и патчем, блокирует мерж при критических находках, накапливает базу знаний по паттернам уязвимостей.

**Аналоги**: Qodo Aware, CodeRabbit, Snyk Code, Semgrep Managed Scans.

**Ключевые отличия**:
- Полностью self-hosted, данные не покидают инфраструктуру
- Security Knowledge Base — "видит" повторяющиеся паттерны между PR'ами
- Ансамбль из трёх LLM-агентов: детерминистика + смысловой анализ + судья
- Autofix PR — автоматически создаёт исправление и открывает PR

---

## 2. Архитектура

```
GitHub / GitLab / Bitbucket
        │ webhook (PR opened/updated)
        ▼
┌───────────────────────────────────────────────────────┐
│  FastAPI Gateway  (aegis/api/webhooks.py)             │
│  • верифицирует HMAC подпись                         │
│  • идемпотентность (claim в Redis)                   │
│  • создаёт Scan в БД, ставит в очередь               │
└────────────────────┬──────────────────────────────────┘
                     │ Redis Queue (aegis.scan)
                     ▼
┌───────────────────────────────────────────────────────┐
│  Pipeline Runner  (aegis/pipeline/runner.py)          │
│  Этапы выполняются последовательно:                   │
│                                                       │
│  1. fetch_pr     — загрузить метаданные PR            │
│  2. fetch_diff   — получить unified diff              │
│  3. deterministic — secrets, SQL-инъекции (regex)    │
│  4. llm_scan     — ансамбль LLM-агентов              │
│  5. kb_enrich    — обогатить KB-матчами              │
│  6. blast_radius — оценить затронутые компоненты      │
│  7. autofix      — сгенерировать патч (если нужно)   │
│  8. render       — опубликовать комментарии в PR      │
└───────────────────────────────────────────────────────┘
        │
        ▼
PostgreSQL (сканы, находки, KB, пользователи, проекты)
Redis     (очередь, LLM-кэш, идемпотентность)
```

### Компоненты

| Компонент | Путь | Назначение |
|-----------|------|-----------|
| FastAPI app | `aegis/api/app.py` | Точка входа, монтирует все роутеры |
| Webhook gateway | `aegis/api/webhooks.py` | Приём событий от VCS |
| REST API | `aegis/api/admin.py` | Управление проектами, репо, сканами |
| Web UI | `aegis/web/routes.py` | HTML-страницы (Jinja2 + Tailwind) |
| Pipeline | `aegis/pipeline/` | Стадии анализа |
| Providers | `aegis/providers/` | Адаптеры для GitHub/GitLab/Bitbucket |
| LLM | `aegis/llm/` | Клиенты OpenRouter + LM Studio |
| KB | `aegis/kb/` | Security Knowledge Base |
| DB models | `aegis/db/models.py` | SQLAlchemy модели |

---

## 3. Pipeline — детально

### 3.1 Детерминистический детектор (`aegis/pipeline/deterministic/`)

Regex-правила без LLM. Быстрые, 100% точные для явных паттернов.

| Детектор | CWE | Примеры |
|----------|-----|---------|
| secrets.py | CWE-798, CWE-321 | AWS keys, GitHub tokens, Stripe keys, private keys, Slack webhooks |
| sqli.py | CWE-89 | Конкатенация строк в SQL-запросах |
| xss.py | CWE-79 | `innerHTML`, `document.write`, не-экранированный вывод |
| cmdi.py | CWE-78 | `subprocess.call(shell=True)`, `os.system()` |
| path_traversal.py | CWE-22 | `../` в путях, open() с user input |
| ssrf.py | CWE-918 | requests.get(user_input) |
| deserialize.py | CWE-502 | pickle.loads, yaml.load, eval() |
| deps.py | CWE-1395 | Pinned deps с известными CVE |

### 3.2 LLM-ансамбль (`aegis/llm/`)

Три агента на каждый hunk кода:

**DET-агент** (qwen/qwq-32b через OpenRouter)
- Роль: старший security инженер
- Задача: найти всё, что детерминистика пропустила
- Формат ответа: JSON список findings

**DON-агент v3** (don-agent-v3 через LM Studio, локально)
- Роль: специалист по offensive security
- Задача: смысловой анализ, логические уязвимости, бизнес-логика
- Формат: native schema (cwe: int, line_number, confidence: str) → нормализуется

**JUDGE-агент** (claude-3-5-sonnet через OpenRouter)
- Роль: арбитр
- Задача: дедупликация, отсев FP, финальное ранжирование
- Вход: находки от DET + DON, исходный код

**LLM Cache** (`aegis/llm/cache.py`): Redis, TTL 1 час, ключ SHA1(model+messages). Экономит токены при повторных анализах одинаковых hunks.

### 3.3 Security Knowledge Base (`aegis/kb/`)

Векторная база подтверждённых находок.

- **Embeddings**: nomic-embed-text-v1.5 (768-dim) через LM Studio
- **Хранение**: JSON-колонка в PostgreSQL (миграция на pgvector готова)
- **Поиск**: cosine similarity, порог 0.75, топ-3 на finding
- **Аннотация**: "🔁 Recurring pattern — similar to confirmed CWE-89 in PR #142 (similarity 0.86)"
- **Накопление**: после каждого подтверждённого finding — индексируется

### 3.4 Autofix (`aegis/pipeline/autofix.py`)

Для критических находок автоматически:
1. Создаёт ветку `aegis/fix-{fingerprint[:8]}`
2. Применяет патч: secrets → `os.getenv()`, уязвимые deps → bumped версия
3. Коммитит и открывает PR с описанием

### 3.5 Comment dedup (`aegis/pipeline/render.py`)

Проверяет `FindingRow.comment_ref` по fingerprint перед каждым комментарием — не дублирует на повторных pushes в тот же PR.

---

## 4. База данных

### Модели (PostgreSQL + SQLAlchemy async)

```
User
├── id, email (unique), password_hash, display_name, created_at
└── → Project (owner_id FK)

Project
├── id, owner_id FK, name, description, created_at
└── → Repository (project_id FK)

Repository
├── id, provider, external_id, slug, status, project_id FK
├── → RepoSecret[] (access_token, webhook_secret — Fernet-encrypted)
└── → RepoPolicy (severity_gate, merge_block, ignore_globs, ensemble_profile, lang)

Scan
├── id (uuid hex), provider, repo_slug, pr_id, head_sha
├── status (queued/running/done/error), risk_score, risk_label
├── decision, files_scanned, files_skipped, degraded
└── → FindingRow[]

FindingRow
├── id, scan_id FK, fingerprint (unique per scan)
├── file, line, cwe, severity, title, rationale, fix, exploit
├── comment_ref (ID комментария в VCS, для dedup)
└── embedding JSON (768-dim vector для KB)

KnowledgeEntry
├── id, repo_slug, fingerprint (unique), cwe, title
├── embedding JSON, confirmed bool
└── created_at
```

### Миграции

```bash
# Применить все миграции
alembic upgrade head

# Создать новую миграцию после изменения моделей
alembic revision --autogenerate -m "description"
```

---

## 5. Безопасность

| Аспект | Реализация |
|--------|-----------|
| Пароли | pbkdf2_hmac SHA-256, 240k итераций, 16-byte salt, constant-time compare |
| Сессии | JWT (HS256), httponly cookie, SameSite=lax, 24h TTL |
| API auth | Bearer JWT в Authorization header |
| Секреты репо | Fernet (AES-128-CBC + HMAC-SHA256) в поле ciphertext |
| Webhook | HMAC-SHA256 подпись, верификация до любых side effects |
| SQL | SQLAlchemy parameterized queries, no raw SQL |
| Admin | Отдельный bootstrap-пользователь через env AEGIS_ADMIN_PASSWORD |

---

## 6. Конфигурация

Все настройки через переменные окружения (`aegis/config.py`):

```bash
# Обязательные
AEGIS_DATABASE_URL=postgresql+asyncpg://user:pass@host/dbname
AEGIS_VAULT_KEY=<fernet key — генерация: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">

# Опциональные (есть дефолты)
AEGIS_REDIS_URL=redis://localhost:6379/0
AEGIS_ADMIN_USER=admin
AEGIS_ADMIN_PASSWORD=changeme
AEGIS_OPENROUTER_API_KEY=sk-or-...
AEGIS_LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
AEGIS_LMSTUDIO_MODEL=don-agent-v3
AEGIS_LMSTUDIO_EMBED_MODEL=nomic-embed-text-v1.5
```

---

## 7. Запуск

### Вариант A — Docker Compose (рекомендуемый)

```bash
# Полный стек: API + Worker + PostgreSQL + Redis + Grafana
docker compose --profile obs up

# Только core (без Grafana)
docker compose up
```

Доступные сервисы после старта:
- `http://localhost:8099` — Web UI
- `http://localhost:8099/docs` — Swagger API
- `http://localhost:3000` — Grafana (admin/admin)
- `http://localhost:9090` — Prometheus

### Вариант B — Локально (разработка)

```bash
# 1. Создать виртуальное окружение
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Настроить .env
cp .env.example .env  # отредактировать

# 3. Запустить PostgreSQL и Redis (или использовать SQLite для теста)
# SQLite — только для разработки:
export AEGIS_DATABASE_URL="sqlite+aiosqlite:///./aegis_local.db"

# 4. Применить миграции
alembic upgrade head

# 5. Запустить API сервер
uvicorn aegis.api.app:app --host 0.0.0.0 --port 8099 --reload

# 6. Запустить worker (в отдельном терминале)
python -m aegis.worker
```

### Вариант C — Только API сервер (быстрый тест без worker)

```bash
AEGIS_DATABASE_URL="sqlite+aiosqlite:///./aegis_local.db" \
AEGIS_REDIS_URL="redis://localhost:6379/0" \
AEGIS_VAULT_KEY="xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=" \
AEGIS_ADMIN_PASSWORD="admin123" \
.venv/bin/uvicorn aegis.api.app:app --host 127.0.0.1 --port 8099
```

Webhook'и принимаются, сканы ставятся в очередь. Без worker — анализ не выполняется.

---

## 8. Публичный доступ для webhook'ов

GitHub требует публичный URL. Для разработки — ngrok:

```bash
brew install ngrok
ngrok http 8099
# → https://xxxx.ngrok-free.app
```

Для production — настрой nginx + SSL и используй реальный домен.

---

## 9. Как работать с системой (руководство пользователя)

### 9.1 Регистрация

1. Открыть `http://localhost:8099/register`
2. Ввести email и пароль (минимум 8 символов)
3. Нажать **Create account** — автоматический вход и редирект на Dashboard

### 9.2 Создание проекта

На Dashboard → форма **New project**:
- **Name** — название проекта (уникальное для вашего аккаунта)
- **Description** — необязательное описание

Проект — это контейнер для репозиториев и сканов.

### 9.3 Подключение репозитория

**Способ 1: Quick Connect (рекомендуется)**

На странице проекта, вкладка **⚡ Quick connect**:
1. **GitHub repo URL** — вставить ссылку: `https://github.com/owner/repo`
2. **GitHub access token** — PAT с правами `repo` + `admin:repo_hook`
3. **Your public URL** — URL вашего сервера (ngrok или домен)
4. Нажать **⚡ Connect automatically**

Что произойдёт автоматически:
- Aegis запросит ID и метаданные репозитория через GitHub API
- Сгенерирует случайный webhook secret
- Зарегистрирует webhook на GitHub (Pull requests events)
- Сохранит токен и секрет в зашифрованном виде

**Способ 2: Manual**

На странице проекта, вкладка **Manual** — ввести все поля вручную.

### 9.4 Создание GitHub PAT (Access Token)

1. Перейти: `github.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token`
2. **Repository access**: выбрать конкретное репо
3. **Permissions**:
   - `Contents` → Read-only (читать diff)
   - `Pull requests` → Read and write (комментарии)
   - `Commit statuses` → Read and write (статус-чеки)
   - `Webhooks` → Read and write (для Quick Connect, auto-регистрация)
4. Сгенерировать и скопировать токен (`ghp_...`)

### 9.5 Просмотр результатов

После открытия PR в подключённом репозитории:
1. GitHub отправляет webhook на Aegis
2. Scan создаётся в очереди (статус `queued`)
3. Worker запускает pipeline (~30-120 сек)
4. Статус меняется на `done`
5. В PR появляются инлайн-комментарии с находками
6. В Dashboard → Project → Recent scans — кликнуть на запись

### 9.6 Страница скана

Показывает:
- **Risk score** (0-100) и **Risk label** (low/medium/high/critical)
- **Decision**: approve / request_changes / block
- **Files scanned** / **Files skipped**
- Таблица находок:
  - Файл и строка
  - CWE и severity
  - Заголовок уязвимости
  - Rationale — объяснение почему это проблема
  - Fix — рекомендуемое исправление
  - Recurring pattern — если KB нашёл аналогичную уязвимость в прошлых PR

---

## 10. REST API

Base URL: `http://localhost:8099/api`
Auth: `Authorization: Bearer <token>`

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/auth/register` | Регистрация |
| POST | `/auth/login` | Логин, получить токен |
| GET | `/projects` | Список проектов |
| POST | `/projects` | Создать проект |
| GET | `/projects/{id}` | Детали проекта (репо + сканы) |
| POST | `/projects/{id}/repos` | Подключить репо (manual) |
| POST | `/projects/{id}/repos/quick-connect` | Подключить репо (auto) |
| GET | `/scans` | Список сканов (admin) |
| GET | `/scans/{id}` | Детали скана + findings (admin) |
| GET | `/stats` | Статистика (admin) |

Полная документация: `http://localhost:8099/docs`

### Пример: полный флоу через API

```bash
# Регистрация
curl -X POST http://localhost:8099/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword"}'

# Логин → токен
TOKEN=$(curl -s -X POST http://localhost:8099/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"mypassword"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Создать проект
curl -X POST http://localhost:8099/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Project"}'

# Quick connect репо
curl -X POST http://localhost:8099/api/projects/1/repos/quick-connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/owner/repo",
    "access_token": "ghp_xxxx",
    "public_url": "https://xxxx.ngrok-free.app"
  }'
```

---

## 11. Мониторинг

### Grafana (http://localhost:3000, admin/admin)

Дашборд **Aegis Overview** включает:
- Webhooks received / Webhooks rejected (по провайдеру)
- Scans queued / completed / errored
- Pipeline latency (p50/p95/p99)
- LLM calls latency (по агенту)
- VCS API calls (по провайдеру и операции)
- Findings per severity (за 24h)
- Active repos

### Prometheus metrics (http://localhost:9090)

```
aegis_webhooks_total{provider, kind, valid}
aegis_scans_total{provider, status}
aegis_pipeline_stage_seconds{stage}
aegis_llm_calls_total{agent, status}
aegis_vcs_calls_total{provider, op, status}
```

---

## 12. Тестирование

```bash
# Все тесты (72 штуки)
pytest tests/ -v

# Только unit тесты (без LM Studio)
pytest tests/ -v -k "not live"

# С LM Studio (don-agent-v3 должен быть загружен)
pytest tests/test_lmstudio_live.py -v

# Eval pipeline (секреты: precision=recall=1.0)
python eval/score_criteria.py
```

### Симуляция webhook без ngrok

```bash
PAYLOAD='{"action":"opened","number":1,"pull_request":{"number":1,"head":{"sha":"abc123"},"base":{"sha":"def456"}},"repository":{"id":1237491770,"full_name":"Nikita56792/Don"}}'
SECRET="your-webhook-secret"
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print "sha256="$2}')

curl -X POST http://127.0.0.1:8099/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: $SIG" \
  -H "X-GitHub-Delivery: test-001" \
  -d "$PAYLOAD"
```

---

## 13. Требования к окружению

### Минимальные (только webhook + web UI)
- Python 3.11+
- PostgreSQL 14+ (или SQLite для разработки)
- Redis 7+

### Для полного LLM-анализа
- LM Studio с загруженными моделями:
  - `don-agent-v3` — смысловой анализ
  - `nomic-embed-text-v1.5` — векторные embeddings для KB
- OpenRouter API key для:
  - `qwen/qwq-32b` — детерминистический агент
  - `anthropic/claude-3-5-sonnet` — судья

### Для продакшена
- nginx + SSL (Let's Encrypt)
- PostgreSQL с pgvector расширением (для ускорения KB-поиска)
- Redis Sentinel или Cluster
- Docker + docker-compose или Kubernetes

---

## 14. Структура репозитория

```
code-review/
├── aegis/
│   ├── api/
│   │   ├── app.py           # FastAPI app factory
│   │   ├── admin.py         # REST API endpoints
│   │   ├── auth.py          # JWT issue/verify
│   │   ├── security.py      # password hash, session auth
│   │   └── webhooks.py      # webhook gateway
│   ├── web/
│   │   ├── routes.py        # web UI routes
│   │   └── templates/       # Jinja2 HTML templates
│   ├── pipeline/
│   │   ├── runner.py        # orchestrator
│   │   ├── deterministic/   # regex detectors
│   │   ├── llm_scan.py      # LLM ensemble
│   │   ├── kb_enrich.py     # KB annotation
│   │   ├── blast_radius.py  # impact analysis
│   │   ├── autofix.py       # auto-patch PR
│   │   └── render.py        # publish comments
│   ├── providers/
│   │   ├── github.py        # GitHub adapter
│   │   ├── gitlab.py        # GitLab adapter
│   │   └── bitbucket.py     # Bitbucket adapter
│   ├── llm/
│   │   ├── openai_compat.py # LLM HTTP client + cache
│   │   ├── parser.py        # response parser + normalizer
│   │   └── cache.py         # Redis LLM cache
│   ├── kb/
│   │   ├── embeddings.py    # nomic-embed client
│   │   └── store.py         # KB index/query
│   ├── db/
│   │   ├── models.py        # SQLAlchemy models
│   │   └── __init__.py      # async session factory
│   └── config.py            # settings (pydantic-settings)
├── tests/                   # pytest test suite (72 tests)
├── eval/                    # evaluation pipeline
│   ├── build_golden.py      # 40-case golden set builder
│   ├── run.py               # eval runner
│   └── score_criteria.py    # C1-C8 criteria scorer
├── deploy/
│   ├── docker-compose.yml
│   └── grafana/             # pre-provisioned dashboards
├── alembic/                 # DB migrations
└── SPECIFICATION.md         # этот файл
```

---

## 15. Оценка качества (C1–C8)

Система оценивается по восьми критериям:

| Критерий | Описание | Результат |
|----------|----------|-----------|
| C1 | Webhook gateway (HMAC, idempotency) | ✅ |
| C2 | Детерминистический детектор (secrets) | ✅ P=R=1.0 |
| C3 | LLM-ансамбль (DET+DON+JUDGE) | ✅ |
| C4 | Инлайн-комментарии с dedup | ✅ |
| C5 | Merge block на critical | ✅ |
| C6 | Security Knowledge Base | ✅ |
| C7 | Dialog (ответы на комментарии в PR) | ✅ |
| C8 | Autofix PR | ✅ |

Eval: `python eval/score_criteria.py` → 32/32 (100%)
