# 11 — Деплой и эксплуатация

Один `docker compose up` поднимает всё, кроме LM Studio (он на хосте Apple Silicon —
Docker на macOS не пробрасывает Metal/GPU в контейнер, MLX-инференс обязан быть на хосте).

## 1. Состав compose

```
services:
  web       — React UI + nginx, порт 8099 (прокси на api)
  api       — FastAPI (REST + webhooks), внутренний :8080
  worker    — Arq worker (pipeline)
  postgres  — состояние/аудит (volume)
  redis     — очередь + кэш + идемпотентность (volume)
  prometheus, grafana — наблюдаемость (опц., profile=obs)
```

Запуск из корня репозитория: `make docker-up` → UI: http://localhost:8099

- `worker` и `api` — один образ (multi-stage Dockerfile), разные command.
- Semgrep ставится в образ (CLI + рулсеты векторизованы на build, чтобы не ходить в сеть
  в рантайме).
- Доступ к LM Studio: `http://host.docker.internal:1234/v1`
  (`extra_hosts: host-gateway` на Linux). Недоступность → авто-fallback (`06 §3`).

## 2. Конфигурация

- Декларативный `config.yaml` (профиль ансамбля, лимиты, фильтры, политика-дефолты) +
  env для секретов (`.env`, пример — `.env.example`). Pydantic-Settings, fail-fast при
  отсутствии обязательных секретов.
- Per-repo конфиг — в БД (портал), переопределяет дефолты `config.yaml`.

## 3. Операторская инструкция по локальным моделям (Apple Silicon)

1. Примонтировать внешний SSD → проверить `/Volumes/SSD/models/lmstudio-community/`.
2. LM Studio → загрузить `don-agent-v3` (23 GB, 6-bit) и/или
   `Qwen 3.6 35B A3B 4-bit MLX`.
3. LM Studio → Developer → Start Server на `:1234` (OpenAI-compat), context ≥ 8k.
4. Память M4 Max 48 GB: одновременно держать одну 30B-модель; роутер
   последовательно или с одной активной моделью (LM Studio hot-swap). Если обе нужны
   параллельно — профиль `det+don+judge` использует cloud для judge/generalist, локально
   только `don-agent-v3`.
5. Если SSD/LM Studio не готовы — сервис работает на OpenRouter + детерминированном
   слое без вмешательства (degraded, видно в метриках).

## 4. Жизненный цикл

- Health: `/healthz` (живость), `/readyz` (БД/Redis/он-демэнд проверка тиров).
- Graceful shutdown: воркер дорабатывает текущую задачу, новые не берёт; in-flight
  VCS-постинг идемпотентен (fingerprint), повтор не дублирует.
- Миграции: Alembic, авто-апгрейд на старте `api` (lock-safe) либо отдельная job.
- Бэкап: dump postgres-volume (конфиги/аудит); Redis — эфемерен (кэш/очередь
  восстановимы; для незавершённых задач — at-least-once + идемпотентность).

## 5. Масштабирование

- Stateless `api` и `worker` → горизонтально (несколько реплик worker, общий Redis).
- Per-repo конкуррентность и отмена устаревших head_sha не дают шторму пушей
  перегрузить LLM-тиры.
- Бюджеты токенов/стоимости per-scan и глобально; backpressure через queue depth.

## 6. CI/CD

- Lint (ruff) + types (mypy) + tests (pytest, unit+integration с respx-моками) +
  Semgrep/`pip-audit` на собственный код + eval-регрессионный гейт (`12`) → сборка
  образа → push. Образ тегается по git-sha; SBOM прикладывается.
