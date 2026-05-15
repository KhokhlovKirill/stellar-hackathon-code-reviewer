# Aegis — AI Security Reviewer для Pull/Merge Requests

Полная архитектура и план реализации production-сервиса (не MVP): автоматизированный
ИИ-пользователь, который как отдельный сервисный аккаунт принимает webhook о PR/MR из
GitHub / GitLab / Bitbucket, выкачивает **только diff**, прогоняет его через
детерминированный SAST + ансамбль LLM (включая нашу дообученную SFT+ORPO
security-модель на базе `Qwen3-Coder-30B-A3B`), и оставляет построчные комментарии с сутью уязвимости и готовым
сниппетом-исправлением, ведёт диалог в треде и блокирует merge при критичной находке.

Решение целится в максимум по официальной шкале оценки (см. `01-task-analysis.md`) и
делается на полную глубину: каждый этап доводится до конца, без упрощений.

## Документы

| Файл | О чём |
|---|---|
| [01-task-analysis.md](01-task-analysis.md) | Разбор требований, маппинг на критерии оценки, стратегия набора баллов |
| [02-competitive-analysis.md](02-competitive-analysis.md) | Аналоги (CodeRabbit, Qodo/PR-Agent, Greptile, Semgrep Assistant, Snyk, DeepSource, Bearer), плюсы/минусы, что берём и что не повторяем |
| [03-architecture.md](03-architecture.md) | Полная архитектура: компоненты, потоки данных, sequence-диаграммы, модель отказоустойчивости |
| [04-vcs-integration.md](04-vcs-integration.md) | Абстракция провайдеров, webhooks, верификация подписи, inline-комментарии, suggestion-блоки, блокировка merge, сервисный аккаунт |
| [05-analysis-engine.md](05-analysis-engine.md) | Конвейер детекта: детерминированный pre-pass + LLM-ансамбль + judge, борьба с false positives, дизайн промпта, защита от prompt-injection |
| [06-model-strategy.md](06-model-strategy.md) | OpenRouter + локальный Qwen 3.6 35B A3B 4-bit MLX (LM Studio) + дообученная `Qwen3-Coder-30B-A3B SFT+ORPO`: роутинг, fallback, ансамбль, почему дообученная модель усиливает решение |
| [07-data-strategy.md](07-data-strategy.md) | Использование mythos `NewData` / datasets для golden-eval, few-shot, регрессии; синтез vulnerable-PR фикстур из PrimeVul |
| [08-admin-portal.md](08-admin-portal.md) | Control plane: привязка репозитория, хранилище токенов, политика, сервисный аккаунт |
| [09-observability.md](09-observability.md) | Структурное логирование, метрики, аудит, аналитический дашборд (доказательство «шлём только diff») |
| [10-security-and-secrets.md](10-security-and-secrets.md) | Модель угроз, секреты, webhook-auth, sandbox, prompt-injection |
| [11-deployment.md](11-deployment.md) | Docker, compose, конфигурация, доступ к LM Studio с хоста, масштабирование, ops |
| [12-evaluation.md](12-evaluation.md) | Golden-set, метрики precision/recall/FP, прогон по критериям хакатона, регрессионный харнесс |
| [13-phased-plan.md](13-phased-plan.md) | **Поэтапный план с галочками** — точка входа для реализации, acceptance-гейты |
| [14-decisions-and-risks.md](14-decisions-and-risks.md) | ADR (принятые решения), открытые развилки, риски и точки отката |
| [15-backend-specification.md](15-backend-specification.md) | Финальная backend-спецификация: API, pipeline, Risk Score, LLM-модуль, БД, acceptance |
| [16-implementation-status.md](16-implementation-status.md) | Что уже реализовано в коде, что добавлено сейчас, какие production-gaps остаются |

## Принципы (наследуем из mythos)

- **Никаких MVP-срезов**: этап делается на полную глубину либо не делается вовсе.
- **Метрики до интуиции**: uplift дообученной модели и качество детекта доказываются на golden-set, а не утверждаются.
- **Деградация, а не падение**: SSD не примонтирован / LM Studio не поднят / OpenRouter упал — сервис продолжает работать на доступном тире и честно об этом сообщает в комментарии и логах.
- **Diff-only и экономия токенов** — встроены в архитектуру, а не «по возможности».
- **Provenance везде**: каждая находка знает, каким детектором и какой моделью получена, с каким confidence.

## Точка входа

Читаешь впервые — иди в [13-phased-plan.md](13-phased-plan.md): там полная
последовательность шагов с галочками и acceptance-критериями на каждой фазе.
