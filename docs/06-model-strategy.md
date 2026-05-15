# 06 — Модельная стратегия

Три источника инференса, оркеструются роутером (`aegis/llm/router.py`). Все клиенты —
OpenAI-совместимый chat-completions интерфейс, поэтому переключение тиров — конфиг, не код.

## 1. Тиры

| Тир | Модель | Транспорт | Роль |
|---|---|---|---|
| `local-secure` | **Qwen3-Coder-30B-A3B SFT+ORPO** (`don-agent-v3`) | LM Studio, `host:1234/v1` | Профильный security-детектор A |
| `local-base` | **Qwen 3.6 35B A3B 4-bit MLX** | LM Studio, `host:1234/v1` | Локальный генералист / detector B / fallback |
| `cloud` | OpenRouter (конфиг. модель) | `openrouter.ai/api/v1` | Детектор B и/или **judge-арбитр**; fallback при недоступности локали |

Профиль ансамбля (per-repo, дефолт): A=`local-secure`, B=`cloud-generalist`,
Judge=`cloud-strong`. Если SSD/LM Studio недоступны → A падает на `cloud`, помечается
деградация. Если OpenRouter недоступен → A=`local-secure`, B=`local-base`, Judge=
`local-secure` (с пометкой «judge деградирован»). Полный отказ LLM → только
детерминированный слой (`05 §1`).

## 2. Дообученная Qwen3-Coder-30B-A3B SFT+ORPO — что это и почему усиливает решение

Дообучена из `Qwen3-Coder-30B-A3B-Instruct-MLX-6bit` методом SFT + ORPO
(см. `/Users/nikitasyzdykov/Desktop/Projects/mythos/SOLUTION.md`):

- **SFT-корпус прямо релевантен задаче:** PrimeVul (1 499 пар vulnerable/fixed —
  «детект и патч уязвимости»), nuclei CVE templates (1 500), HackTricks (828),
  PayloadsAllTheThings (140), WSTG (162), exploitdb (8 000), pwn-college — это
  ровно знание о том, как выглядят SQLi/XSS/inj/деструктивные паттерны и как их чинить.
- **ORPO** учит давать **законченный ответ вместо «рекомендации/хеджа»** — для
  ревью это значит конкретные находки + готовый fix, а не «возможно, стоит проверить».
- **Anti-refusal:** не отказывается анализировать exploit-подобный код (generic
  safety-tuned cloud-модели иногда soft-refuse на «как это эксплуатировать»). Для
  security-ревью оборонительная рамка — легитимна, и модель её не блокирует.
- **Скорость:** в mythos-eval дообученные отвечают в 2–4× короче/быстрее (стиль
  «действуй сразу») — на локальном M4 Max это ощутимо для латентности ревью.

### Известные ограничения и как мы их снимаем
- Нативный вывод — CTF-формат `<action>/<observation>/<answer>`, system-промпт «ACT
  immediately». Для ревью **переопределяем промпт** на строгий JSON-контракт находок
  (наш system-промпт перекрывает дефолтное поведение; few-shot закрепляет формат) и
  ставим тонкий парсер с repair-проходом + валидацией по схеме. Если модель всё же
  дрейфует в `<action>` — judge нормализует, а парсер достаёт находки из текста.
- На голом тексте без инструментов она не «решает» CTF (eval: 0 флагов) — нам это и не
  нужно: задача статическая (diff → находки), а не интерактивная эксплуатация.
- Метрики keyword-overlap в mythos-eval занижают её из-за краткости — мы меряем не
  overlap, а **precision/recall по находкам** на нашем golden-set (`12`).

### Доказательство uplift (принцип «метрики до интуиции»)
A/B-переключатель в конфиге: профиль `det+cloud` vs `det+cloud+don` vs `det+don+judge`.
Eval-харнесс (`12`) гоняет все профили по golden-set и публикует
precision/recall/FP/latency/cost в `eval/results/`. Дообученная модель включается в
дефолт **только если на golden-set она статистически улучшает F1 или снижает FP** при
приемлемой латентности. Если нет — остаётся опциональным тиром, решение задокументировано
как ADR в `14`. Это честная инженерия, а не «вставили, потому что своя».

## 3. Доступ к LM Studio

- LM Studio поднимает OpenAI-совместимый сервер на `:1234`. Воркер из контейнера ходит
  на `http://host.docker.internal:1234/v1` (на Linux — `--add-host`/host-gateway).
- На момент проектирования: `/Volumes/SSD` **не примонтирован**, LM Studio **не
  запущен** — это штатный degraded-сценарий, не блокер. Health-probe тира
  (`GET /v1/models`) кэшируется (TTL 30s); недоступность → автоматический fallback на
  `cloud`, метрика `llm_tier_down{tier=...}`.
- Путь дообученной модели: `/Volumes/SSD/models/lmstudio-community/don-agent-v3`
  (23 GB, 6-bit). В LM Studio она указывается как `LMSTUDIO_SECURE_MODEL`.
- Локальный базовый генералист для второго независимого взгляда:
  `Qwen 3.6 35B A3B 4-bit MLX`, переменная `LMSTUDIO_BASE_MODEL`.
  Operator-doc — `11`.

## 4. OpenRouter

- Ключ — из vault/env (`OPENROUTER_API_KEY`), на хакатоне выдаётся организаторами.
- Конфигурируемые модель-слоты: `OPENROUTER_GENERALIST_MODEL`, `OPENROUTER_JUDGE_MODEL`.
  Дефолт judge — сильная reasoning-модель; generalist — дешевле/быстрее.
- Ретраи, таймауты, бюджет токенов/стоимости per-scan; учёт стоимости в `llm_calls` и
  Prometheus (`llm_cost_usd_total`).

## 5. Контракт клиента

`aegis/llm/base.py`: единый `async def complete(messages, schema, budget) -> Parsed`.
Все тиры реализуют его. Гарантии: таймаут, ретрай, structured-output (через
`response_format`/JSON-mode где поддерживается, иначе schema-в-промпте + парсер),
учёт usage, маскирование секретов в логах запроса/ответа.

## 6. Конфиг (выдержка)

```yaml
llm:
  ensemble_profile: det+don+judge        # det+cloud | det+cloud+don | det+don+judge
  detector_a: local-secure
  detector_b: cloud-generalist
  judge: cloud-strong
  per_scan_token_budget: 120000
  per_scan_cost_usd_cap: 0.50
tiers:
  local-secure: { base_url: http://host.docker.internal:1234/v1, model: don-agent-v3 }
  local-base:   { base_url: http://host.docker.internal:1234/v1, model: qwen3.6-35b-a3b-4bit-mlx }
  cloud:        { base_url: https://openrouter.ai/api/v1,
                  generalist_model: ${OPENROUTER_GENERALIST_MODEL},
                  judge_model: ${OPENROUTER_JUDGE_MODEL} }
```
