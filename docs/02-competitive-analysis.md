# 02 — Анализ аналогов

Срез на май 2026. Цель: понять, что рынок уже умеет, какие у лидеров сильные стороны и
системные слабости, и явно зафиксировать, что мы повторяем, а что делаем иначе.

## 1. Обзор аналогов

### Обновление на 2026-05-15

Проверены актуальные страницы документации и публичные материалы: CodeRabbit
поддерживает GitHub/GitLab/Azure DevOps/Bitbucket и публикует review-комментарии в PR;
Qodo v2 с 4 февраля 2026 описывает новый code-review experience; Greptile делает
полный graph-index кодовой базы; Snyk PR Checks позиционируются как автоматический
security reviewer в pull requests; OpenRouter и LM Studio подтверждают единый
OpenAI-compatible API для нашего роутинга. Вывод архитектурно не изменился: лидеры
сильны в UX и контексте, но наша ставка должна быть на гибридный security-first
pipeline: детерминированный SAST/SCA/secrets слой + локальная SFT+ORPO security-модель
+ OpenRouter judge + измеримый FP-rate.

### CodeRabbit
- **Что:** самый массовый AI-reviewer, поддерживает GitHub/GitLab/Bitbucket/Azure DevOps,
  inline-комментарии, summary, чат в PR.
- **Плюсы:** широкая интеграция, удобный UX, дёшево ($24/dev/мес), быстрый онбординг.
- **Минусы:** это **не security-инструмент**: по независимым замерам ~44–46% bug-catch на
  реальных рантайм-багах; контекст ограничен текущим PR/репо; нет глубокого taint-анализа;
  security — побочная функция, без SCA/secret-движка уровня SAST.
- **Берём:** UX inline + summary, чат в PR. **Не повторяем:** «LLM на голом diff без
  детерминированного слоя» — отсюда их низкая security-точность.

### Qodo Merge / PR-Agent (бывш. Codium)
- **Что:** open-source PR-Agent + коммерческий Qodo Merge; Qodo 2.0 (фев 2026) —
  мульти-агентная архитектура (отдельные агенты: bug / security / quality / tests
  параллельно), RAG-движок по кодовой базе (Qodo Aware).
- **Плюсы:** лучший F1 (~60%) среди 8 инструментов в их бенче; self-host бесплатно;
  мульти-агентность; кросс-репо контекст на Enterprise.
- **Минусы:** «security-агент» — это всё ещё LLM-проход, не специализированный
  vuln-движок; качество сильно зависит от выбранной cloud-модели; FP на больших PR.
- **Берём:** идею **специализированных параллельных детекторов** и **judge-консолидации**.
  Мы усиливаем её доменно-дообученной моделью + детерминированным слоем.

### Greptile
- **Что:** AI-reviewer с pattern-matching + трассировкой зависимостей по всему репо
  (GitHub/GitLab).
- **Плюсы:** заявленный bug-catch 82% (против 44% CodeRabbit); кросс-файловый контекст.
- **Минусы:** ценой высокого FP (в их же бенче 11 FP против 2 у CodeRabbit) — иллюстрирует
  фундаментальный trade-off recall↔precision, который мы решаем judge-слоем и
  confidence-гейтингом; нет формальной верификации/symbolic exec.
- **Вывод:** высокий recall без анти-FP даёт шум → разработчики игнорируют бота. У нас
  анти-FP — отдельный обязательный слой (см. `05-analysis-engine.md`).

### Semgrep + Semgrep Assistant
- **Что:** индустриальный SAST (taint-tracking, OWASP/secret/SCA rulesets), Assistant —
  AI-постобработка находок (триаж, объяснение, авто-фикс-предложения, Assistant Memories).
- **Плюсы:** детерминированный движок с низким FP (Assistant снижает шум ещё на ~20%,
  поднимает true-positive до +250%); признан в Gartner MQ 2025; правила на десятки
  языков; taint-анализ для SQLi/XSS/inj.
- **Минусы:** Assistant **не делает независимое ревью и не пишет патчи как полноценный
  AI-reviewer** — это надстройка над движком правил; UX заточен под AppSec-команду, не
  под inline-диалог в PR; кастомные правила — порог входа.
- **Берём:** **Semgrep OSS как наш детерминированный слой** (p/owasp-top-ten,
  p/security-audit, p/secrets) — даёт near-zero-FP recall по C3 даже без LLM. Это
  ключевое архитектурное заимствование.

### Snyk (Code/Open Source/Container)
- **Что:** платформа SAST + SCA + контейнеры + IaC; DeepCode AI.
- **Плюсы:** сильнейшая SCA/база уязвимостей зависимостей, авто-фиксы, широкая экосистема.
- **Минусы:** проприетарно/дорого; SAST исторически шумнее DeepSource на CVE-бенче;
  vendor lock-in.
- **Берём:** подход к **supply-chain** (манифесты → база уязвимостей). У нас — открытый
  OSV.dev + GitHub Advisory + deps.dev вместо проприетарной БД.

### DeepSource
- **Что:** статанализ + AI; гарантия <5% FP на детерминированных правилах.
- **Плюсы:** 84.5% F1 на OpenSSF CVE-бенче (против 56.97% Semgrep CE); акцент на низкий FP;
  OWASP Top10 / SANS Top25.
- **Минусы:** автокомментарии менее «разговорные»; меньше языков с глубокими правилами;
  AI-слой закрыт.
- **Берём:** философию **«детерминированное ядро + AI поверх, FP — KPI №1»**.

### Bearer (ныне в составе Cycode)
- **Что:** SAST с фокусом на data-flow и PII/секреты.
- **Плюсы:** хороший secret/PII data-flow; OSS-версия.
- **Минусы:** меньше языков; меньше комьюнити, чем Semgrep.
- **Берём:** идею data-flow к секретам как доп. сигнал (через Semgrep-правила).

## 2. Системные выводы для нашей архитектуры

| Наблюдение по рынку | Наше архитектурное решение |
|---|---|
| Чистый LLM-проход (CodeRabbit) → низкая security-точность | Детерминированный SAST/secret/SCA слой **перед** LLM, его находки — grounded-факты в промпте |
| Высокий recall без анти-FP (Greptile) → шум, бота игнорируют | Обязательный judge-слой + confidence-гейтинг + «только changed-lines» + дедуп |
| Детерминированное ядро + AI поверх (DeepSource/Semgrep) → лучший F1 при низком FP | Берём как базовый паттерн; FP-rate — метрика №1 в eval |
| Мульти-агентность (Qodo 2.0) | Ансамбль детекторов: дообученная security-модель + генералист + judge-арбитр |
| SCA как отдельная ценность (Snyk) | Supply-chain поверх OSV/Advisory/deps.dev + предложение замены библиотеки |
| Никто не использует доменно-дообученную offensive-security модель | **Наш дифференциатор:** `don-agent-v3` (PrimeVul/exploitdb/HackTricks/nuclei SFT+ORPO), не отказывается анализировать exploit-подобный код, даёт решение, а не «посмотрите внимательнее» |

## 3. Где мы сильнее аналогов (защита на демо)

1. **Гибрид:** детерминированный near-zero-FP слой **гарантирует** P1-критерии даже при
   полном отказе LLM-тира — ни один аналог не даёт такой страховки самого дорогого блока.
2. **Доменно-дообученная модель** как security-детектор + ORPO-поведение «давать
   законченный ответ, не хеджировать» → конкретные находки и патчи, а не вода.
3. **Анти-FP как отдельный слой с метрикой**, а не побочный эффект промпта.
4. **Доказуемость:** свой golden-set из PrimeVul (vulnerable/fixed пары → синтетические
   «PR, вносящий уязвимость») + аналитический дашборд «ушло только diff» — прямой ответ
   на критерии C2/C3 и на запрос организаторов о прозрачной оценке.
5. **Отказоустойчивость и деградация** — продуманы как часть архитектуры, а не «потом».

## Источники

- [Best AI Code Review Tools in 2026 — Qodo](https://www.qodo.ai/blog/best-ai-code-review-tools-2026/)
- [Best AI Code Review Tools in 2026: Top 8 Compared — Qodo](https://www.qodo.ai/blog/ai-code-review-tools/)
- [The Best AI Code Review Tools in 2026 — Medium](https://medium.com/@lewis_75321/the-best-ai-code-review-tools-in-2026-599c7dd1b305)
- [Best CodeRabbit Alternatives 2026 — Surmado](https://www.surmado.com/blog/best-coderabbit-alternatives-2026)
- [Semgrep AI Code Review — Augment Code](https://www.augmentcode.com/tools/semgrep-ai-code-review)
- [DeepSource vs Semgrep (2026) — DEV](https://dev.to/rahulxsingh/deepsource-vs-semgrep-static-analysis-tools-compared-2026-1h8a)
- [AI-Powered Detection with Semgrep — Semgrep blog](https://semgrep.dev/blog/2025/ai-powered-detection-with-semgrep/)
- [Snyk vs Semgrep — Aikido](https://www.aikido.dev/blog/snyk-vs-semgrep)
- [CodeRabbit platform overview](https://docs.coderabbit.ai/platforms/overview)
- [Qodo Merge documentation](https://docs.qodo.ai/qodo-documentation/qodo-merge/)
- [Greptile API/docs overview](https://www.greptile.com/docs/api-reference)
- [Snyk Pull Request checks](https://docs.snyk.io/scan-with-snyk/pull-requests/pull-request-checks)
- [OpenRouter structured outputs](https://openrouter.ai/docs/features/structured-outputs)
- [LM Studio OpenAI-compatible endpoints](https://lmstudio.ai/docs/app/api/endpoints/openai/)
