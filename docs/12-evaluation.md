# 12 — Оценка качества

Воспроизводимый харнесс: доказываем критерии хакатона цифрами, а не словами (принцип
mythos «метрики до интуиции»). Организаторы единый пул репозиториев не дают →
собственный golden-set (`07`) + локальный тестовый репозиторий для e2e.

## 1. Golden-set

- Источник: PrimeVul vulnerable/fixed пары + ручные фикстуры под формулировки критериев
  (SQLi f-string, hardcoded AWS-key/`.env`, reflected XSS, supply-chain bad dep) +
  не-кодовые файлы (README/.gitignore/png) + чистые рефакторы (анти-FP, ≥40%).
- Каждый кейс отрендерен в payload **всех трёх провайдеров** (github/gitlab/bitbucket)
  → проверяем парсинг diff и маппинг строк на каждом.
- `eval/golden/` версионируется; `eval/build_golden.py` детерминирован (seed).

## 2. Метрики

- Per-class precision / recall / F1 (SQLi, secret, XSS, cmd-inj, path-trav, SCA, …).
- **FP-rate** на негативных/чистых кейсах — KPI №1 (анти-FP требование).
- Line-accuracy: доля находок, привязанных к правильной изменённой строке (C4).
- Fix-validity: предложенный сниппет синтаксически валиден и снимает находку при
  повторном прогоне (C5).
- Operational: latency p50/p95, токены, стоимость per scan, fallback-rate.

## 3. Прогон по критериям хакатона

`eval/score_criteria.py` отображает результаты на официальную шкалу (C1..C8, веса) и
печатает ожидаемый итог из 96. e2e-сценарии на локальном тестовом репо:
- C1: webhook (валидная/битая подпись, replay) → корректный приём/отказ.
- C2: diff-only → панель «sent vs full-repo tokens».
- C3: SQLi/secret/XSS фикстуры → находки с правильным CWE.
- C4: inline-комментарий на нужной строке.
- C5: suggestion применяется, находка исчезает.
- C6: README/.gitignore/png отфильтрованы (в skipped, не в LLM).
- C7: ответ в треде на reply автора.
- C8: Critical → падающий required-check, merge заблокирован до override.

## 4. Сравнение ensemble-профилей (uplift дообученной модели)

`eval/run.py --profile {det+cloud, det+cloud+don, det+don+judge}` → таблица
F1/FP/latency/cost по golden-set → `eval/results/<ts>.json` + markdown-отчёт и графики
(как в mythos `eval_results/`). Дефолт-профиль выбирается по данным; решение и цифры
фиксируются ADR в `14`. Честно публикуем, даже если дообученная модель не даёт uplift.

## 5. Регрессионная защита

CI-гейт: если F1 по SQLi/secret/XSS падает > δ или FP-rate растёт > δ относительно
зафиксированного `eval/baseline.json` — мерж блокируется. Few-shot и golden-set
заморожены и версионируются; изменение baseline — осознанный коммит с обоснованием.

## 6. Нагрузочная проверка

Скрипт шлёт N webhook параллельно (разные repo/pr) → проверяем queue depth, отсутствие
дублей комментариев (идемпотентность), деградацию при недоступном LLM-тире, отсутствие
утечки токенов в логах (grep по redaction).
