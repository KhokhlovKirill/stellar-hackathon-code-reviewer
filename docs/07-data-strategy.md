# 07 — Стратегия данных (mythos NewData / datasets)

Дообучать модель заново **не требуется** — `don-agent-v3` берём как есть. Данные mythos
используем для **доказательной базы**: golden-eval, синтез vulnerable-PR фикстур, few-shot,
регрессия. Это прямой ответ на критерии C2/C3 и на запрос организаторов о прозрачной
оценке (единый пул репозиториев они не дают — мы строим свой воспроизводимый набор).

## 1. Источники в mythos

| Путь | Что | Как используем |
|---|---|---|
| `model/training_data/full_corpus_extracted` (PrimeVul, 1 499) | пары **vulnerable/fixed** функций с CWE | Главный источник: из каждой пары синтезируем «PR, вносящий уязвимость» (fixed→vulnerable как diff) и «PR, который чинит» (vulnerable→fixed) → golden-set с известным ground-truth |
| PrimeVul + nuclei CVE templates (1 500) | CVE-паттерны | Доп. позитивы по классам inj/SSRF/deserialization; sanity для SCA-сигналов |
| PayloadsAllTheThings (140), WSTG (162), HackTricks (828) | техники эксплуатации/тест-кейсы | Few-shot экземпляры (curated, 2–4 шт.) и проверочные негативы |
| `NewData/AYI-NEDJIMI:cloud-security-en`, `cryptography_dataset_processed.csv` | cloud-misconfig / крипто-Q&A | Доп. классы: weak-crypto, IaC/cloud-misconfig фикстуры |
| `NewData/Containers_Dataset-combine-llm-security-bench.csv` | LLM security bench | Кросс-проверка анти-FP и prompt-injection устойчивости |
| mythos `eval_models.py`, `eval_results/` | харнесс/отчёты mythos | Образец воспроизводимого eval — переносим подход в `eval/` Aegis |

> Данные используются **только для eval/fixtures/few-shot**, не для обучения. Provenance
> фиксируется в каждом сгенерированном фикстуре (источник, CWE, исходная пара).

## 2. Генерация golden-set (`eval/build_golden.py`)

Из PrimeVul vulnerable/fixed пар:

1. Берём пару `(vuln_fn, fixed_fn, cwe)`.
2. **Positive case:** синтезируем unified-diff `fixed → vuln` (как будто PR вносит
   уязвимость) → ожидаемая находка: `{cwe, line=изменённая, severity}`. Ground-truth = 1.
3. **Negative case:** diff `vuln → fixed` (PR убирает уязвимость) и/или нейтральный
   рефактор → ожидаемо **0 находок**. Ground-truth = 0. Это ядро измерения FP.
4. Балансируем по классам, обязательная доля чистых diff (анти-FP) ≥ 40%.
5. Доп. ручные фикстуры под точные формулировки критериев: SQLi (f-string в `execute`),
   hardcoded secret (AWS-ключ/`.env`), reflected XSS (Flask/Express), плюс «не-код»
   файлы (README/.gitignore/png) для проверки C6.

Каждый кейс: `{id, provider_diff (github/gitlab/bitbucket payload), files, expected:[{file,line,cwe,severity}], expect_empty:bool, tags}`.

## 3. Few-shot для промпта

2–4 кураторских экземпляра «diff → JSON находок», включая обязательный
**negative** (безопасный diff → `{"findings": []}`). Берём из PrimeVul/WSTG, вручную
вычитываем (как mythos чистил синтетику `clean_synthetic_v2.py`). Few-shot замораживаются
и версионируются (`eval/fewshot/`), участвуют в регрессии.

## 4. Регрессионный гейт

`eval/run.py` гоняет golden-set по выбранному ensemble-профилю → precision/recall/F1/
FP-rate per-class + латентность + стоимость → `eval/results/<ts>.json` + сравнение с
baseline. CI-гейт: запрещает мерж, если F1 по SQLi/secret/XSS упал > δ или FP-rate вырос
> δ относительно зафиксированного baseline (принцип mythos «регрессионная защита»).

## 5. Что НЕ делаем

- Не тащим гигабайтные сырые файлы (`tool_calling.jsonl` 5.3GB, `interactive_agent.jsonl`)
  в репозиторий — из них только сэмплируем фикстуры скриптом с фиксированным seed.
- Не обучаем и не файнтюним в рамках этой задачи (опциональный roadmap «review.lora» на
  PrimeVul-as-diff — задокументирован в `14` как возможное усиление, вне scope текущего
  production-решения).
- Не используем benchmark test-split как train (его и не было — мы только eval).
