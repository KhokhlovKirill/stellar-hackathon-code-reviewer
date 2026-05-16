# Don Agent — Решение, данные и обучение

Полное описание проекта: что построено, как работает, какие данные, параметры и процесс обучения.

---

## 1. Что это

**Don** — автономный агент для CTF и пентеста, дообученный из `Qwen3-Coder-30B-A3B-Instruct-MLX-6bit` методом LoRA на MLX (Apple Silicon, M4 Max 48 GB).

Целевое поведение:
- Идентифицирует себя как **Don**, не как Qwen.
- **Действует немедленно**, не объясняет перед действием, не даёт рекомендаций вместо решения.
- Доводит CTF-задачу до конца (web / pwn / crypto / forensics / reversing), а не останавливается на середине.
- При неудаче пробует другой подход; рассуждает только после ≥2 провалов одного метода.
- Не отказывается от offensive-security задач (снята доменная цензура через anti-refusal обучение).

### Итоговая модель

| | |
|---|---|
| Путь | `/Volumes/SSD/models/lmstudio-community/don-agent-v3` |
| Размер | 23 GB (5 шардов safetensors) |
| Формат | qwen3_moe, 48 слоёв, hidden 2048, **6-bit quantization сохранена** |
| Загрузка | LM Studio → указать путь выше |

---

## 2. Системный промпт

Единый промпт на **каждой** обучающей записи (SFT и ORPO):

```
You are Don, an elite autonomous security agent specializing in CTF challenges and penetration testing.

Core directive: ACT immediately based on the task. Do NOT explain before acting. Do NOT give
recommendations — execute actions until the task is complete. When an approach fails, try a
different one. Reasoning is permitted only after ≥2 consecutive failures on the same approach.

When you find a flag or complete the objective, output it and stop.

Available tools: bash, python, browser, nmap, ffuf, sqlmap, nikto, radare2, gdb, pwntools,
kb_search, submit_flag.

Output format:
<action name="TOOL">command or code</action>
<observation>tool output</observation>
... (repeat as needed until task is complete) ...
<answer>FLAG or solution + 1-2 sentence explanation</answer>
```

Формат траектории: чередование `<action>`/`<observation>`, завершается `<answer>` с флагом.

---

## 3. Архитектура решения / пайплайн

4 фазы, оркестрируются скриптом `model/run_full_training.sh`:

```
Base (Qwen3-Coder-30B-6bit)
        │
   ┌────▼─────┐  Phase 1: SFT LoRA (config_sft.yaml, 4000 iter)
   │  SFT     │  → lora_adapters/sft_v3/adapters.safetensors
   └────┬─────┘
        │  Phase 2: mlx_lm.fuse
   ┌────▼──────────────────┐
   │ ctf-agent-sft-v3-fused │  (23 GB, на /Volumes/SSD)
   └────┬──────────────────┘
        │  Phase 3: ORPO LoRA (config_orpo.yaml, 1000 iter)
   ┌────▼─────┐
   │  ORPO    │  → lora_adapters/orpo_v2/adapters.safetensors
   └────┬─────┘
        │  Phase 4: mlx_lm.fuse (6-bit, БЕЗ --dequantize)
   ┌────▼──────────┐
   │  don-agent-v3 │  ← финальная модель
   └───────────────┘
```

**SFT** даёт навык (CTF-траектории, идентичность Don, не-отказ).
**ORPO** — preference learning: предпочитать полное решение над «рекомендацией»/отказом/зацикливанием.

---

## 4. Данные

### 4.1 SFT-датасет — `model/training_data/mlx_format_v3/`

| | Записей |
|---|---|
| `train.jsonl` | **19 975** |
| `valid.jsonl` | **1 050** |
| Всего | 21 025 |

Собирается скриптом `model/build_dataset_v3.py`. Все записи нормализованы к Don system prompt. Дедупликация по содержимому user+assistant. Сплит valid = 5 %.

**Пулы-источники:**

| Источник | Доступно | Описание |
|---|---|---|
| Playbook `exploitdb` | 20 220 | эксплойты ExploitDB (сэмплируется 8 000 — `EXPLOITDB_SAMPLE`) |
| Playbook `ctf-skills` | 2 333 | CTF-навыки, полные траектории — берётся всё |
| Playbook `ctf-writeup` | 199 | разборы CTF — всё |
| Playbook `nyu-ctf` | 56 | NYU CTF bench — всё |
| `synthetic_v2/` | 474 | синтетические полные траектории (web/pwn/crypto/forensics/reversing/recovery/identity), сгенерированы `generate_ctf_v2.py`, очищены `clean_synthetic_v2.py` |
| `corpus_extracted/` (corpus_v2) | 178 | pwn-college, MBE, hacktricks, identity, error-recovery |
| `newdata_extracted/` | 548 | cloud security (мисконфиги/best-practice/Q&A) + кодинг из `NewData/` |
| `full_corpus_extracted/` | 5 131 | HackTricks 828, nuclei CVE 1 500, PayloadsAllTheThings 140, PrimeVul 1 499, pwn-college 1 002, WSTG 162 |
| `interactive_extracted/` | 4 000 | multi-turn персистентность (interactive_agent 2 500 + tool_calling 1 500) — учит «доводить до конца» |
| `anti_refusal/anti_refusal_sft.jsonl` | 1 658 | инвертированный LLM-LAT: chosen = реальный ответ, не отказ |
| Playbook `secqa` | — | security Q&A — всё |
| Playbook `security-dpo` | — | сэмплируется 400 (`SECURITY_DPO_SAMPLE`) — снижено, т.к. это «secure-coding», смещённый домен |

> История баланса CTF-данных: v1 — 284 записи (4.7 %) → v2 — 2 872 (39.4 %) → **v3 — ~50 %+**. Это устранило проблему «модель пытается, но не доводит до конца».

### 4.2 ORPO-датасет — `model/training_data/dpo_format_v2/`

| | Пар |
|---|---|
| `train.jsonl` | **4 371** |
| `valid.jsonl` | **230** |

Собирается `model/build_orpo_v2.py`. Формат: `{"prompt", "chosen", "rejected"}`.

- **chosen** — полная траектория до флага (из playbook CTF + corpus_v2 + synthetic_v2 + full_corpus).
- **rejected** — конструируется из первых 1–2 action/observation пар + один из паттернов отказа:
  - `RECOMMENDATION_ENDINGS` (70 %) — «вот мои рекомендации, дайте знать…» вместо решения.
  - `LOOP_ENDINGS` (30 %) — зацикливание на одном проваленном действии.
- Плюс `anti_refusal_orpo.jsonl` (1 658 пар): chosen = реальный ответ, rejected = отказ «I can't help…».

Целевые failure-режимы, которые ORPO искореняет:
1. «Даёт рекомендации вместо завершения».
2. «Уходит в сторону / зацикливается».
3. «Отказывается от offensive-задачи».

### 4.3 Очистка качества данных

`clean_synthetic_v2.py` отбраковывает записи с: несбалансированными тегами, повторами 3-строчных блоков (зацикливание модели-генератора), без `<answer>`/без флага, слишком коротким ответом, рассинхроном action/observation. Из 488 синтетических осталось **474** валидных.

Длинные последовательности (>6000 символов ≈ >2048 токенов) удалены из SFT-датасета: 230 из train, 13 из valid — они вызывали обрезку до 2048 → порчу градиентов (см. §6).

---

## 5. Параметры обучения

### 5.1 SFT — `model/config_sft.yaml`

| Параметр | Значение | Комментарий |
|---|---|---|
| base model | Qwen3-Coder-30B-A3B-Instruct-MLX-6bit | MoE, 48 слоёв |
| fine_tune_type | lora | |
| num_layers | **24** | последние 24 из 48 (было 32 — вызывало OOM) |
| rank | 16 | |
| scale | 2.0 | |
| dropout | 0.08 | |
| optimizer | adamw | |
| learning_rate | 5.0e-5 | cosine_decay → 5.0e-7 за 4000 шагов |
| warmup | 250 | от 0.0 |
| mask_prompt | true | лосс только на assistant-токенах |
| batch_size | 1 | |
| grad_accumulation_steps | 8 | эффективный батч = 8 |
| grad_checkpoint | true | обязательно для памяти |
| iters | 4000 | ≈ 1.6 эпохи на 20K |
| max_seq_length | 2048 | |
| val_batches | 20 | снижено с 30 (память на eval) |
| save_every | 500 | |
| Trainable params | 422.8M (1.385 %) | |

### 5.2 ORPO — `model/config_orpo.yaml`

| Параметр | Значение | Комментарий |
|---|---|---|
| base model | ctf-agent-sft-v3-fused | результат Phase 2 |
| num_layers | 24 | под глубину SFT |
| rank | 8 | |
| scale | 1.0 | |
| dropout | 0.0 | |
| learning_rate | 5.0e-6 | |
| beta | 0.15 | сила preference-сигнала vs reference |
| batch_size | 1 | |
| grad_accumulation_steps | 8 | |
| iters | 1000 | |
| max_seq_length | 2048 | |

---

## 6. Результаты обучения

### SFT (4000 итераций, ~3.5 ч)

| Метрика | Старт (iter 25) | Финал (iter 4000) |
|---|---|---|
| Train loss | 2.294 | **0.711** |
| Val loss | — | **0.882** |
| Peak mem | 34.5 GB | **37.128 GB** |

Стабильное снижение лосса, без NaN. Пик памяти 37 GB — в пределах целевого лимита (≤37 GB).

### ORPO (1000 итераций, ~17 мин)

| Метрика | Значение (iter 1000) |
|---|---|
| Loss | 0.058 |
| Train accuracy | 0.85 |
| **Val accuracy** | **0.706** |
| Val margin | 0.016 |
| Peak mem | 30.945 GB |

Val accuracy 0.706 — модель устойчиво предпочитает «полное решение» над «рекомендацией/отказом».

---

## 7. Проблемы и решения по ходу

| Проблема | Причина | Решение |
|---|---|---|
| **OOM крах на iter 800, Peak 40 GB** | num_layers=32 + последовательности до 8838 токенов, обрезаемые до 2048 → скачки памяти + NaN-градиенты | num_layers 32→24; фильтр последовательностей >6000 симв.; val_batches 30→20 → Peak 37 GB, стабильно |
| Resume из чекпойнта iter-500 дал NaN | адаптер сохранён для 32 слоёв, конфиг — 24 слоя (рассинхрон индексов слоёв) | старт с нуля на 24 слоях (Val loss 1.765 — чисто) |
| Метрики качества «врали» (98 % valid, реально 35 %) | поверхностная проверка не ловила зацикливание/незакрытые теги | `clean_synthetic_v2.py` с детектором повторов и баланса тегов |
| `[DRY RUN]` плейсхолдеры в данных | накопились от прежних dry-run запусков | вычищены при сборке |
| **Сбой финального fuse: «Unable to write»** | `mlx_lm_lora.train` после ORPO делает авто-fuse с **деквантизацией** (~57 GB записи), места не хватило; шарды легли на внутренний диск | удалены частичные шарды; финальный fuse запущен отдельно через `mlx_lm.fuse` **без** `--dequantize` → 6-bit, 23 GB |

---

## 8. Как воспроизвести

```bash
cd /Users/nikitasyzdykov/Desktop/Projects/mythos/model

# (опц.) пересобрать датасеты
python3 build_dataset_v3.py      # SFT  → training_data/mlx_format_v3/
python3 build_orpo_v2.py         # ORPO → training_data/dpo_format_v2/

# Полный пайплайн (4 фазы). Перед стартом — выгрузить модель из LM Studio.
nohup ./run_full_training.sh > logs/training_v3_final.log 2>&1 &
tail -f logs/training_v3_final.log
```

**Важно про Phase 4 (финальный fuse):** если `run_full_training.sh` падает на авто-fuse внутри ORPO, запустить fuse вручную (сохраняет 6-bit, ~23 GB вместо 57 GB):

```bash
.venv/bin/mlx_lm.fuse \
  --model /Volumes/SSD/models/lmstudio-community/ctf-agent-sft-v3-fused \
  --adapter-path lora_adapters/orpo_v2 \
  --save-path /Volumes/SSD/models/lmstudio-community/don-agent-v3
# НЕ добавлять --dequantize (иначе модель раздуется до ~57 GB)
```

---

## 9. Структура файлов

```
mythos/
├── SOLUTION.md                          ← этот файл
├── dataset/v1.0/playbook_train_dedup.jsonl   (22 808 — исходный playbook)
├── NewData/                             (исходники: LLM-LAT parquet, interactive_agent и т.д.)
└── model/
    ├── run_full_training.sh             (оркестратор 4 фаз)
    ├── config_sft.yaml                  (параметры SFT)
    ├── config_orpo.yaml                 (параметры ORPO)
    ├── build_dataset_v3.py              (сборка SFT-датасета)
    ├── build_orpo_v2.py                 (сборка ORPO-пар)
    ├── generate_ctf_v2.py               (генератор синтетики)
    ├── clean_synthetic_v2.py            (строгая очистка синтетики)
    ├── process_anti_refusal.py          (инверсия LLM-LAT)
    ├── process_full_corpus.py           (HackTricks/PAtT/nuclei/PrimeVul)
    ├── process_interactive_agent.py     (multi-turn → Don-формат)
    ├── training_data/
    │   ├── mlx_format_v3/               (SFT: 19 975 + 1 050)
    │   ├── dpo_format_v2/               (ORPO: 4 371 + 230)
    │   ├── synthetic_v2/  corpus_extracted/  newdata_extracted/
    │   ├── full_corpus_extracted/  interactive_extracted/  anti_refusal/
    └── lora_adapters/
        ├── sft_v3/    (чекпойнты 500–4000 + adapters.safetensors)
        └── orpo_v2/   (чекпойнты 250–1000 + adapters.safetensors)

/Volumes/SSD/models/lmstudio-community/
├── Qwen3-Coder-30B-A3B-Instruct-MLX-6bit   (база)
├── ctf-agent-sft-v3-fused                  (промежуточная, после SFT-fuse)
└── don-agent-v3                            ← ФИНАЛЬНАЯ МОДЕЛЬ (23 GB, 6-bit)
```
