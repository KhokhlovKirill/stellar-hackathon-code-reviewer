# Backend Specification — Aegis DevSecOps Bot

> **Статус:** Production-final. Не MVP. Каждый раздел описывает финальное поведение системы.
> Синтез: ТЗ DevSecOps + ClaudeSonnet4.6 + Gemini3.1Pro + ChatGPT DeepResearch + docs/01–14.

---

## 0. Решения, принятые по AdditionalData

| Фича из AdditionalData | Решение | Обоснование |
|---|---|---|
| **Risk Score 0–100** | ✅ Принять полностью | Даёт числовой gate для авто-блокировки и dashboard; веса из ТЗ |
| **Smart Context Window ±50** | ✅ Принять | Снижает FP; контекст нужен для тайн-анализа |
| **Code RAG / AST** | ✅ Принять (Python/JS/TS приоритет) | Кардинально снижает FP на multi-file taint; реализуется через tree-sitter |
| **Autofix PR** | ✅ Принять (secret→.env, dep bump) | Killer-фича; реализуется через provider API |
| **ChatOps @secbot** | ✅ Принять все 5 команд | Требование C7 + killer-фича |
| **PoC exploit snippet** | ✅ Принять (только для SQLi/XSS/SSTI) | LLM генерирует curl/python PoC для доказательства |
| **Retro-scan** | ✅ Принять | Команда `@secbot scan full` + кнопка в UI |
| **FP-learning** | ✅ Принять (3 отметки → auto-suppression) | Адаптивность; хранится в PostgreSQL |
| **Knowledge Base (pgvector)** | ✅ Принять | Добавить `pgvector` extension; семантический поиск похожих находок |
| **Blast Radius (Mermaid)** | ✅ Принять | Генерируется только при SCA-находках; через import-граф |
| **Bandit (Python)** | ✅ Принять | Добавить к Semgrep как язык-специфичный детектор |
| **Gitleaks** | ✅ Принять как альтернативу | Легковеснее TruffleHog; запускается на diff, до LLM |
| **Celery** | ❌ Заменён на Arq | Arq native-async, меньше deps, та же Redis-очередь; Celery = sync overhead |
| **LLM: Claude/GPT/Qwen** | ✅ Через OpenRouter + LM Studio | OpenRouter абстрагирует cloud-провайдеров; локально работают SFT+ORPO security-модель и Qwen 3.6 35B A3B 4-bit MLX |
| **Frontend React+TS** | ✅ Отдельный микросервис | Backend отдаёт REST API; фронт описан кратко (не backend scope) |

---

## 1. Общее описание

Aegis — микросервис на **Python 3.12 / FastAPI (async)**, который:
1. Принимает вебхуки от GitHub / GitLab / Bitbucket
2. Извлекает только изменённый diff (не весь репозиторий)
3. Запускает детерминированный анализ (secrets + Semgrep + Bandit + SCA)
4. Расширяет контекст (Smart Context Window ±50 строк + Code RAG via tree-sitter)
5. Отправляет в LLM-ансамбль (локальная SFT+ORPO security-модель + OpenRouter/local-base → judge)
6. Вычисляет Risk Score
7. Публикует inline-комментарии с PoC, fix-snippet, Blast Radius
8. Применяет merge policy (block при Risk Score > 60 или critical)
9. Создаёт autofix PR при hardcoded secret / уязвимой зависимости
10. Поддерживает ChatOps-диалог (@secbot команды)
11. Обучается на FP-отметках команды

---

## 2. Технологический стек

```
Python 3.12
FastAPI 0.115           — webhook gateway + admin REST API
SQLAlchemy 2.x async    — ORM
Alembic                 — миграции
PostgreSQL 16 + pgvector — хранение + Knowledge Base
Redis 7                 — idempotency, queue, dialog session, diff cache
Arq                     — async job queue (замена Celery; native asyncio)
httpx                   — async HTTP к VCS и LLM API
structlog               — JSON structured logging (без PII)
Prometheus + Grafana    — метрики
Semgrep CLI             — SAST (offline ruleset в образе)
Bandit                  — Python-специфичный SAST
Gitleaks CLI            — secret scan (diff-only, до LLM)
tree-sitter             — AST парсинг для Code RAG (Python, JS, TS, Go)
cryptography (Fernet)   — vault для токенов
JWT (python-jose)       — авторизация Admin Portal
Docker + Docker Compose — упаковка и локальный запуск
```

---

## 3. Модульная архитектура

```
aegis/
  api/
    webhooks.py       — POST /webhooks/{provider}  [C1]
    admin.py          — REST API для Portal
    auth.py           — JWT login/refresh
  pipeline/
    runner.py         — оркестратор стадий
    state.py          — PipelineState (единый контекст через стадии)
    filter.py         — C6: фильтрация файлов
    context.py        — Smart Context Window + Code RAG  [NEW]
    deterministic/
      secrets.py      — regex + Shannon entropy (C3)
      gitleaks.py     — Gitleaks CLI wrapper  [NEW]
      bandit.py       — Bandit wrapper  [NEW]
      semgrep.py      — Semgrep wrapper (C3)
      sca.py          — OSV.dev SCA (C3)
    deterministic_stage.py
    llm_stage.py      — LLM ensemble orchestrator  (Phase 4-5)
    risk_score.py     — Risk Score 0-100  [NEW]
    render.py         — inline comments + summary (C4, C5)  (Phase 6)
    policy.py         — merge block (C8)  (Phase 6)
    autofix.py        — autofix PR creator  [NEW]  (Phase 6)
    blast_radius.py   — Mermaid Blast Radius  [NEW]  (Phase 6)
  llm/
    router.py         — tier selection + fallback
    tier_local.py     — don-agent-v3 via LM Studio
    tier_openrouter.py— OpenRouter (cloud)
    prompt.py         — prompt builder
    parser.py         — JSON response parser + repair
  dialog/
    handler.py        — ChatOps command dispatch  (Phase 7)
    commands.py       — @secbot commands  (Phase 7)
    session.py        — Redis session (context window)
  knowledge/
    kb.py             — pgvector store + search  [NEW]  (Phase 8)
  retro/
    scanner.py        — @secbot scan full  [NEW]  (Phase 8)
  providers/
    base.py, github.py, gitlab.py, bitbucket.py
    diffparse.py, signatures.py
  admin/
    portal.py         — repo registration API  (Phase 8)
  db/
    models.py, session.py, alembic/
  worker/main.py      — Arq worker entrypoint
  vault.py, repos.py, config.py, errors.py
  idempotency.py, queue.py, redispool.py
  tokenest.py, obs/
```

---

## 4. Webhook Gateway — детальная спецификация

**POST /webhooks/{provider}**

```
Провайдеры: github | gitlab | bitbucket
```

### 4.1 Порядок операций (security-critical)

```
1. Прочитать raw body (лимит: config.service.max_webhook_body_bytes = 5MB)
2. Проверить Content-Type (application/json)
3. JSON-parse (400 на ошибку)
4. parse_event(headers, payload) → WebhookEvent (no side effects)
   ↳ При WebhookPayloadError: verify с env-секретом → 202 ignored
5. webhook_secret(provider, repo_external_id) — per-repo vault или env
6. verify(provider, raw_body, headers, secret)
   ↳ При ошибке: 401 + метрика webhooks_total{sig_ok=false}
7. Проверить ev.kind:
   IGNORED  → 202 {"status":"ignored"}
   COMMENT  → enqueue_dialog, 202 {"status":"queued","kind":"dialog"}
   PR_OPENED|PR_UPDATED →
     8. idempotency.claim(ev.dedupe_key()) — False → 202 {"status":"duplicate"}
     9. scan_id = uuid4().hex
    10. INSERT Scan(status=queued)
    11. enqueue_scan(scan_id, ev)   [сохранить event JSON в Redis ex=86400]
    12. 202 {"status":"queued","scan_id":"..."}
```

**SLA:** ответ < 300ms (вся обработка async, тяжёлая работа в worker)

### 4.2 Верификация подписи

| Провайдер | Метод | Заголовок |
|---|---|---|
| GitHub | HMAC-SHA256 | `X-Hub-Signature-256` |
| GitLab | Shared token | `X-Gitlab-Token` |
| Bitbucket | HMAC-SHA256 или shared | `X-Hub-Signature` / `X-Aegis-Secret` |

Сравнение через `hmac.compare_digest` (constant-time, анти-timing-attack).

---

## 5. Scan Pipeline — детальная спецификация

### 5.1 Стадии и контракт

```
runner.run_scan_pipeline(scan_id)
  │
  ├─ load_event(scan_id)              ← Redis
  ├─ is_stale() check                 ← отмена устаревших сканов
  ├─ resolve(provider, repo, slug)    ← repo context + access token
  ├─ provider.fetch_pull_request()    ← title, SHAs, branches
  ├─ provider.fetch_diff()            ← ТОЛЬКО изменённые файлы (C2)
  │
  ├─ STAGE: filter.apply_filter()     ← C6
  │    · deleted / binary / non-code / ignore-glob / too-large / generated
  │    · manifests → state.manifest_files (SCA)
  │    · code_files → state.code_files (analysis)
  │
  ├─ STAGE: context.enrich_context()  ← Smart Context Window + Code RAG
  │    · ±50 строк вокруг каждого hunk через provider.get_file_content()
  │    · tree-sitter: resolve called functions → pull body from file
  │    · результат: state.context_map {path: enriched_text}
  │
  ├─ STAGE: deterministic_stage.run_deterministic()  ← C3
  │    · gitleaks on diff (binary, fast)
  │    · secrets (regex + Shannon entropy) on added lines
  │    · semgrep on full changed files (filter to changed lines)
  │    · bandit on Python files
  │    · sca (OSV.dev batch) on manifests
  │    · persist FindingRow rows
  │
  ├─ STAGE: llm_stage.run_llm_analysis()  ← C3, C4, C5
  │    · build prompt (diff + context + det findings + language + framework)
  │    · tier 1: don-agent-v3 local (LM Studio)
  │    · tier 2: OpenRouter (fallback / judge)
  │    · parse JSON response + repair
  │    · dedup with deterministic findings
  │    · anti-FP: suppress if matches team suppression patterns
  │    · persist
  │
  ├─ STAGE: risk_score.compute()
  │    · weighted sum по типам находок
  │    · итог 0–100 + traffic light label
  │
  ├─ STAGE: blast_radius.generate()   ← при SCA-находках
  │    · import-граф из AST
  │    · Mermaid-диаграмма → state.blast_radius_mermaid
  │
  ├─ STAGE: render.render_and_post()  ← C4, C5
  │    · inline-комментарии с {title, CWE, exploit-PoC, fix snippet}
  │    · summary-комментарий: Risk Score (🟢🟡🔴), breakdown, blast radius
  │
  ├─ STAGE: policy.apply_merge_policy()  ← C8
  │    · Risk Score > threshold OR critical finding → block merge
  │    · Status check: aegis/security-gate = failure
  │
  └─ STAGE: autofix.create_autofix_pr()  ← killer-фича
       · hardcoded secret → PR: секрет в .env, .env.example обновлён
       · уязвимая dep → PR: version bump до patched
```

**PipelineState** — единый mutable объект, передаётся через все стадии:

```python
@dataclass
class PipelineState:
    scan_id: str
    ev: WebhookEvent
    pr: PullRequest
    ctx: RepoContext
    result: ScanResult
    files: list[FileChange]           # все изменённые
    code_files: list[FileChange]      # после filter
    manifest_files: list[FileChange]  # для SCA
    context_map: dict[str, str]       # path → enriched context text
    findings: list[Finding]           # накапливается
    risk_score: int                   # 0-100
    risk_label: str                   # green/yellow/red
    blast_radius_mermaid: str | None
    posted_refs: list[str]            # VCS comment IDs
```

---

## 6. Smart Context Window + Code RAG

### 6.1 Smart Context Window

Для каждого hunk в каждом code_file:
```
GET /repos/{slug}/contents/{path}?ref={head_sha}
→ полный текст файла
→ вырезать [hunk.new_start - 50 : hunk.new_start + hunk.new_count + 50]
→ добавить в context_map[path]
```

**Зачем:** LLM видит вызов функции в изменённой строке, но без тела функции → FP.
С контекстом → FP снижается на ~40% (по данным Semgrep research).

### 6.2 Code RAG via tree-sitter

```
Поддерживаемые языки: Python, JavaScript/TypeScript, Go
Алгоритм:
  1. parse file AST via tree-sitter
  2. для каждой добавленной строки: найти function calls
  3. для каждого call: resolve в том же файле
     → если найден: добавить тело функции в context
  4. если не найден в файле: попытаться resolve через imports
     → fetch referenced file → extract function body
  5. limit: max 2000 tokens добавленного контекста на файл
```

**Зачем:** "Blind spot" — атака через обёртку. `process(user_input)` безопасна в diff,
но `process()` содержит `eval()`. Без Code RAG → FN. С RAG → детектируется.

---

## 7. Risk Score

### 7.1 Веса

| Тип уязвимости | Вес |
|---|---|
| SQL Injection (CWE-89) | +40 |
| Hardcoded secret / credential (CWE-798) | +35 |
| XSS (CWE-79) | +30 |
| SSTI, SSRF, RCE (CWE-94/918/78) | +35 |
| Path Traversal (CWE-22) | +25 |
| Insecure Deserialization (CWE-502) | +30 |
| Vulnerable dependency (CVE known) | +15 |
| Hardcoded cryptographic key (CWE-321) | +30 |
| High-entropy token (probable credential) | +20 |
| Other medium Semgrep/Bandit finding | +10 |
| Other low/info finding | +5 |

Итог: `min(sum_of_weights, 100)`. Risk Score ≠ count; повторные одного типа
накапливаются, но не больше порога насыщения (cap per type = weight × 2).

### 7.2 Traffic Light

| Risk Score | Label | Действие |
|---|---|---|
| 0–30 | 🟢 LOW RISK | Одобряющий комментарий |
| 31–60 | 🟡 MEDIUM RISK | Предупреждение, merge разрешён |
| 61–100 | 🔴 HIGH RISK | Merge заблокирован (C8) |
| Любой CRITICAL | 🔴 CRITICAL | Merge заблокирован немедленно |

---

## 8. LLM-модуль

### 8.1 Стратегия тиров

```
Tier 1 (LOCAL SECURE): don-agent-v3 / Qwen3-Coder-30B-A3B SFT+ORPO via LM Studio API
  · Плюсы: бесплатно, data never leaves infra, fine-tuned на security/CTF
  · Минусы: доступен только на Mac M4 Max (dev/demo); SSD должен быть подключён
  · Роль: detector_a (первичный анализ)

Tier 1b (LOCAL BASE): Qwen 3.6 35B A3B 4-bit MLX via LM Studio API
  · Плюсы: независимый локальный генералист без отправки кода наружу
  · Минусы: конкурирует за unified memory; при одновременной загрузке моделей нужен health-based routing
  · Роль: detector_b / fallback judge в degraded cloud-сценарии

Tier 2 (CLOUD): OpenRouter
  · Модели в порядке приоритета:
      qwen/qwen3-coder-30b (через OpenRouter)
      google/gemini-2.0-flash (fast fallback)
      anthropic/claude-3-5-sonnet (judge / качество)
  · Роль: detector_b + judge

Fallback: если Tier 1 недоступен → Tier 2
         если оба недоступны → deterministic only (degraded mode)
```

### 8.2 Health probe

```python
async def probe_local() -> bool:
    try:
        r = await httpx.post(LM_STUDIO_URL + "/v1/models", timeout=3)
        return r.status_code == 200
    except:
        return False
```

Probe выполняется при старте worker и каждые 60s (кэшируется).
Результат влияет на tier selection в `router.select_tier()`.

### 8.3 Prompt — финальная структура

```
[SYSTEM]
You are Aegis, an elite production security code reviewer.

STRICT RULES:
- Analyze ONLY the provided git diff and context
- Report ONLY confirmed, exploitable vulnerabilities
- NEVER flag: test mock data, commented code, documentation, placeholder values
- For EACH finding output JSON with ALL fields
- If no vulnerabilities: {"findings": []}
- No markdown, no preamble, ONLY valid JSON

CONTEXT:
  Language: {language}
  Framework: {framework}
  File: {file_path}
  Static analysis pre-scan: {det_findings_summary}

[USER]
DIFF:
{diff_chunk}

CONTEXT (±50 lines around changes):
{context_window}

REFERENCED FUNCTIONS (Code RAG):
{code_rag}

Respond with JSON:
{
  "findings": [
    {
      "file": "path/to/file.py",
      "line": 42,
      "severity": "critical|high|medium|low",
      "cwe": "CWE-89",
      "title": "SQL Injection via string concatenation",
      "rationale": "...",
      "exploit": "curl -X POST ... --data \"id=' OR 1=1--\"",
      "fix": "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
      "confidence": 0.95
    }
  ]
}
```

### 8.4 JSON repair

При невалидном JSON от LLM:
1. Попытка `json.loads()`
2. При ошибке: `json_repair.repair(raw)` (lib json-repair)
3. При второй ошибке: retry запрос с добавлением `"Return ONLY valid JSON:"`
4. После 2 retry: логировать `llm.json_parse_failed` + пропустить LLM findings (deterministic остаются)

### 8.5 Anti-FP механизм

```python
def should_suppress(finding: Finding, suppressions: list[Suppression]) -> bool:
    for s in suppressions:
        if fnmatch(finding.file, s.path_glob) and finding.rule_id == s.rule_id:
            return True  # team-specific suppression
    # Global: никогда не флагировать test-файлы как critical
    if finding.severity == "critical" and is_test_file(finding.file):
        return False  # разрешить medium/high для тестов, но не critical
    return False
```

---

## 9. Deterministic Layer — детальная спецификация

### 9.1 Порядок запуска

```
1. Gitleaks     — быстрый, бинарный, на raw diff (subprocess, < 2s)
2. secrets.py   — regex patterns + Shannon entropy (pure Python, < 0.1s)
3. Semgrep      — SAST на полных файлах (subprocess, 5-30s, зависит от языка)
4. Bandit       — Python SAST (subprocess, 2-10s)
5. SCA          — OSV.dev batch HTTP (async, 1-3s)
```

Все запускаются параллельно за исключением Gitleaks (он должен завершиться до
отправки в LLM — данные с секретами не должны покидать машину).

### 9.2 Gitleaks

```bash
gitleaks detect --source . --no-git --report-format json --report-path /tmp/gl.json
```

Запускается на временной директории с patch-файлом diff.
Результат: list[Finding] с severity=CRITICAL, source=DETERMINISTIC.

### 9.3 Bandit

```bash
bandit -r {tmpdir} -f json -o /tmp/bandit.json --severity-level medium
```

Только Python файлы. Findings фильтруются: только те строки, что в `added_lines()`.

### 9.4 SCA + Blast Radius

```
1. Parse manifests (requirements.txt, package.json, go.mod, Cargo.toml, pom.xml)
   → extract (ecosystem, package, version) tuples
2. POST https://api.osv.dev/v1/querybatch
   → получить список vulns per package
3. GET https://api.osv.dev/v1/vulns/{id}
   → получить fixed_version
4. Finding: severity=HIGH, CWE=CWE-1395, fix="upgrade X to Y"
5. При нахождении уязвимой библиотеки:
   → blast_radius.build_import_graph(repo_files, library_name)
   → генерировать Mermaid flowchart
```

### 9.5 Blast Radius Mermaid

```python
def generate_blast_radius(lib: str, modules: list[str]) -> str:
    lines = ["```mermaid", "flowchart TD", f'  LIB["{lib} ⚠️ VULNERABLE"]']
    for m in modules[:10]:  # max 10 для читаемости
        safe = m.replace("/", "_").replace(".", "_")
        lines.append(f'  {safe}["{m}"] --> LIB')
    lines.append("```")
    return "\n".join(lines)
```

---

## 10. Render & Comments — детальная спецификация

### 10.1 Inline-комментарий на строку

```markdown
<!-- aegis:finding:{fingerprint} -->
**[🔴 CRITICAL] SQL Injection (CWE-89)**

**Файл:** `app/db.py:42`
**Обнаружен:** Semgrep + LLM (consensus)
**Уверенность:** 97%

**Проблема:**
Пользовательский ввод `user_id` конкатенируется в SQL-запрос без параметризации.

**Proof of Concept:**
```bash
curl -X POST /api/users \
  --data "id=1' OR '1'='1" \
  -H "Content-Type: application/x-www-form-urlencoded"
# → возвращает всех пользователей БД
```

**Исправление:**
```python
# До:
query = "SELECT * FROM users WHERE id=" + user_id
# После:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Ссылки:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
```

### 10.2 Summary-комментарий

```markdown
## 🔴 Aegis Security Review — Risk Score: 78/100

| Уровень | Количество |
|---------|-----------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 3 |
| 🔵 Low | 1 |

**Score breakdown:** SQLi +40, Hardcoded token +35, Outdated dep +15 = 90 → cap 78

**Merge:** 🚫 ЗАБЛОКИРОВАН (Risk Score > 60)

**Файлы проанализированы:** 4 из 7 (3 пропущено: README.md, package-lock.json, image.png)

**Blast Radius:**
{mermaid_diagram_here}

---
*Aegis v1.0 | Scan ID: abc123 | Время: 12.3s | Токены diff: ~2400 (сохранено: ~180K)*
*Найдено что-то подозрительное? Напишите `@secbot why` под конкретным комментарием.*
```

### 10.3 Provider API — публикация

**GitHub:**
```
POST /repos/{owner}/{repo}/pulls/{pr}/reviews
{
  "commit_id": "{head_sha}",
  "event": "REQUEST_CHANGES",  // при critical/high
  "body": "{summary}",
  "comments": [
    {
      "path": "app/db.py",
      "position": {diff_position},
      "body": "{inline_comment}"
    }
  ]
}
```

**GitLab:**
```
POST /projects/{id}/merge_requests/{iid}/discussions
{
  "body": "{inline_comment}",
  "position": {
    "position_type": "text",
    "base_sha": "{base_sha}",
    "head_sha": "{head_sha}",
    "new_path": "app/db.py",
    "new_line": 42
  }
}
```

**Bitbucket:**
```
POST /repositories/{slug}/pullrequests/{id}/comments
{
  "content": {"raw": "{inline_comment}"},
  "inline": {"to": 42, "path": "app/db.py"}
}
```

### 10.4 Merge Policy

**GitHub:** Создать статус-чек через Checks API или Commit Status API:
```
POST /repos/{slug}/statuses/{sha}
{ "state": "failure", "context": "aegis/security-gate",
  "description": "Critical vulnerabilities found. See PR comments." }
```
При `require_status_checks` на protected branch → merge физически заблокирован.

**GitLab:** Использовать external status check API (GitLab EE) или
MR approval rules (бот отклоняет через `POST /merge_requests/{iid}/approve` с `REJECT`).
Для CE: оставить комментарий с чётким "🚫 DO NOT MERGE" и Request Changes.

**Bitbucket:** `POST /pullrequests/{id}/decline` при CRITICAL.

---

## 11. ChatOps — детальная спецификация

Бот отслеживает комментарии, начинающиеся с `@secbot` (или `@aegis`).
Все команды идут в отдельную Arq-очередь (`run_dialog`).

### 11.1 Команды

| Команда | Действие |
|---|---|
| `@secbot why [is this X]?` | Объяснить находку из текущего треда + сгенерировать PoC |
| `@secbot explain [how X works]` | Описать механизм атаки для типа уязвимости |
| `@secbot false positive` | Записать FP в БД; при 3+ → auto-suppression |
| `@secbot ignore [path/pattern]` | Добавить glob в per-repo ignore list |
| `@secbot scan full` | Поставить в очередь retro-scan всего репозитория |
| `@secbot status` | Ответить текущим Risk Score и статусом скана |
| `@secbot fix` | Создать autofix PR (если ещё не создан) |

### 11.2 Контекст диалога

```
Redis key: aegis:dialog:{provider}:{repo}:{pr_id}:{thread_id}
TTL: 7 дней
Value: JSON list[{role, content}]  — история для LLM
Max messages: 20 (скользящее окно)
```

Каждый ответ бота добавляет в историю. При следующем обращении история
передаётся в LLM как system context: "Previous conversation: ..."

### 11.3 FP Learning

```python
# При команде @secbot false positive:
INSERT INTO false_positives (
  repo_id, fingerprint, rule_id, path_glob, count
) VALUES (...) ON CONFLICT (repo_id, fingerprint) DO UPDATE SET count = count + 1

# При count >= 3:
INSERT INTO repo_suppressions (repo_id, rule_id, path_glob)

# При следующем скане:
SELECT * FROM repo_suppressions WHERE repo_id = ?
→ применяется в anti_fp.should_suppress()
```

---

## 12. Autofix PR — детальная спецификация

### 12.1 Hardcoded Secret → .env migration

```python
async def create_secret_fix_pr(pr: PullRequest, finding: Finding, token: str):
    # 1. Получить полный файл
    content = await provider.fetch_file(pr, token, finding.file)
    # 2. Выделить имя переменной из finding
    var_name = extract_var_name(finding.rationale)  # e.g. "API_KEY"
    # 3. Заменить значение на env lookup
    fixed = content.replace(
        finding_raw_line,
        f'{var_name} = os.environ.get("{var_name}")'
    )
    # 4. Добавить import os если нет
    # 5. Создать/дополнить .env.example
    env_example = f'{var_name}=your_{var_name.lower()}_here\n'
    # 6. Создать ветку "aegis/fix-{scan_id[:8]}"
    await provider.create_branch(pr, token, f"aegis/fix-{scan_id[:8]}")
    # 7. Push changes
    await provider.update_file(pr, token, finding.file, fixed)
    await provider.create_file(pr, token, ".env.example", env_example)
    # 8. Create PR
    fix_pr_url = await provider.create_pull_request(
        pr, token,
        title=f"[Aegis] Fix: move hardcoded secret to .env",
        body=f"Auto-generated fix for finding in #{pr.pr_number}.\n\nRotate the exposed credential immediately."
    )
```

### 12.2 Vulnerable Dep → Version Bump

```python
async def create_dep_fix_pr(pr: PullRequest, finding: Finding, fixed_version: str, token: str):
    manifest_path = finding.file
    content = await provider.fetch_file(pr, token, manifest_path)
    updated = bump_version(content, finding.package_name, fixed_version)
    await provider.create_branch(...)
    await provider.update_file(pr, token, manifest_path, updated)
    await provider.create_pull_request(
        title=f"[Aegis] Fix: upgrade {finding.package_name} to {fixed_version}"
    )
```

---

## 13. Retro-Scan — детальная спецификация

Запускается через `@secbot scan full` или кнопку в UI.

```
1. Получить список всех файлов репозитория через provider API
   (GitHub: GET /repos/{slug}/git/trees/{sha}?recursive=1)
2. Фильтровать: только code files (не md, не lock, не images)
3. Разбить на батчи по 20 файлов
4. Для каждого батча:
   a. Скачать полное содержимое файлов (batch API)
   b. Запустить Semgrep + Bandit + secrets (без LLM — экономия токенов)
5. Агрегировать все находки
6. Запустить LLM только на TOP-20 самых подозрительных файлов
   (по количеству детерминированных находок)
7. Сформировать Summary Report (markdown)
8. Сохранить отчёт в БД (retro_scans table)
9. Опционально: создать Issue в репозитории со Summary Report
```

**Ограничения:**
- Max 500 файлов на retro-scan (конфигурируемо)
- Timeout: 10 минут
- Прогресс-обновления каждые 30s через database polling (UI показывает процент)

---

## 14. Knowledge Base (pgvector)

### 14.1 Схема

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE kb_findings (
  id SERIAL PRIMARY KEY,
  fingerprint VARCHAR(64) UNIQUE,
  repo_slug VARCHAR(255),
  pr_number INT,
  file VARCHAR(512),
  cwe VARCHAR(16),
  severity VARCHAR(16),
  title TEXT,
  rationale TEXT,
  fix TEXT,
  code_snippet TEXT,
  embedding VECTOR(1536),   -- text-embedding-3-small или local model
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON kb_findings USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 100);
```

### 14.2 Использование

При каждой новой находке:
1. Embed `{cwe}: {title}\n{rationale}` → vector
2. `SELECT * FROM kb_findings ORDER BY embedding <-> $1 LIMIT 3`
3. Если cosine similarity > 0.85 → добавить в summary:
   > "⚡ Похожая уязвимость (CWE-89) уже встречалась в PR #142 (app/auth.py) 3 недели назад."
4. INSERT новой находки в kb_findings

**Embedding model:** локально через Ollama (nomic-embed-text) или OpenRouter (text-embedding-3-small).
Fallback: SHA256-based exact match без embedding.

---

## 15. База данных — полная схема

```sql
-- Репозитории (Portal)
CREATE TABLE repositories (
  id SERIAL PRIMARY KEY,
  provider VARCHAR(16) NOT NULL,        -- github|gitlab|bitbucket
  external_id VARCHAR(255) NOT NULL,
  slug VARCHAR(255) NOT NULL,
  status VARCHAR(16) DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uq_repo_provider_extid UNIQUE(provider, external_id)
);

-- Зашифрованные секреты репозиториев
CREATE TABLE repo_secrets (
  id SERIAL PRIMARY KEY,
  repo_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  kind VARCHAR(32) NOT NULL,            -- access_token|webhook_secret
  ciphertext TEXT NOT NULL,             -- Fernet encrypted
  created_at TIMESTAMPTZ DEFAULT NOW(),
  rotated_at TIMESTAMPTZ
);

-- Политики репозитория
CREATE TABLE repo_policies (
  repo_id INT PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
  severity_gate VARCHAR(16) DEFAULT 'medium',  -- min severity для комментария
  merge_block VARCHAR(16) DEFAULT 'critical',  -- блокировать merge при severity >=
  risk_score_block INT DEFAULT 60,             -- блокировать при Risk Score >
  ignore_globs JSONB DEFAULT '[]',
  ensemble_profile VARCHAR(32) DEFAULT 'det+don+judge',
  lang VARCHAR(4) DEFAULT 'ru',
  prompt_overrides JSONB DEFAULT '{}',
  budgets JSONB DEFAULT '{}'
);

-- Сканы PR
CREATE TABLE scans (
  id VARCHAR(64) PRIMARY KEY,           -- scan_id
  provider VARCHAR(16) NOT NULL,
  repo_slug VARCHAR(255) NOT NULL,
  pr_id VARCHAR(64) NOT NULL,
  head_sha VARCHAR(64) NOT NULL,
  status VARCHAR(16) DEFAULT 'queued',  -- queued|running|completed|error|superseded|no_token
  degraded JSONB DEFAULT '[]',          -- список недоступных стадий
  files_scanned JSONB DEFAULT '[]',
  files_skipped JSONB DEFAULT '[]',
  risk_score INT DEFAULT 0,
  risk_label VARCHAR(16),
  est_sent_tokens INT DEFAULT 0,
  est_full_repo_tokens INT DEFAULT 0,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  autofix_pr_url TEXT
);

-- Находки
CREATE TABLE findings (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
  fingerprint VARCHAR(64) NOT NULL,     -- SHA256 для идемпотентности
  file VARCHAR(512) NOT NULL,
  line INT NOT NULL,
  diff_position INT,
  cwe VARCHAR(16),
  rule_id VARCHAR(128),
  severity VARCHAR(16) NOT NULL,
  confidence FLOAT NOT NULL,
  source VARCHAR(16) NOT NULL,          -- deterministic|llm_a|llm_b|judge
  title TEXT NOT NULL,
  rationale TEXT NOT NULL,
  exploit TEXT,                         -- PoC snippet
  fix TEXT,
  fix_is_suggestion BOOLEAN DEFAULT FALSE,
  suppressed BOOLEAN DEFAULT FALSE,
  comment_ref VARCHAR(255),             -- VCS comment ID after posting
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Лог LLM-вызовов (аудит)
CREATE TABLE llm_calls (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64),
  tier VARCHAR(32),                     -- local|openrouter
  model VARCHAR(128),
  role VARCHAR(16),                     -- detector_a|detector_b|judge|dialog|embed
  prompt_tokens INT DEFAULT 0,
  completion_tokens INT DEFAULT 0,
  latency_ms INT DEFAULT 0,
  cost_usd FLOAT DEFAULT 0.0,
  ok BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Лог VCS API-вызовов
CREATE TABLE vcs_calls (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64),
  provider VARCHAR(16),
  op VARCHAR(48),
  status_code INT,
  latency_ms INT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Диалоговые сессии
CREATE TABLE dialog_turns (
  id SERIAL PRIMARY KEY,
  provider VARCHAR(16),
  repo_slug VARCHAR(255),
  pr_id VARCHAR(64),
  thread_id VARCHAR(128),
  finding_fingerprint VARCHAR(64),
  turn INT DEFAULT 1,
  command VARCHAR(32),                  -- why|explain|false_positive|ignore|scan_full
  actor VARCHAR(128),
  question TEXT,
  answer TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- FP-отметки для обучения
CREATE TABLE false_positives (
  id SERIAL PRIMARY KEY,
  repo_id INT REFERENCES repositories(id),
  fingerprint VARCHAR(64),
  rule_id VARCHAR(128),
  path_glob VARCHAR(512),
  count INT DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uq_fp UNIQUE(repo_id, fingerprint)
);

-- Auto-suppression rules (после 3+ FP отметок)
CREATE TABLE repo_suppressions (
  id SERIAL PRIMARY KEY,
  repo_id INT REFERENCES repositories(id),
  rule_id VARCHAR(128),
  path_glob VARCHAR(512),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Knowledge Base (pgvector)
CREATE TABLE kb_findings (
  id SERIAL PRIMARY KEY,
  fingerprint VARCHAR(64) UNIQUE,
  repo_slug VARCHAR(255),
  pr_number INT,
  file VARCHAR(512),
  cwe VARCHAR(16),
  severity VARCHAR(16),
  title TEXT,
  rationale TEXT,
  fix TEXT,
  code_snippet TEXT,
  embedding VECTOR(1536),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Retro-сканы
CREATE TABLE retro_scans (
  id SERIAL PRIMARY KEY,
  repo_id INT REFERENCES repositories(id),
  status VARCHAR(16),
  total_files INT DEFAULT 0,
  scanned_files INT DEFAULT 0,
  findings_count INT DEFAULT 0,
  report_markdown TEXT,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);

-- Аудит Admin Portal
CREATE TABLE admin_audit (
  id SERIAL PRIMARY KEY,
  actor VARCHAR(128),
  action VARCHAR(64),
  entity_type VARCHAR(32),
  entity_id VARCHAR(128),
  details JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Пользователи Portal
CREATE TABLE portal_users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(16) DEFAULT 'viewer',    -- admin|viewer
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_login TIMESTAMPTZ
);
```

---

## 16. REST API — полный список эндпоинтов

### Webhooks (публичные, без авторизации, только с HMAC)

```
POST /webhooks/github         — GitHub webhooks
POST /webhooks/gitlab         — GitLab webhooks
POST /webhooks/bitbucket      — Bitbucket webhooks
```

### Auth

```
POST /api/auth/login          — {email, password} → {access_token, refresh_token}
POST /api/auth/refresh        — {refresh_token} → {access_token}
POST /api/auth/logout
```

### Repositories (Admin only)

```
GET  /api/repos               — список подключённых репозиториев
POST /api/repos               — подключить репозиторий
  Body: {provider, slug, access_token, webhook_secret, policy}
GET  /api/repos/{id}          — детали репозитория
PUT  /api/repos/{id}          — обновить настройки / токен
DELETE /api/repos/{id}        — отключить (soft delete)
POST /api/repos/{id}/test     — проверить токен и webhook
GET  /api/repos/{id}/stats    — статистика по репозиторию
```

### Scans

```
GET  /api/scans               — список сканов (с фильтром по repo, pr, status)
GET  /api/scans/{scan_id}     — детали скана
GET  /api/scans/{scan_id}/findings — все находки скана
POST /api/repos/{id}/retro    — запустить retro-scan
GET  /api/retro/{retro_id}    — статус + progress retro-скана
```

### Dashboard / Stats

```
GET  /api/stats               — общая статистика (для Dashboard)
  Response: {
    total_prs_analyzed, blocked_merges, total_findings,
    findings_by_severity, findings_by_type, risk_score_trend,
    tokens_saved_total, last_30_days: [...]
  }
GET  /api/stats/repo/{id}     — статистика конкретного репозитория
```

### Knowledge Base

```
GET  /api/kb                  — список записей (с поиском)
  Query: ?q=sql+injection&cwe=CWE-89&severity=critical
GET  /api/kb/{id}             — карточка уязвимости
```

### Findings / Feedback

```
POST /api/findings/{id}/feedback
  Body: {kind: "false_positive"|"helpful", comment}
GET  /api/suppressions        — team-specific suppressions
DELETE /api/suppressions/{id} — удалить suppression
```

### Settings

```
GET  /api/settings            — глобальные настройки
PUT  /api/settings            — обновить (risk_score_block, global ignores)
```

---

## 17. Edge-cases и обработка ошибок

| Ситуация | Обработка |
|---|---|
| Пустой PR (только .md) | filter.apply_filter() → все скипнуты → summary "No security-relevant changes" (без LLM запроса) |
| Большой PR (>500 строк diff) | Разбить code_files на batches по 150 строк → отдельные LLM вызовы → merge findings |
| LLM таймаут | retry=2 с backoff; после → degraded mode (deterministic only), summary с пометкой |
| LLM невалидный JSON | json_repair → retry с explicit prompt → при failure: пропустить LLM findings |
| Provider API 4xx | ProviderError → scan status=provider_error → лог + метрика |
| Provider API 5xx | exponential backoff 3 попытки (2s, 4s, 8s) |
| Semgrep не установлен | FileNotFoundError → degraded.append("semgrep") → продолжить без |
| Gitleaks не установлен | Аналогично → degraded |
| OSV API недоступен | httpx.HTTPError → SCA пропущен → degraded |
| Дублированный webhook | idempotency.claim() → False → 202 duplicate (не обрабатывается) |
| Новый commit пока идёт скан | is_stale() → True → abort scan, status=superseded |
| Бинарные файлы | fc.is_binary=True → filter пропускает |
| Файл слишком большой | >100KB added bytes → filter пропускает с reason=too-large |
| Репозиторий не зарегистрирован | ctx.access_token="" → scan status=no_token → guidance в лог |
| Retro-scan timeout | status=timeout, partial report сохраняется |

---

## 18. Безопасность сервиса

```
· Fernet (AES-128-CBC) для всех токенов в БД
· AEGIS_VAULT_KEY из env/Secrets Manager (≠ default)
· Webhook signature fail-closed (reject, не предупреждение)
· Rate limiting: 100 req/s на /webhooks (nginx или slowapi)
· Gitleaks запускается ДО отправки в LLM (секреты не утекают в cloud)
· Diff никогда не логируется полностью (только метаданные)
· LLM response не хранится в plain text → только parsed findings
· JWT access_token TTL = 15min, refresh TTL = 7 days
· HTTPS everywhere (nginx TLS termination)
· Worker изолирован (нет прямого DB access из webhook handler)
· Semgrep запускается в tmpdir с ограниченными правами (subprocess)
· SQL параметризованные запросы через SQLAlchemy (никакого string format)
· XSS в Admin Portal: React escaping + CSP headers
```

---

## 19. Non-functional Requirements

| Параметр | Цель |
|---|---|
| Webhook ack | < 300ms |
| Scan completion (typical PR ~50 строк) | < 45s |
| Scan completion (large PR ~500 строк) | < 3 min |
| Concurrent scans | 4 параллельно (Arq worker concurrency) |
| LLM latency (local, Tier 1) | 5–15s |
| LLM latency (OpenRouter) | 3–8s |
| DB queries | < 50ms p99 |
| Uptime | 99.5% (single-node) |
| Token savings | >90% vs full-repo analysis |

---

## 20. Mapping критериев оценки → реализация

| Критерий | Вес | Реализация |
|---|---|---|
| C1: Webhook от PR | 6 | api/webhooks.py + HMAC verification (Phase 1) |
| C2: Только diff → LLM | 6 | pipeline/filter.py + provider.fetch_diff() (Phase 1-2) |
| C3: SQLi / hardcoded / XSS | 6 | deterministic/* + llm_stage (Phase 3-5) |
| C4: Inline-комментарии | 6 | render.py + provider write APIs (Phase 6) |
| C5: Fix snippet | 3 | LLM prompt → fix field + autofix.py (Phase 5-6) |
| C6: Фильтрация файлов | 3 | filter.py с 8 причинами skip (Phase 2) |
| C7: Диалог @secbot | 1 | dialog/* + ChatOps commands (Phase 7) |
| C8: Блокировка merge | 1 | policy.py + Status Check API (Phase 6) |
| **Killer-фичи** | bonus | Risk Score, PoC, autofix PR, KB, retro-scan, FP-learning, Blast Radius |
