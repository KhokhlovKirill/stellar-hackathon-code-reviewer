# Aegis Security Review — Agent Handoff

_Last updated: 2026-05-16 (сессия 7)_

---

## Что такое проект

**Aegis** — AI-powered инструмент для автоматического security code review pull request'ов.
Принимает PR (через webhook или вручную по URL), прогоняет диффы через цепочку LLM-агентов,
возвращает findings с severity, line numbers и авто-фиксами.
Есть полноценный VS Code extension и web UI.

Репозиторий: `~/Desktop/code-review/`
```
code-review/
├── backend/
│   ├── aegis/
│   │   ├── api/            — HTTP endpoints (FastAPI routers)
│   │   │   ├── app.py      — точка входа, регистрация роутеров
│   │   │   ├── extension.py — /api/ext/* (VS Code + web chat)
│   │   │   ├── auth.py     — JWT issue/verify
│   │   │   ├── security.py — password hash, require_user
│   │   │   └── webhooks.py — GitHub/GitLab webhook intake
│   │   ├── llm/
│   │   │   ├── base.py     — LLMClient ABC, ChatMessage, LLMCompletion
│   │   │   ├── openai_compat.py — httpx client (complete + stream_complete)
│   │   │   ├── router.py   — LLMRouter (complete + stream_chat, fallback tiers)
│   │   │   ├── parser.py   — JSON → Finding list
│   │   │   └── prompt.py   — system/user prompt builders
│   │   ├── pipeline/
│   │   │   ├── simple_scan.py — pull-mode scanner (URL → diff → findings)
│   │   │   ├── llm_stage.py   — LLM pipeline stage
│   │   │   └── dialog.py      — @secbot comment handler
│   │   ├── db/             — SQLAlchemy models + session
│   │   ├── web/routes.py   — Jinja2 web UI routes (/chat, /scan, /dashboard, ...)
│   │   └── worker/         — ARQ background jobs
│   └── deploy/
│       └── docker-compose.yml
└── frontend/
    ├── templates/          — Jinja2 HTML шаблоны
    │   ├── base.html
    │   ├── chat.html       — страница чата с агентом (НОВОЕ)
    │   ├── scan.html       — детали скана + кнопки Ask Aegis
    │   ├── review.html     — quick review (paste GitHub URL)
    │   └── dashboard.html / project.html / login.html / register.html
    └── vscode-extension/
        ├── src/
        │   ├── extension.ts
        │   ├── aegisClient.ts
        │   ├── types.ts
        │   ├── auth.ts / config.ts
        │   ├── commands/index.ts
        │   ├── providers/
        │   │   ├── prTreeProvider.ts
        │   │   ├── findingsTreeProvider.ts
        │   │   ├── diagnosticsProvider.ts
        │   │   ├── codeLensProvider.ts
        │   │   └── hoverProvider.ts
        │   ├── views/
        │   │   ├── panelManager.ts
        │   │   ├── prDetailView.ts
        │   │   └── chatView.ts
        │   └── git/gitProvider.ts
        ├── esbuild.mjs
        └── package.json
```

---

## Инфраструктура

### Как запустить

```bash
cd backend/deploy
docker-compose up -d
# aegis-api   → localhost:8080
# aegis-worker → ARQ (Redis queue)
# postgres:16  → localhost:5432
# redis:7      → localhost:6379
```

### SSH туннель (VPS → интернет)
```bash
./start_tunnel.sh   # ssh -R 18099:localhost:8080 vps...
```
Nginx на VPS `87.242.94.247` → `127.0.0.1:18099` → `localhost:8080`.
SSH ключ: `~/.ssh/vps_aegis_key` — **НИКОГДА не коммитить**.

### Переменные окружения (`.env` в корне)
```
DATABASE_URL=postgresql+asyncpg://aegis:aegis@localhost:5432/aegis
REDIS_URL=redis://localhost:6379
OPENROUTER_API_KEY=sk-or-v1-...
SECRET_KEY=...          # JWT signing + Fernet key
OPENROUTER_GENERALIST_MODEL=deepseek/deepseek-v4-flash:free
OPENROUTER_JUDGE_MODEL=xiaomi/mimo-v2-flash
OPENROUTER_MIMO_MODEL=xiaomi/mimo-v2-flash
LMSTUDIO_SECURE_MODEL=don-agent-v3
LMSTUDIO_SWAP_MODELS=false
```

---

## LLM роутинг

Файл: `backend/aegis/llm/router.py`

**Порядок fallback (cloud-first):**
| Роль       | Тиры по приоритету                            |
|------------|-----------------------------------------------|
| detector_a | cloud-generalist → cloud-mimo → local-secure  |
| detector_b | cloud-mimo → cloud-generalist → local-secure  |
| judge      | cloud-judge → cloud-generalist → local-secure |

**Модели:**
| Тир              | Модель                            | Провайдер  |
|------------------|-----------------------------------|------------|
| cloud-generalist | `deepseek/deepseek-v4-flash:free` | OpenRouter |
| cloud-judge      | `xiaomi/mimo-v2-flash`            | OpenRouter |
| cloud-mimo       | `xiaomi/mimo-v2-flash`            | OpenRouter |
| local-secure     | `don-agent-v3`                    | LM Studio  |

`local-secure` — последний fallback, LM Studio часто выключен — это нормально.

**Два режима вызова LLMRouter:**
- `await router.complete(role, messages, schema, max_tokens)` — полный JSON ответ (для сканирования)
- `async for token in router.stream_chat(role, messages, max_tokens)` — SSE стриминг (для чата)

`stream_chat` добавлен в этой сессии. Реализован в `openai_compat.py::stream_complete()` через
`httpx.AsyncClient.stream()` — читает `data: ...` SSE строки, парсит JSON чанки, yield'ит дельты.

---

## Backend API — полная таблица

### `/api/ext/*` — VS Code extension API
Файл: `backend/aegis/api/extension.py`

| Метод | Путь | Auth | Описание |
|-------|------|------|----------|
| GET  | `/api/ext/auth/vscode-login` | — | HTML страница логина → redirect `vscode://` |
| GET  | `/api/ext/repos` | Bearer | Список репозиториев пользователя |
| GET  | `/api/ext/repos/{id}/prs` | Bearer | Открытые PR'ы + последний скан каждого |
| GET  | `/api/ext/repos/{id}/scans` | Bearer | Последние 30 сканов репозитория |
| GET  | `/api/ext/scans/{id}` | — | Детали скана + findings |
| POST | `/api/ext/scan/url` | — | Скан PR по GitHub URL |
| POST | `/api/ext/scan/branch` | — | Скан raw unified diff (локальная ветка) |
| POST | `/api/ext/scan/pr` | Bearer | **НОВОЕ** Скан PR по repo_id+pr_number (использует сохранённый токен) |
| POST | `/api/ext/chat` | — | Чат с агентом (finding опциональный), полный ответ |
| POST | `/api/ext/chat/stream` | — | **НОВОЕ** SSE стриминг чата |
| POST | `/api/ext/feedback` | — | Отметить finding как false positive |

### `/api/web/*` — web UI API
Файл: `backend/aegis/web/routes.py`

| Метод | Путь | Auth | Описание |
|-------|------|------|----------|
| POST | `/api/web/chat/stream` | Cookie | **НОВОЕ** SSE стриминг чата для web UI |

### Web страницы
| GET | `/` | Redirect → /dashboard или /login |
| GET | `/login`, POST `/login` | Форма входа |
| GET | `/register`, POST `/register` | Регистрация |
| GET | `/dashboard` | Список проектов |
| GET | `/projects/{id}` | Репозитории + сканы проекта |
| GET | `/review` | Quick review (paste GitHub PR URL) |
| GET | `/scans/{id}` | Детали скана + findings + **кнопки Ask Aegis** |
| GET | `/chat` | **НОВОЕ** Страница чата (опционально `?scan_id=&fingerprint=`) |

---

## Чат с агентом — как работает

### Режимы
1. **С finding контекстом** — передаётся объект `{file, line, severity, title, rationale, ...}`.
   Агент знает о конкретной уязвимости, может объяснить и сгенерировать diff-фикс.
2. **Free-form** — finding = null. Агент отвечает на общие вопросы по безопасности.

### SSE стриминг (бэкенд)
```
POST /api/ext/chat/stream  (или /api/web/chat/stream)
→ Content-Type: text/event-stream
→ data: {"token": "SQL"}\n\n
→ data: {"token": " injection"}\n\n
→ data: [DONE]\n\n
```
Каждый chunk — один токен от LLM. При ошибке: `data: {"error": "..."}\n\n`.
`X-Accel-Buffering: no` — отключает nginx буферизацию, нужен для работы SSE через прокси.

### VS Code Webview стриминг
Webview не может напрямую вызвать backend (CSP ограничения). Поэтому:
1. Webview → `postMessage({ type: 'sendMessage', text, finding, history })` → Extension Host
2. Extension Host → `client.streamChat()` → `fetch('/api/ext/chat/stream')` → читает ReadableStream
3. Каждый токен → `panel.webview.postMessage({ type: 'streamChunk', token })`
4. Webview appends токен к текущему сообщению, re-рендерит markdown на лету
5. После `[DONE]` → `postMessage({ type: 'streamEnd', proposed_patch })`

`connect-src http: https:` в CSP chatView.ts — разрешает fetch к backend из Webview.

### Web UI стриминг
Браузер использует `fetch()` с `response.body.getReader()` (ReadableStream API).
Credentials: `'include'` — передаёт session cookie для аутентификации.
Если в ответе есть finding — чат автоматически запускает первый вопрос при открытии страницы.

### Предложенные патчи
Если агент возвращает код в блоке ` ```diff ... ``` `, он отображается в diff-viewer с кнопками
**Apply Patch** (VS Code) или **Copy / Download .patch** (Web). В VS Code патч сначала
проходит `sanitizePatch()` (см. `git/patch.ts`), затем `resolveTargetPath()` —
сверяет target-файл с воркспейсом через `hintFiles=[finding.file]` / `git ls-files`
и переписывает заголовки на реальный путь, если LLM указал голое имя. Только потом
запускается цепочка `git apply --recount` → `--3way` → `--unidiff-zero` →
GNU `patch --fuzz` с dry-run перед каждой мутацией. На web — тот же
`/api/ext/chat/stream`, что и у расширения.

---

## Скан PR из сайдбара расширения

### Проблема
Пользователь видит PR'ы в дереве сайдбара но не мог их отсканировать оттуда.
`Scan Current Branch` сканирует только локальный git diff открытого проекта — это другое.

### Решение
Добавлена команда `aegis.scanPR` + inline кнопка 🔍 на каждом PR-узле.

**Поток:**
1. Пользователь нажимает 🔍 на PR-узле (или правый клик → Scan PR)
2. Расширение вызывает `POST /api/ext/scan/pr` с `{ repo_id, pr_number }`
3. Бэкенд ищет репозиторий, проверяет ownership, достаёт зашифрованный GitHub токен из `RepoSecret`
4. Вызывает `run_simple_scan(pr_url, token=access_token)` — тот же pipeline что и для URL скана
5. Результат → открывается панель деталей + загружается в Current Findings + diagnostics
6. PR list автоматически обновляется (`prTree.loadData()`) чтобы показать новый scan summary

**Почему через `repo_id` а не URL:**
Расширение не хранит GitHub токены. Токены репозиториев хранятся в БД в зашифрованном виде
(Fernet). Передавая `repo_id`, расширение даёт бэкенду найти и расшифровать нужный токен.

**Изменения в `PRNode`:**
Добавлено поле `public readonly repoId: number` — передаётся из `RepoNode.repo.id` при создании дерева.

---

## VS Code расширение — сборка и установка

```bash
cd frontend/vscode-extension
node esbuild.mjs
npx vsce package --no-dependencies --allow-missing-repository
/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code \
  --install-extension aegis-security-0.1.0.vsix --force
# Затем: Cmd+Shift+P → Developer: Reload Window
```

### Команды расширения (полный список)
| Команда | Где доступна | Описание |
|---------|-------------|----------|
| `aegis.login` | Sidebar welcome | Открыть страницу входа в браузере |
| `aegis.scanCurrentBranch` | Sidebar toolbar, Palette | Сканировать локальный git diff vs main |
| `aegis.scanCurrentFile` | Palette | Сканировать diff только текущего файла |
| `aegis.scanURL` | Sidebar welcome, Palette | Сканировать PR по GitHub URL |
| `aegis.scanPR` | **PR-узел inline + контекстное меню** | **НОВОЕ** Скан PR из сайдбара |
| `aegis.refreshPRs` | Sidebar toolbar | Обновить список PR'ов |
| `aegis.openPRDetail` | Клик по PR/Scan узлу | Открыть детальную панель |
| `aegis.openChat` | Editor context, Palette | Открыть чат (с finding или free-form) |
| `aegis.fixFinding` | Editor context, CodeLens | Авто-фикс через streaming чат |
| `aegis.fixAll` | Palette | Авто-фикс всех findings |
| `aegis.markFalsePositive` | Palette | False positive → убрать из диагностики |
| `aegis.hardenBranch` | Palette | Scan + Fix всех critical/high |
| `aegis.configure` | Status bar click | Меню: settings, login, logout, severity gate |
| `aegis.openWebUI` | Sidebar welcome | Открыть web UI в браузере |

### Сайдбар — логика показа контента
VS Code `viewsWelcome` показывается только когда `getChildren()` возвращает `[]`.
`prTreeProvider.getChildren()` возвращает `[]` когда `repoNodes.length === 0` — ОБЯЗАТЕЛЬНО,
иначе viewsWelcome не показывается и Sign In кнопка не видна.

Контекстные ключи:
```
aegis.isAuthenticated = false  →  viewsWelcome с кнопкой Sign In
aegis.isAuthenticated = true
  aegis.repoCount = 0          →  viewsWelcome "connect first repo"
  aegis.repoCount > 0          →  дерево репозиториев/PR'ов
```

---

## Что было сделано по сессиям

### Сессия 1
1. Обновлены LLM модели на бесплатные OpenRouter (DeepSeek, Qwen3, MiMo)
2. Переход на cloud-first роутинг (LM Studio = последний fallback)
3. Запуск в Docker (PostgreSQL вместо SQLite)
4. Написано VS Code расширение с нуля (полный production UI)
5. OAuth-style login (браузер → vscode:// redirect)
6. Исправлен баг с Sign In кнопкой (prTreeProvider возвращал MessageNode)

### Сессия 2
7. **SSE стриминг в LLM слое** — `openai_compat.py::stream_complete()` + `router.py::stream_chat()`
8. **Chat endpoint обновлён** — `finding` теперь опциональный (null = free-form режим)
9. **`POST /api/ext/chat/stream`** — SSE endpoint для VS Code
10. **`POST /api/web/chat/stream`** — SSE endpoint для Web UI (session cookie auth)
11. **Новая страница `/chat`** — полноценный web чат с SSE стримингом, markdown, diff viewer
12. **`/chat?scan_id=X&fingerprint=Y`** — автоматически загружает finding контекст и запускает первый вопрос
13. **`scan.html` обновлён** — кнопка "Ask Aegis about this scan" + "🛡️ Ask Aegis" у каждого finding
14. **Навбар** — добавлена ссылка "🛡️ Agent" для залогиненных пользователей
15. **VS Code чат переведён на streaming** — `streamChunk/streamStart/streamEnd` postMessage protocol
16. **`aegis.openChat` без finding** — free-form режим, placeholder меняется
17. **`aegis.fixFinding` / `fixAll` / `hardenBranch`** — переведены на streaming
18. **`POST /api/ext/scan/pr`** — новый endpoint, скан по repo_id+pr_number с хранимым токеном
19. **`aegis.scanPR`** — новая команда, inline кнопка 🔍 + контекстное меню на PR-узлах
20. **`PRNode.repoId`** — добавлено поле для передачи в scanPR

### Сессия 3
21. **Исправлен stale client после browser-login в VS Code** — команды теперь используют тот же
    `AegisClient`, которому обновляется token/baseUrl; `scanPR` больше не остаётся без Bearer после логина.
22. **Добавлен общий 401 handler расширения** — при протухшем JWT очищается SecretStorage,
    сбрасывается `aegis.isAuthenticated=false`, возвращается Sign In welcome-state.
23. **PR tree получил error-state** — authenticated API ошибки больше не выглядят как пустой список.
24. **Scan URL / Scan PR / Scan Branch теперь сохраняют Scan + FindingRow в БД** —
    возвращаемый `scan_id` реально открывается через `/api/ext/scans/{id}`, а PR sidebar может показать `last_scan`.
25. **Pull-mode LLM анализ стал ensemble, а не fallback-only** — OpenRouter detector и локальный Don
    (`local-secure`, `don-agent-v3`) запускаются параллельно; Don принудительно вызывается через конкретный tier.
26. **Don стал обязательным модулем аудита** — если `local-secure` недоступен, scan помечается degraded
    (`local-secure`), но это больше не скрывается под cloud fallback.
27. **Fix Apply Patch в chat webview исправлен** — убраны inline `onclick`, которые блокировались CSP,
    patch передаётся через event delegation без HTML-escaping порчи diff.
28. **SSE parser расширения стал устойчивее** — malformed/non-JSON SSE строки игнорируются, ошибки backend
    по-прежнему пробрасываются пользователю.
29. **Docker и VSIX обновлены** — пересобраны и перезапущены `api`/`worker`, VS Code extension переустановлен
    из `frontend/vscode-extension/aegis-security-0.1.0.vsix`.

### Сессия 4
30. **Починены Fix / Ask Agent / Ignore в PR Detail webview** — finding больше не передаётся
    через fragile HTML-escaped JSON в `data-*`; кнопки берут объект из `currentScan.findings` по fingerprint.
31. **PR Detail panel теперь перерисовывается при новом scan** — повторное открытие панели больше не делает
    `window.location.reload()` старого HTML.
32. **Добавлен whole-PR chat context** — чат принимает `scan` вместе с `finding`, умеет отвечать по всему PR,
    объяснять review и готовить общий remediation/fix plan.
33. **Добавлен Agent Review Summary** в VS Code PR detail, web `/review` и `/scans/{id}`.
34. **Quick Review теперь сохраняет scan в БД** — нижние кнопки “Ask / Explain / Fix whole PR” открывают чат
    с реальным `scan_id`, findings и summary.
35. **Scan summary генерируется coordinator LLM** на базе findings; при сбое есть deterministic fallback summary.

---

### Сессия 5
36. **Исправлен баг «git apply failed: corrupt patch at line N» в расширении** —
    LLM-диффы малформатны для строгого парсера `git apply`. Добавлен чистый
    модуль `frontend/vscode-extension/src/git/patch.ts`:
    `sanitizePatch()` стрипит markdown-фенсы/прозу, конвертирует пустые
    blank-context строки в ` ` (главная причина "corrupt patch"), пересчитывает
    `@@ -a,b +c,d @@` по факту, синтезирует отсутствующие `---/+++` из
    `diff --git`, выкидывает `\ No newline`. `GitProvider.applyPatch` теперь
    прогоняет цепочку стратегий с dry-run перед мутацией: `git apply -p1
    --recount` → `-p0` → `--3way` → `--unidiff-zero` → GNU `patch -p1/-p0
    --fuzz=3`. Проверено end-to-end: дифф, дававший ровно `corrupt patch at
    line 11`, теперь применяется чисто.
37. **Backend prompt hardening** — системные промпты chat/fix в
    `api/extension.py` и `api/admin.py` требуют строгий git unified diff
    (diff --git/---/+++, корректные счётчики, пробел перед blank-context,
    без прозы внутри блока) — defense-in-depth с клиентским санитайзером.
38. **Web frontend приравнен к VS Code extension** — React-чат переписан на
    тот же путь и принцип: SSE-стриминг через `/api/ext/chat/stream` с тем же
    структурированным payload (`finding`/`scan`/`repo`/`message`/`history`/`lang`).
    Новые `frontend/src/lib/chatStream.ts` (типы + SSE), переписан
    `components/Chat.tsx` (стриминг токенов, markdown, diff-viewer с Copy /
    Download .patch, imperative `ask()/focus()` handle). `ScanPage`/`ReviewPage`
    передают структурированный `scan`/`finding`, у каждой находки кнопки
    💬 Ask / 📖 Explain / 🔧 Fix и whole-PR действия — зеркало команд расширения.
39. **Настройки + выбор языка на web** — `context/SettingsContext.tsx`
    (ru/en, i18n словарь, persist в localStorage, seed из
    `GET /api/config/defaults`), страница `/settings` (язык + тема + модели),
    переключатель RU/EN в навбаре. `lang` протянут во все вызовы
    (`/api/review`, chat stream, `/api/web/chat/stream` через новое поле
    `_WebChatRequest.lang`). Новый backend `GET /api/config/defaults` отдаёт
    `policy.comment_language`.

### Сессия 6
40. **Исправлен второй слой бага Apply Patch — «No such file / does not exist
    in index»**. После фикса парсинга (сессия 5) патчи стали валидны, но
    падали т.к. LLM указывает голый/неверный путь (`auth_test.py`), а файл
    лежит по реальному пути находки. В `git/patch.ts` добавлены чистые
    `extractPatchPaths`, `isSingleFilePatch`, `retargetSingleFilePatch`,
    `stripAB`. `GitProvider.applyPatch(patch, { hintFiles })` теперь до
    стратегий резолвит target-файл в воркспейсе: hints (реальный
    `finding.file`) → литеральный путь → уникальный basename через
    `git ls-files`; при несовпадении переписывает заголовки `diff --git/--- /
    +++` на реальный путь. Если файла нет в открытой папке вовсе — понятная
    actionable-ошибка (открыть нужный репозиторий / Copy-Download). `hintFiles`
    протянут во все 4 call-site (`applyAndVerify`, chat `applyPatch`, `fixAll`,
    `hardenBranch`) из `finding.file` (+ все файлы scan-findings в чате).
    Проверено end-to-end: патч на `auth_test.py` ресолвится в
    `backend/tests/auth_test.py` и применяется чисто.

### Сессия 7
41. **Apply Patch теперь работает когда сканированный репо ≠ открытая папка.**
    Резолвер ищет файл во **всех** `workspace.workspaceFolders`, не только в
    первом. Если ни в одной не нашёлся — новый класс `PatchTargetNotFoundError`
    несёт `targetPath` + `sanitizedPatch` + `searchedRoots`, и команды
    показывают QuickPick восстановления:
    - **Open scanned repository…** — folder picker → ретрай с `rootOverride`
    - **Save patch to file…** — `showSaveDialog` → `fs.writeFile` → Reveal/Open
    - **Copy patch to clipboard** — `vscode.env.clipboard.writeText`
    Подключено к `applyAndVerify` (Fix) и chat-panel "Apply Patch" — обе точки
    интерактивны. `GitProvider.applyPatch(patch, { hintFiles, rootOverride? })`
    + новый `applyPatchInRoot(root, sanitized, opts)` для прицельного применения.

## Что нужно доделать (актуально)

### Приоритет 1 — Проверить работу end-to-end

- [ ] **OAuth flow**: нажать Sign In → браузер → логин → `vscode://` redirect → расширение авторизовано.
      Если падает 401 — старый JWT из SecretStorage (юзер не существует в новом PostgreSQL).
      401 handler реализован; остался ручной UX smoke-test browser redirect в VS Code.

- [x] **Scan PR backend flow**: `POST /api/ext/scan/pr` сохраняет scan/findings в БД и fallback на публичный
      доступ уже есть через `access_token=None`. Остался ручной UI smoke-test на реальном PR.

- [ ] **Web chat**: войти → `/chat` → задать вопрос → стриминг работает.
      Возможная проблема: nginx буферизация. Проверить что `X-Accel-Buffering: no` доходит до клиента.

### Приоритет 2 — UX расширения

- [x] **401 handler в aegisClient**: при auth 401 → `clearToken` + `setContext(isAuthenticated, false)` +
      `statusBar.text = "Sign in"`, Sign In welcome-state возвращается.

- [x] **Error state в prTreeProvider**: authenticated API ошибка показывает
      `MessageNode("Failed to load repositories: ...", "error")`; unauth welcome-state не ломается.

- [ ] **`aegis.openChat` из палитры** (без finding): сейчас работает, но нужно протестировать что
      free-form режим корректно работает — сообщение передаётся, ответ стримится.

### Приоритет 3 — Функциональность

- [ ] **Сохранение истории чата**: сейчас история живёт только в памяти Webview/страницы.
      Можно добавить `DialogTurn` в БД через `/api/ext/chat` endpoint (уже есть модель `DialogTurn`).

- [x] **Повторный скан PR с обновлением иконки**: после `aegis.scanPR` дерево обновляется через
      `prTree.loadData()`, но иконка severity на PR-узле показывает `last_scan` из БД.
      Extension scan endpoints теперь сохраняют scan/findings в БД.

- [ ] **Scan Current Branch** — diff передаётся корректно, но `repoSlug` берётся из `git remote`,
      который может не совпадать с slug в Aegis БД. Нужно проверить маппинг.

### Приоритет 4 — Деплой

- [ ] **HTTPS**: Let's Encrypt на VPS для продакшн-деплоя
- [ ] **Версия 0.2.0**: поднять версию расширения после тестирования
- [ ] **Marketplace публикация**: нужен аккаунт на marketplace.visualstudio.com

---

## Полезные команды

```bash
# Логи
docker-compose -f backend/deploy/docker-compose.yml logs -f aegis-api
docker-compose -f backend/deploy/docker-compose.yml logs -f aegis-worker

# Перезапуск после изменений Python
docker-compose -f backend/deploy/docker-compose.yml build api && \
docker-compose -f backend/deploy/docker-compose.yml up -d api

# Пересобрать и установить расширение
cd frontend/vscode-extension
node esbuild.mjs && \
npx vsce package --no-dependencies --allow-missing-repository && \
/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code \
  --install-extension aegis-security-0.1.0.vsix --force

# Запустить туннель на VPS
./start_tunnel.sh

# Тест chat stream
curl -N -X POST http://localhost:8080/api/ext/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message":"What is SQL injection?","finding":null,"repo":"","history":[]}'

# Тест scan PR (нужен Bearer токен)
curl -X POST http://localhost:8080/api/ext/scan/pr \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_id":1,"pr_number":5}'
```

---

## Архитектурные решения

- **ARQ вместо Celery** — легче, нативно async, Redis уже используется
- **esbuild вместо webpack** — в 10x быстрее, для VS Code расширений достаточно
- **SecretStorage для JWT** — единственный безопасный способ хранить секреты в VS Code
- **viewsWelcome + setContext** — стандартный VS Code паттерн для conditional sidebar content
- **Fernet encryption** — симметричное шифрование GitHub токенов в БД; ключ = `SECRET_KEY`
- **cloud-first LLM** — LM Studio нестабилен (SSD выключается), OpenRouter как основной путь
- **SSE через fetch() а не EventSource** — EventSource не поддерживает POST body; fetch + ReadableStream работает везде (браузер и VS Code Webview)
- **`repo_id` в scanPR вместо URL** — расширение не хранит GitHub токены, бэкенд достаёт их сам по ID
- **stream_chat как AsyncGenerator** — позволяет прерывать стриминг при закрытии соединения, graceful cleanup
