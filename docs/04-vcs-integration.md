# 04 — Интеграция с VCS (GitHub / GitLab / Bitbucket)

Один абстрактный протокол `VCSProvider`, три реализации. Бот работает как **отдельный
сервисный аккаунт**, привязка репозитория — через токены в Admin Portal (`08`).

## 1. Протокол провайдера

```python
class VCSProvider(Protocol):
    async def verify_webhook(self, headers, body, secret) -> WebhookEvent | None: ...
    async def fetch_pull_request(self, repo, pr_id) -> PullRequest: ...
    async def fetch_diff(self, repo, pr_id, base_sha, head_sha) -> list[FileChange]: ...
    async def post_inline_comment(self, repo, pr_id, c: ReviewComment) -> str: ...
    async def post_summary(self, repo, pr_id, body, scan_id) -> str: ...
    async def reply_in_thread(self, repo, pr_id, thread_id, body) -> str: ...
    async def set_status_check(self, repo, head_sha, state, ctx, url) -> None: ...
    async def request_changes(self, repo, pr_id, body) -> None: ...
    async def get_thread(self, repo, pr_id, thread_id) -> DiscussionThread: ...
```

`FileChange` несёт: `path`, `old_path`, `status` (added/modified/renamed/deleted),
`is_binary`, `language`, и список `Hunk` с `DiffLine` (тип `+/-/ctx`, номер новой
строки, номер старой строки, позиция в diff для GitHub). Парсинг unified diff —
библиотека `unidiff`; для каждого `+`-line знаем `new_lineno` и `diff_position`.

## 2. Приём webhook и верификация подписи (критерий C1)

| Провайдер | Заголовок подписи | Алгоритм проверки |
|---|---|---|
| **GitHub** | `X-Hub-Signature-256` | `hmac_sha256(secret, raw_body)` → сравнение constant-time с `sha256=...`; событие в `X-GitHub-Event`, delivery в `X-GitHub-Delivery` |
| **GitLab** | `X-Gitlab-Token` | constant-time сравнение с настроенным секретом; событие в `X-Gitlab-Event`; delivery в `X-Gitlab-Event-UUID` |
| **Bitbucket** | (Cloud) без HMAC | секрет в URL-пути + IP-allowlist Atlassian + опц. Basic-auth; (Server/DC) `X-Hub-Signature` HMAC; delivery в `X-Request-Id` / `X-Event-Key` |

Правила: сверяем по **сырому телу до парсинга JSON**; неверная/отсутствующая подпись →
`401`, инцидент в лог; пустой secret в конфиге запрещён (fail-closed). Идемпотентность —
по delivery-id + (repo, pr, head_sha) в Redis (TTL 24ч): повтор не порождает второй
прогон/дубли комментариев.

**Какие события слушаем:**
- GitHub: `pull_request` (`opened`, `synchronize`, `reopened`, `ready_for_review`),
  `pull_request_review_comment` / `issue_comment` (для C7 диалога).
- GitLab: `Merge Request Hook` (`open`, `update`, `reopen`), `Note Hook` (диалог).
- Bitbucket: `pullrequest:created`, `pullrequest:updated`,
  `pullrequest:comment_created` (диалог).

## 3. Выкачивание только diff (критерий C2)

Никогда не клонируем репозиторий целиком. Берём именно изменения:

- **GitHub:** `GET /repos/{o}/{r}/pulls/{n}/files` (пагинация) + при необходимости
  `GET /repos/{o}/{r}/pulls/{n}` для `base.sha`/`head.sha`; `patch`-поле каждого файла —
  готовый unified hunk. Для крупных diff — `Accept: application/vnd.github.diff`.
- **GitLab:** `GET /projects/{id}/merge_requests/{iid}/changes` (или `/diffs`) —
  `diffs[].diff`, `new_path`, `old_path`, `new_file/renamed_file/deleted_file`.
- **Bitbucket:** `GET /2.0/repositories/{ws}/{rs}/pullrequests/{id}/diff` (raw unified)
  + `/diffstat` для списка файлов.

Контекст для LLM — **только изменённые hunks + узкие N строк вокруг** (конфигурируемо,
дефолт 3), не весь файл. В аналитику пишем: число изменённых файлов/строк, размер diff в
токенах, оценку «сколько было бы при полном репозитории» → доказательство C2 на дашборде.

## 4. Построчные комментарии (критерий C4)

| Провайдер | API | Привязка к строке |
|---|---|---|
| **GitHub** | `POST /repos/{o}/{r}/pulls/{n}/comments` | `commit_id`=head_sha, `path`, `side=RIGHT`, `line`/`start_line` (или `position` по diff). Несколько находок — батчем через `POST /pulls/{n}/reviews` c `event=COMMENT` или `REQUEST_CHANGES` |
| **GitLab** | `POST /projects/{id}/merge_requests/{iid}/discussions` | `position`: `position_type=text`, `new_path`, `new_line`, `base_sha/head_sha/start_sha` |
| **Bitbucket** | `POST /2.0/.../pullrequests/{id}/comments` | `inline`: `{ "path", "to": <new_line> }` |

Если строку не удалось сматчить на правую сторону diff (например, находка в удалённом
контексте) — комментарий деградирует до file-level с явной пометкой строки в тексте, а не
теряется.

## 5. Сниппет-исправление (критерий C5)

Используем нативные suggestion-блоки (применяются автором в один клик):

- **GitHub / Bitbucket / GitLab** поддерживают \`\`\`suggestion … \`\`\` в теле inline-комментария
  (GitLab — `suggestion:-k+n`). Renderer формирует синтаксически валидную замену именно
  изменённых строк. Если правка многострочная/структурная и не ложится в suggestion —
  прикладываем unified-diff патч в fenced-блоке + текстовую инструкцию.

## 6. Блокировка merge (критерий C8)

Бот **не аппрувит** (финал — тимлид). Блокировка реализована как **падающий required
status check**, который ветка-protection не даёт обойти не-админу:

- **GitHub:** `POST /repos/{o}/{r}/statuses/{sha}` или Checks API
  (`conclusion=failure`), контекст `aegis/security`; в branch protection этот чек —
  required. Дополнительно `reviews` c `event=REQUEST_CHANGES` от сервисного аккаунта.
- **GitLab:** внешний статус через Commit Status API (`state=failed`,
  `name=aegis/security`); опц. MR approval rule / blocking. Merge при `failed` запрещён,
  если включено «Pipelines must succeed»/external status.
- **Bitbucket:** Build Status API (`state=FAILED`, key `aegis-security`); merge-check
  «Minimum successful builds» блокирует слияние.

Срабатывает по политике репо: дефолт — только `Critical` (настраивается до
`High`/`off`). Override — ручное действие тимлида (re-run чека, admin-merge): право
блокировки за ботом, право разблокировки за человеком — точно по постановке задачи.

## 7. Диалог в треде (критерий C7)

При webhook о новом комментарии: фильтруем (только @mention бота ИЛИ прямой reply на
комментарий бота; игнор других ботов и собственных сообщений), достаём тред
(`get_thread`) + исходную находку (по scan-id/finding-id, хранится в БД при постинге) →
отвечаем `reply_in_thread`. Состояние треда персистится; guard: ≤ N реплик на тред,
rate-limit на пользователя, anti-loop.

## 8. Сервисный аккаунт и токены

- **GitHub:** предпочтительно **GitHub App** (инсталляционный токен, узкие
  permissions: PR read/write, checks write, contents read; webhook на уровне App).
  Альтернатива — machine-user + fine-grained PAT.
- **GitLab:** отдельный service account / project access token с ролью Reporter+ и
  скоупом `api`.
- **Bitbucket:** workspace app password / OAuth consumer у выделенного пользователя-бота.

Все токены — только в зашифрованном vault (`08`, `10`), никогда не в логах, передаются в
provider-клиент через короткоживущий контекст. Минимальные scope. Ротация — операция в
Admin Portal.

## 9. Тестирование интеграции

- Контрактные тесты на каждый провайдер с записанными фикстурами реальных webhook/API
  ответов (`respx`-моки) + локальный тестовый репозиторий для e2e (организаторы единый
  пул не дают — поднимаем свой, см. `07`/`12`).
- Negative: битая подпись, повтор delivery, переименование файла, бинарь, пустой diff,
  огромный diff, удалённый файл, force-push (смена head_sha).
