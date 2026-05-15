# 08 — Admin Portal (control plane)

Портал позволяет администратору привязать репозиторий через токены и управлять политикой.
Бот при этом работает от **отдельного сервисного аккаунта** (`04 §8`).

## 1. Возможности

- **Регистрация репозитория:** провайдер (github/gitlab/bitbucket), идентификатор репо,
  способ аутентификации (GitHub App install / PAT / GitLab service-token / Bitbucket
  app-password), webhook-secret. Портал отдаёт готовый webhook URL и инструкцию по
  настройке вебхука в репо.
- **Проверка связи:** кнопка «Test connection» — портал дергает API провайдера от имени
  токена (минимальный read-запрос) и валидирует scope/permissions; показывает, чего не
  хватает.
- **Политика на репо:** severity-порог для inline/summary; merge-block policy
  (`off|critical|high`); ignored paths (доп. к дефолтным); ensemble-профиль (`06`);
  per-repo prompt-overrides; язык комментариев (ru/en); лимиты токенов/стоимости.
- **Просмотр:** список сканов, находок, диалогов; фид feedback (👍/👎 на комментарии);
  ссылки в аналитический дашборд (`09`).
- **Ротация токена / отвязка репо**, аудит изменений конфигурации (кто/что/когда).

## 2. Модель данных (Postgres)

`repositories(id, provider, external_id, slug, status, created_at)`,
`repo_secrets(repo_id, kind, ciphertext, nonce, created_at, rotated_at)` —
**только шифртекст**, `repo_policies(repo_id, severity_gate, merge_block, ignore_globs,
ensemble_profile, prompt_overrides, lang, budgets)`,
`admin_audit(id, actor, action, target, before, after, ts)`.

## 3. Token vault

- Симметричное шифрование (Fernet/AES-GCM), ключ — из `AEGIS_VAULT_KEY` (env/секрет-стор;
  в проде — KMS/Secrets Manager). Ключ **никогда** в БД и логах.
- Токены расшифровываются только в момент вызова provider-клиента, живут в памяти
  короткоживущего контекста, не сериализуются, не попадают в трейсы/исключения
  (redaction-фильтр в логгере, `10`).
- Ротация: новая версия секрета добавляется, старая помечается `rotated_at`, грейс-период,
  затем удаление шифртекста.
- Принцип наименьших привилегий: портал подсказывает минимальный набор scope на провайдер.

## 4. Аутентификация портала

- Портал — отдельная зона: вход по admin-credential (env-провижн первого админа) +
  сессии; CSRF на формах; rate-limit; все мутации — в `admin_audit`.
- В деплое за reverse-proxy/VPN; портал не выставляется в публичный интернет без
  TLS и аутентификации (см. `11`).

## 5. UI

FastAPI + server-rendered шаблоны (Jinja2) + минимальный JS — без тяжёлого SPA
(production-надёжность и простота деплоя приоритетнее). Страницы: Repos, Repo Detail
(policy + secrets + test), Scans, Scan Detail (findings + diff + LLM trace), Analytics
(встроенные панели/ссылка в Grafana), Audit.
