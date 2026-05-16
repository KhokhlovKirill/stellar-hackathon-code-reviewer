# Aegis — AI Security Code Review

Aegis is a production AI system that performs **security review of pull/merge
requests**. It acts as a dedicated review bot: it listens for VCS webhooks (or
takes a PR URL directly), pulls **only the changed diff**, runs it through a
deterministic + multi-model LLM ensemble, and posts precise, line-anchored
findings with severity, CWE, exploit path and a concrete fix — in the team's
configured language. A human tech lead still owns the merge decision; Aegis
removes the bottleneck of the first, obvious pass.

---

## What it does

- **Diff-only analysis.** Fetches just the PR diff (not the whole repo) — cheaper
  and faster, since ~90% of files don't change.
- **Deterministic detectors.** Secrets / high-entropy tokens, hardcoded
  credentials, unsafe patterns — fast, zero-LLM, high confidence.
- **LLM ensemble.** Two independent detectors (a cloud generalist via
  OpenRouter and the locally fine-tuned **Don** security model) run in
  parallel, then a judge consolidates and de-duplicates. A coordinator model
  writes the human-readable PR summary and short labels.
- **Inline PR comments.** Findings are posted under the exact code lines with
  CWE links, exploit scenario and a suggested patch, plus a review summary and
  a merge-gating status check.
- **Dialog.** Users can reply to a finding thread (`@secbot …`) and the bot
  answers in context.
- **Output language.** Summaries, finding rationale/exploit/fix and posted
  comments are produced in the configured language (`ru` / `en`), selectable
  in the web Settings page and the VS Code extension.

---

## Architecture

```
                    GitHub / GitLab / Bitbucket
                     (incl. self-hosted GitLab)
                              │  webhook
                              ▼
                    ┌──────────────────────┐
   PR URL  ───────► │   Aegis API (FastAPI)│
   (pull mode)      │  /api  /webhooks     │
                    └─────────┬────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                                ▼
     Deterministic detectors          LLM ensemble
     (secrets / entropy / SAST)       ┌───────────────────────────┐
                                      │ detector A: OpenRouter     │
                                      │ detector B: Don (local MLX)│
                                      │ judge: consolidate/dedupe  │
                                      │ coordinator: summary+labels│
                                      └───────────────────────────┘
              └───────────────┬───────────────┘
                              ▼
        risk scoring → render → publish (inline comments + status)
                              │
                  Postgres • Redis • ARQ worker
```

Two orchestration paths share **one** pipeline implementation:

- **Direct** (`run_simple_scan`) — the default synchronous path.
- **LangGraph** (`aegis/graph/`) — the same stages lifted into a typed
  `StateGraph` (parse → fetch → filter → deterministic → llm → review →
  finalize) with per-node tracing and graceful short-circuits. Selected via
  `AEGIS_USE_LANGGRAPH=1` or per request (`engine: auto|graph|direct`).

### Components

| Area | Stack |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy, Alembic, ARQ, Postgres, Redis |
| Orchestration | direct pipeline + optional LangGraph DAG |
| LLM routing | OpenRouter (cloud) + LM Studio / MLX (local Don) with tiered fallback and hard time budgets |
| Web UI | React + Vite SPA (streaming chat, scan/review, settings, ru/en) |
| Editor | VS Code extension (PR/findings sidebar, streaming chat, robust Apply Patch) |
| Observability | structlog, Prometheus metrics, Grafana provisioning |

---

## Models

- **Cloud (OpenRouter).** Generalist + judge + coordinator tiers, configured
  via `OPENROUTER_*` env. Fast, used as the primary path.
- **Don (local).** `don-agent-v3` — a Qwen3-Coder-30B-A3B model fine-tuned
  (SFT + ORPO) for security / CTF / pentest reasoning, served by LM Studio
  (MLX) on Apple Silicon. Don is a **mandatory** ensemble member, not just a
  fallback: every scan gets an independent Don pass.

In the production deployment the Mac runs **only** the MLX server with Don.
The backend stack runs on the VPS and reaches Don over a persistent,
auto-healing reverse SSH tunnel (autossh + launchd), bound to the Docker
bridge so it is never publicly exposed. Every LLM call is wrapped in a hard
time budget, so a slow or saturated local model degrades gracefully instead
of hanging the request.

---

## Running locally

```bash
# backend stack (api, worker, web, postgres, redis)
docker compose -f backend/deploy/docker-compose.yml up -d
# api  → http://localhost:8080
# web  → http://localhost:8099

# checks
cd backend
../.venv/bin/ruff check aegis
../.venv/bin/mypy aegis
../.venv/bin/python -m pytest -q
```

Environment lives in a root `.env` (never committed). Key variables:

```
OPENROUTER_API_KEY=...
AEGIS_VAULT_KEY=...                 # Fernet key for stored secrets
AEGIS_DATABASE_URL=postgresql+asyncpg://aegis:aegis@postgres:5432/aegis
AEGIS_REDIS_URL=redis://redis:6379/0
LMSTUDIO_BASE_URL=http://host.docker.internal:1234/v1
LMSTUDIO_SWAP_MODELS=false
GITLAB_BASE_URL=https://gitlab.com  # set to a self-hosted instance if used
AEGIS_USE_LANGGRAPH=0               # 1 to route scans through LangGraph
```

### VS Code extension

```bash
cd frontend/vscode-extension
node esbuild.mjs && npx vsce package --no-dependencies --allow-missing-repository
code --install-extension aegis-security-0.1.0.vsix --force
```

The extension defaults to the production backend; override with the
`aegis.backendUrl` setting for local development.

---

## Deployment

The production deployment serves the React UI + API behind nginx with
Let's Encrypt TLS at **https://aegis.khokhlovkirill.ru**, with the full stack
in Docker on the VPS and Don reached from the Mac over the reverse tunnel.

- HTTP → HTTPS redirect, HTTP/2, long-timeout proxy for streaming/long scans.
- Web + API bound to localhost on the host; only nginx is public (UFW).
- Self-hosted GitLab is supported: the GitLab API base is taken from the
  webhook payload host (auto), or `GITLAB_BASE_URL`.

---

## Security

- Stored VCS tokens are encrypted at rest (Fernet, `AEGIS_VAULT_KEY`).
- Webhook signatures are verified over the raw body per provider.
- Diff/context is always treated as untrusted data in prompts.
- Secrets never leave the env; `.env` and key material are git-ignored.
