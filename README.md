# Aegis — Security Code Review

AI-assisted PR security review: deterministic scanners + LLM ensemble, GitHub webhooks,
and a **React** control plane (Vite + Tailwind).

## Quick start (Docker — frontend + backend)

**Requirements:** Docker Desktop, `.env` in the repo root (copy from `backend/.env.example`).

1. **Generate vault key** (required once):

   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Put the value in `.env` as `AEGIS_VAULT_KEY=...`

2. **Build and run the full stack:**

   ```bash
   make docker-up
   ```

   This starts Postgres, Redis, API, worker, and the **React UI** (nginx).

3. **Open the app:**

   | What | URL |
   |------|-----|
   | **Web UI** | http://localhost:8099 |
   | Register | http://localhost:8099/register |
   | API docs | http://localhost:8099/docs |
   | Health | http://localhost:8099/healthz |

4. **Logs:**

   ```bash
   make docker-logs
   ```

5. **Stop:**

   ```bash
   make docker-down
   ```

## Local development (hot reload)

Run backend in Docker and frontend with Vite:

```bash
make docker-up          # API inside Docker (internal :8080)
make frontend-install   # once
make frontend-dev       # http://localhost:5173 → proxies to :8080
```

Or run only infra in Docker and API on the host — see [backend/README.md](backend/README.md).

## Project layout

```text
backend/     FastAPI, worker, pipeline, deploy/
frontend/    React + Vite UI, nginx image
docs/        Architecture and specs
Makefile     docker-up, frontend-dev, backend-check, …
```

## More docs

- [STATUS.md](STATUS.md) — project status (RU)
- [SPECIFICATION.md](SPECIFICATION.md) — full spec
- [frontend/README.md](frontend/README.md) — UI development
- [backend/README.md](backend/README.md) — backend commands
- [docs/11-deployment.md](docs/11-deployment.md) — deployment details
