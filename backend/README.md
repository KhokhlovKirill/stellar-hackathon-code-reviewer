# Backend

FastAPI, ARQ worker, pipeline, providers, migrations, tests, and Docker deploy files.

## Docker (full stack with React UI)

From the **repository root**:

```bash
# .env must include AEGIS_VAULT_KEY (see backend/.env.example)
make docker-up
```

| Service | Role |
|---------|------|
| `api` | FastAPI on :8080 (internal) |
| `worker` | ARQ scan worker |
| `web` | React UI + nginx on **http://localhost:8099** |
| `postgres`, `redis` | Data stores |

```bash
make docker-logs    # api, worker, web
make docker-down
```

## From this directory

```bash
make install
make check
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

Compose build context is the repo root (`../..`) so both `backend/` and `frontend/` are available.

## Root Makefile shortcuts

```bash
make backend-check
make docker-build
make docker-up
```
