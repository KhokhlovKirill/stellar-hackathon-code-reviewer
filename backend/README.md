# Backend

FastAPI, worker, pipeline, providers, database migrations, tests, eval harness and
deployment files live here.

Common commands from this directory:

```bash
make install
make check
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

From the repository root, use the wrapper targets:

```bash
make backend-check
make docker-build
make docker-up
```
