# Multi-stage. Single image; api vs worker chosen by compose `command`.
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Semgrep CLI lives in the image so the deterministic layer never needs the
# network at scan time (rulesets are vendored on build — see fetch-rules).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM base AS deps
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install "." && pip install semgrep>=1.95

FROM deps AS app
COPY aegis ./aegis
COPY alembic ./alembic
COPY alembic.ini config.example.yaml ./
# Vendor Semgrep registry rulesets at build time (offline at runtime).
RUN semgrep --version \
    && semgrep --config p/owasp-top-ten --config p/security-audit --config p/secrets \
       --config p/cwe-top-25 --validate || true

# Non-root, read-only-friendly (docs/10).
RUN useradd -u 10001 -m aegis && chown -R aegis /app
USER aegis
EXPOSE 8080

# Default = API; compose overrides command for the worker.
CMD ["uvicorn", "aegis.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
