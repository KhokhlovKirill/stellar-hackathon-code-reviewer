# Multi-stage. Single image; api vs worker chosen by compose `command`.
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Semgrep CLI lives in the image so the deterministic layer never needs the
# network at scan time (rulesets are vendored on build — see fetch-rules).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG GITLEAKS_VERSION=8.24.3
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) gitleaks_arch="x64" ;; \
        arm64) gitleaks_arch="arm64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac \
    && curl -sSfL \
       "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" \
       -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

FROM base AS deps
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install "." && pip install semgrep>=1.95

FROM deps AS app
COPY aegis ./aegis
COPY alembic ./alembic
COPY alembic.ini config.example.yaml ./
# Vendor Semgrep registry rulesets at build time (offline at runtime).
RUN semgrep --version && bandit --version && gitleaks version \
    && semgrep --config p/owasp-top-ten --config p/security-audit --config p/secrets \
       --config p/cwe-top-25 --validate || true

# Non-root, read-only-friendly (docs/10).
RUN useradd -u 10001 -m aegis && chown -R aegis /app
USER aegis
EXPOSE 8080

# Default = API; compose overrides command for the worker.
CMD ["uvicorn", "aegis.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
