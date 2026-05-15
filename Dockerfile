FROM python:3.12-slim

# System dependencies for tree-sitter, semgrep, gitleaks, bandit
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep
RUN pip install --no-cache-dir semgrep

# Install gitleaks
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

WORKDIR /app

# Copy dependency manifest and package skeleton (editable install needs sources)
COPY pyproject.toml .
COPY aegis/ aegis/
COPY main.py .

# Install Python dependencies
RUN pip install --no-cache-dir setuptools wheel \
    && pip install --no-cache-dir -e ".[dev]"

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 aegis && chown -R aegis:aegis /app
USER aegis

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop"]
