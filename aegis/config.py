"""Application-wide configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    app_secret_key: str = "change-me-32-bytes-random-secret"
    log_level: str = "INFO"

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://aegis:aegis@localhost:5432/aegis"
    database_sync_url: str = "postgresql+psycopg2://aegis:aegis@localhost:5432/aegis"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_ttl_seconds: int = 604800  # 7 days

    # ── LLM ──────────────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    openrouter_api_key: str = ""
    openai_api_key: str = ""

    primary_llm_model: str = "claude-sonnet-4-5"
    fallback_llm_model: str = "qwen/qwen3-coder-30b"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    llm_max_tokens: int = 16_000
    llm_temperature: float = 0.1
    llm_timeout: int = 120
    llm_max_retries: int = 2

    # ── Encryption ───────────────────────────────────────────────────────────
    fernet_key: str = ""

    # ── JWT ──────────────────────────────────────────────────────────────────
    jwt_secret_key: str = "change-me-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 1440

    # ── Webhooks ─────────────────────────────────────────────────────────────
    github_webhook_secret: str = ""
    gitlab_webhook_secret: str = ""

    # ── LangSmith ────────────────────────────────────────────────────────────
    langchain_tracing_v2: bool = False
    langchain_api_key: str = ""
    langchain_project: str = "aegis"

    # ── OpenTelemetry ────────────────────────────────────────────────────────
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "aegis"

    # ── Risk Engine ──────────────────────────────────────────────────────────
    risk_block_threshold: int = 60

    # ── Auth ─────────────────────────────────────────────────────────────────
    admin_username: str = "admin"
    admin_password: str = "admin"
    jwt_refresh_secret_key: str = "change-me-refresh-secret"

    # ── Worker ───────────────────────────────────────────────────────────────
    worker_concurrency: int = 10
    worker_max_jobs: int = 10
    worker_job_timeout: int = 600
    max_diff_size_kb: int = 500
    max_files_per_scan: int = 100
    max_retro_files: int = 500
    max_graph_execution_seconds: int = 900  # 15 min

    # ── Embeddings ───────────────────────────────────────────────────────────
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = 1536

    @field_validator("fernet_key", mode="before")
    @classmethod
    def generate_fernet_key_if_empty(cls, v: str) -> str:
        if not v:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# Module-level convenience alias
settings = get_settings()
