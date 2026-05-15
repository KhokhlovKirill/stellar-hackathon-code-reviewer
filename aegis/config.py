<<<<<<< Updated upstream
"""Configuration: secrets from env (pydantic-settings), declarative knobs from YAML.

Fail-fast: invalid/missing required config raises ConfigError at startup, never silently.
Per-repo policy (DB) overrides the YAML defaults at scan time, not here.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from aegis.errors import ConfigError


# --------------------------------------------------------------------------- #
# Secrets / environment
# --------------------------------------------------------------------------- #
class Settings(BaseSettings):
    """Secrets and environment. Never logged, never written to YAML."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=True)

    env: Literal["dev", "prod"] = Field("dev", alias="AEGIS_ENV")
    config_file: str = Field("config.yaml", alias="AEGIS_CONFIG_FILE")
    log_level: str = Field("INFO", alias="AEGIS_LOG_LEVEL")

    database_url: str = Field(..., alias="AEGIS_DATABASE_URL")
    redis_url: str = Field(..., alias="AEGIS_REDIS_URL")

    vault_key: str = Field(..., alias="AEGIS_VAULT_KEY")

    admin_user: str = Field("admin", alias="AEGIS_ADMIN_USER")
    admin_password: str = Field("", alias="AEGIS_ADMIN_PASSWORD")

    github_webhook_secret: str = Field("", alias="AEGIS_GITHUB_WEBHOOK_SECRET")
    gitlab_webhook_secret: str = Field("", alias="AEGIS_GITLAB_WEBHOOK_SECRET")
    bitbucket_webhook_secret: str = Field("", alias="AEGIS_BITBUCKET_WEBHOOK_SECRET")

    openrouter_api_key: str = Field("", alias="OPENROUTER_API_KEY")
    openrouter_base_url: str = Field("https://openrouter.ai/api/v1", alias="OPENROUTER_BASE_URL")
    openrouter_generalist_model: str = Field(
        "qwen/qwen-2.5-coder-32b-instruct", alias="OPENROUTER_GENERALIST_MODEL"
    )
    openrouter_judge_model: str = Field(
        "anthropic/claude-3.7-sonnet", alias="OPENROUTER_JUDGE_MODEL"
    )

    lmstudio_base_url: str = Field("http://host.docker.internal:1234/v1", alias="LMSTUDIO_BASE_URL")
    lmstudio_secure_model: str = Field("don-agent-v3", alias="LMSTUDIO_SECURE_MODEL")
    lmstudio_base_model: str = Field(
        "qwen3.6-35b-a3b-ud-mlx", alias="LMSTUDIO_BASE_MODEL"
    )

    @field_validator("vault_key")
    @classmethod
    def _validate_vault_key(cls, v: str) -> str:
        from cryptography.fernet import Fernet

        if not v:
            raise ValueError("AEGIS_VAULT_KEY is required (Fernet key)")
        try:
            Fernet(v.encode())
        except Exception as exc:
            raise ValueError(f"AEGIS_VAULT_KEY is not a valid Fernet key: {exc}") from exc
        return v


# --------------------------------------------------------------------------- #
# Declarative config (YAML) — non-secret knobs
# --------------------------------------------------------------------------- #
class ServiceCfg(BaseModel):
    ack_timeout_ms: int = 1000
    max_webhook_body_bytes: int = 5_242_880
    idempotency_ttl_seconds: int = 86_400


class QueueCfg(BaseModel):
    per_repo_concurrency: int = 1
    max_retries: int = 5
    retry_backoff_base_seconds: int = 2


class DiffCfg(BaseModel):
    context_lines: int = 3
    max_files: int = 300
    max_total_added_lines: int = 20_000
    per_scan_token_budget: int = 120_000
    per_scan_cost_usd_cap: float = 0.50


class FilterCfg(BaseModel):
    ignore_globs: list[str] = Field(default_factory=list)
    sca_manifests: list[str] = Field(default_factory=list)
    max_file_bytes: int = 1_048_576


class DeterministicCfg(BaseModel):
    semgrep_configs: list[str] = Field(default_factory=list)
    secrets_min_entropy: float = 4.0
    sca_sources: list[str] = Field(default_factory=list)


class LLMCfg(BaseModel):
    ensemble_profile: Literal["det+cloud", "det+cloud+don", "det+don+judge"] = "det+don+judge"
    detector_a: str = "local-secure"
    detector_b: str = "cloud-generalist"
    judge: str = "cloud-judge"
    request_timeout_seconds: int = 120
    tier_health_ttl_seconds: int = 30
    fewshot_dir: str = "eval/fewshot"


class PolicyCfg(BaseModel):
    severity_comment_gate: Literal["info", "low", "medium", "high", "critical"] = "medium"
    merge_block: Literal["off", "critical", "high"] = "critical"
    comment_language: Literal["ru", "en"] = "ru"
    dialog_max_turns: int = 8


class ObservabilityCfg(BaseModel):
    prometheus_enabled: bool = True
    otel_enabled: bool = False
    otel_endpoint: str = ""


class AppConfig(BaseModel):
    service: ServiceCfg = Field(default_factory=ServiceCfg)
    queue: QueueCfg = Field(default_factory=QueueCfg)
    diff: DiffCfg = Field(default_factory=DiffCfg)
    filter: FilterCfg = Field(default_factory=FilterCfg)
    deterministic: DeterministicCfg = Field(default_factory=DeterministicCfg)
    llm: LLMCfg = Field(default_factory=LLMCfg)
    policy: PolicyCfg = Field(default_factory=PolicyCfg)
    observability: ObservabilityCfg = Field(default_factory=ObservabilityCfg)


# --------------------------------------------------------------------------- #
# Accessors (cached; fail-fast)
# --------------------------------------------------------------------------- #
@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
            return Settings()
    except ValidationError as exc:
        raise ConfigError(f"Invalid environment configuration:\n{exc}") from exc


@functools.lru_cache(maxsize=1)
def get_config() -> AppConfig:
    path = Path(get_settings().config_file)
    if not path.exists():
        # YAML is optional; pure defaults are valid for tests / minimal runs.
        return AppConfig()
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Cannot parse {path}: {exc}") from exc
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid {path}:\n{exc}") from exc


def reset_caches() -> None:
    """Test helper — drop cached settings/config."""
    get_settings.cache_clear()
    get_config.cache_clear()
=======
"""Application-wide configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
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
>>>>>>> Stashed changes
