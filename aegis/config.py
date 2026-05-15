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
    # infosec specialist (don-agent-v3 / qwen3 finetuned)
    lmstudio_secure_model: str = Field("don-agent-v3", alias="LMSTUDIO_SECURE_MODEL")
    # generalist security analyst (large reasoning model)
    lmstudio_generalist_model: str = Field(
        "qwen3.6-35b-a3b-ud-mlx", alias="LMSTUDIO_GENERALIST_MODEL"
    )
    # judge (consolidation) — defaults to generalist if not set
    lmstudio_judge_model: str = Field(
        "qwen3.6-35b-a3b-ud-mlx", alias="LMSTUDIO_JUDGE_MODEL"
    )
    lmstudio_base_model: str = Field(
        "qwen3.6-35b-a3b-ud-mlx", alias="LMSTUDIO_BASE_MODEL"
    )
    lmstudio_embed_model: str = Field(
        "text-embedding-nomic-embed-text-v1.5", alias="LMSTUDIO_EMBED_MODEL"
    )
    # Sequential model swap: unload previous model before loading next (saves RAM)
    lmstudio_swap_models: bool = Field(True, alias="LMSTUDIO_SWAP_MODELS")

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


class KbCfg(BaseModel):
    enabled: bool = True
    top_k: int = 3
    min_similarity: float = 0.78        # cosine; below this → not "similar"
    candidate_limit: int = 500          # most-recent entries scanned per repo
    embed_timeout_seconds: int = 20


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
    kb: KbCfg = Field(default_factory=KbCfg)
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
