"""Resolve a registered repository: its access token, webhook secret, policy.

Per-repo secrets (vault, set via Admin Portal in Phase 8) take precedence; the
per-provider env secret is the fallback so the gateway works before the portal
is populated. Plaintext is returned only to short-lived callers, never persisted.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from aegis.config import get_config, get_settings
from aegis.db import get_session
from aegis.db.models import RepoSecret, Repository
from aegis.schemas import Provider
from aegis.vault import decrypt


@dataclass(slots=True)
class RepoContext:
    repo_id: int | None
    provider: Provider
    slug: str
    access_token: str
    severity_gate: str
    merge_block: str
    ensemble_profile: str
    ignore_globs: list[str]
    lang: str


def _env_webhook_secret(p: Provider) -> str:
    s = get_settings()
    return {
        Provider.GITHUB: s.github_webhook_secret,
        Provider.GITLAB: s.gitlab_webhook_secret,
        Provider.BITBUCKET: s.bitbucket_webhook_secret,
    }[p]


async def webhook_secret(provider: Provider, repo_external_id: str) -> str:
    """Secret used to verify the webhook signature (per-repo vault, else env)."""
    async with get_session() as s:
        repo = (
            await s.execute(
                select(Repository).where(
                    Repository.provider == provider.value,
                    Repository.external_id == repo_external_id,
                )
            )
        ).scalar_one_or_none()
        if repo:
            row = (
                await s.execute(
                    select(RepoSecret)
                    .where(RepoSecret.repo_id == repo.id, RepoSecret.kind == "webhook_secret")
                    .order_by(RepoSecret.created_at.desc())
                )
            ).scalars().first()
            if row:
                return decrypt(row.ciphertext)
    return _env_webhook_secret(provider)


async def resolve(provider: Provider, repo_external_id: str, slug: str) -> RepoContext:
    cfg = get_config().policy
    async with get_session() as s:
        repo = (
            await s.execute(
                select(Repository).where(
                    Repository.provider == provider.value,
                    Repository.external_id == repo_external_id,
                )
            )
        ).scalar_one_or_none()
        token = ""
        gate: str = cfg.severity_comment_gate
        block: str = cfg.merge_block
        profile: str = get_config().llm.ensemble_profile
        lang: str = cfg.comment_language
        ignore: list[str] = []
        if repo:
            tok_row = (
                await s.execute(
                    select(RepoSecret)
                    .where(RepoSecret.repo_id == repo.id, RepoSecret.kind == "access_token")
                    .order_by(RepoSecret.created_at.desc())
                )
            ).scalars().first()
            if tok_row:
                token = decrypt(tok_row.ciphertext)
            if repo.policy:
                gate = repo.policy.severity_gate
                block = repo.policy.merge_block
                profile = repo.policy.ensemble_profile
                lang = repo.policy.lang
                ignore = list(repo.policy.ignore_globs or [])
        return RepoContext(
            repo_id=repo.id if repo else None,
            provider=provider, slug=slug, access_token=token,
            severity_gate=gate, merge_block=block,
            ensemble_profile=profile, ignore_globs=ignore, lang=lang,
        )
