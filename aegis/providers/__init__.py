<<<<<<< Updated upstream
"""Provider registry. `get_provider(Provider.X)` returns the singleton impl."""

from __future__ import annotations

from aegis.providers.base import VCSProvider
from aegis.providers.bitbucket import BitbucketProvider
from aegis.providers.github import GitHubProvider
from aegis.providers.gitlab import GitLabProvider
from aegis.schemas import Provider

_REGISTRY: dict[Provider, VCSProvider] = {
    Provider.GITHUB: GitHubProvider(),
    Provider.GITLAB: GitLabProvider(),
    Provider.BITBUCKET: BitbucketProvider(),
}


def get_provider(p: Provider) -> VCSProvider:
    return _REGISTRY[p]


__all__ = ["VCSProvider", "get_provider"]
=======
"""Git provider abstraction layer."""

from aegis.providers.base import BaseProvider, DiffFile, PRMetadata
from aegis.providers.github import GitHubProvider
from aegis.providers.gitlab import GitLabProvider


def get_provider(provider: str, token: str, repo_slug: str) -> BaseProvider:
    """Factory function — returns the correct provider implementation."""
    match provider.lower():
        case "github":
            return GitHubProvider(token=token, repo_slug=repo_slug)
        case "gitlab":
            return GitLabProvider(token=token, repo_slug=repo_slug)
        case _:
            raise ValueError(f"Unsupported provider: {provider}")


__all__ = ["BaseProvider", "DiffFile", "PRMetadata", "GitHubProvider", "GitLabProvider", "get_provider"]
>>>>>>> Stashed changes
