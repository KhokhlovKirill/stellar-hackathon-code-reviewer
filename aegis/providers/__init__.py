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
