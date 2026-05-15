"""Security Knowledge Base — embedding index of confirmed findings.

Enables cross-PR memory ("similar to a finding in PR #142"), the differentiator
called out in docs/02 vs Qodo Aware / Semgrep Assistant Memories.
"""

from aegis.kb.store import index_finding, query_similar

__all__ = ["index_finding", "query_similar"]
