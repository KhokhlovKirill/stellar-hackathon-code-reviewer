"""Autofix stage: open a remediation PR for actionable findings.

Two autofix strategies implemented:
  secret  — move hardcoded credential to .env and replace with os.getenv() call
  dep     — bump a pinned vulnerable dependency to its fixed version in requirements.txt

The stage only runs when:
  - state.ctx.access_token is set
  - at least one finding has fix_is_suggestion=True and a non-empty fix
  - the finding is a secret (CWE-798/321/259) or vulnerable dep (CWE-1395/937)

On any VCS error the stage logs a warning and sets state.result.degraded; it never
raises, so the rest of the pipeline continues.
"""

from __future__ import annotations

import base64
import re

from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState
from aegis.providers import get_provider
from aegis.schemas import Finding, FindingSource

log = get_logger("aegis.autofix")

_SECRET_CWES = {"CWE-798", "CWE-321", "CWE-259", "CWE-312"}
_DEP_CWES = {"CWE-1395", "CWE-937"}

# Patterns for manifest filenames handled by the dep-bump strategy
_MANIFEST_RE = re.compile(r"requirements.*\.txt$|pyproject\.toml$|package\.json$|go\.mod$")


def _is_secret_finding(f: Finding) -> bool:
    return bool(f.cwe and f.cwe in _SECRET_CWES) or f.source is FindingSource.DETERMINISTIC


def _is_dep_finding(f: Finding) -> bool:
    return bool(f.cwe and f.cwe in _DEP_CWES)


def _env_var_name(path: str, line: int) -> str:
    """Derive a reasonable env var name from file path + line context."""
    stem = re.sub(r"[^A-Z0-9]", "_", path.upper().rsplit(".", 1)[0])
    return f"{stem}_SECRET_L{line}"


def _patch_secret_to_env(content: str, line: int, env_var: str) -> str | None:
    """Replace the value on `line` (1-indexed) with os.getenv(env_var).

    Supports both Python assignment patterns:
      KEY = "value"  →  KEY = os.getenv("KEY", "")
    Returns None if the line doesn't match an assignment pattern.
    """
    lines = content.splitlines(keepends=True)
    if line < 1 or line > len(lines):
        return None
    target = lines[line - 1]
    match = re.match(r'^(\s*\w+\s*=\s*)["\']([^"\']+)["\']', target)
    if not match:
        return None
    var_name = target.split("=")[0].strip()
    lines[line - 1] = f'{match.group(1)}os.getenv("{var_name}", "")\n'
    # Prepend import if not already present
    joined = "".join(lines)
    if "import os" not in joined:
        joined = "import os\n" + joined
    return joined


def _patch_dep_bump(content: str, rule_id: str, fix: str | None) -> str | None:
    """Bump a pinned dep to the fixed version stated in the finding's fix field.

    Handles requirements.txt lines:  package==X.Y.Z
    Extracts target version from `fix` string, e.g. "upgrade to 2.28.0".
    """
    if not fix:
        return None
    ver_match = re.search(r"\b(\d+\.\d+[\.\d]*)\b", fix)
    if not ver_match:
        return None
    target_ver = ver_match.group(1)
    # rule_id from SCA findings is "sca:<package_name>"
    pkg = rule_id.replace("sca:", "").split(">")[0].strip()
    if not pkg:
        return None
    patched = re.sub(
        rf"(?im)^({re.escape(pkg)})\s*==\s*[\d.]+",
        rf"\g<1>=={target_ver}",
        content,
    )
    return patched if patched != content else None


async def generate_autofix(state: PipelineState) -> None:
    if not state.ctx.access_token:
        return

    actionable = [
        f for f in state.findings
        if f.fix_is_suggestion and f.fix and (_is_secret_finding(f) or _is_dep_finding(f))
    ]
    if not actionable:
        return

    provider = get_provider(state.ev.provider)
    branch_name = f"aegis/autofix/{state.scan_id[:12]}"

    try:
        default_branch = await provider.get_default_branch(state.pr, state.ctx.access_token)
        await provider.create_branch(
            state.pr, state.ctx.access_token, branch_name, state.pr.head_sha
        )
    except Exception as exc:
        log.warning("autofix.branch_failed", scan_id=state.scan_id, error=str(exc))
        state.result.degraded.append("autofix:branch")
        return

    committed: list[str] = []
    env_additions: list[str] = []  # lines to append to .env.example

    for finding in actionable:
        try:
            raw = await provider.fetch_file(state.pr, state.ctx.access_token, finding.file)
            if not raw:
                continue

            if _is_secret_finding(finding):
                env_var = _env_var_name(finding.file, finding.line)
                patched = _patch_secret_to_env(raw, finding.line, env_var)
                if not patched:
                    continue
                env_additions.append(f"{env_var}=REPLACE_ME")
                content_b64 = base64.b64encode(patched.encode()).decode()
                await provider.create_or_update_file(
                    state.pr, state.ctx.access_token, branch_name, finding.file,
                    content_b64,
                    f"fix: move hardcoded credential to env ({finding.file}:{finding.line})",
                )
                committed.append(finding.file)

            elif _is_dep_finding(finding) and _MANIFEST_RE.search(finding.file):
                patched = _patch_dep_bump(raw, finding.rule_id or "", finding.fix)
                if not patched:
                    continue
                content_b64 = base64.b64encode(patched.encode()).decode()
                await provider.create_or_update_file(
                    state.pr, state.ctx.access_token, branch_name, finding.file,
                    content_b64,
                    f"fix: bump vulnerable dependency ({finding.title})",
                )
                committed.append(finding.file)

        except Exception as exc:
            log.warning(
                "autofix.file_patch_failed",
                scan_id=state.scan_id,
                file=finding.file,
                error=str(exc),
            )

    if env_additions:
        env_example = "\n".join(env_additions) + "\n"
        content_b64 = base64.b64encode(env_example.encode()).decode()
        try:
            await provider.create_or_update_file(
                state.pr, state.ctx.access_token, branch_name, ".env.example",
                content_b64,
                "fix: add .env.example for rotated credentials",
            )
            committed.append(".env.example")
        except Exception as exc:
            log.warning("autofix.env_example_failed", scan_id=state.scan_id, error=str(exc))

    if not committed:
        log.info("autofix.nothing_committed", scan_id=state.scan_id)
        return

    body_lines = [
        "## Aegis Autofix",
        "",
        "This PR was automatically generated to remediate security findings in "
        f"#{state.pr.pr_id}.",
        "",
        "### Changes",
    ]
    for path in committed:
        body_lines.append(f"- `{path}`")
    body_lines += [
        "",
        "**Review carefully before merging.** Rotate any exposed secrets immediately.",
        f"\n_Aegis scan ID: `{state.scan_id}`_",
    ]

    try:
        url = await provider.open_pull_request(
            state.ctx.access_token,
            state.pr.repo_slug,
            f"[Aegis] Security autofix for PR #{state.pr.pr_id}",
            "\n".join(body_lines),
            branch_name,
            default_branch,
        )
        log.info(
            "autofix.pr_opened",
            scan_id=state.scan_id,
            files=len(committed),
            pr_url=url,
        )
    except Exception as exc:
        log.warning("autofix.open_pr_failed", scan_id=state.scan_id, error=str(exc))
        state.result.degraded.append("autofix:open_pr")
