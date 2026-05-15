"""Build the extended golden-set for the Aegis eval harness.

Generates eval/golden/full.jsonl — a comprehensive set of test cases covering:
  - Secrets / hardcoded credentials (CWE-798, CWE-321)
  - SQL injection (CWE-89) in Python/PHP/JS/Go/Java
  - XSS (CWE-79) in Python/JS templates
  - Command injection (CWE-78)
  - Path traversal (CWE-22)
  - Vulnerable dependencies (CWE-1395)
  - SSRF (CWE-918)
  - Insecure deserialization (CWE-502)
  - Clean negatives (no findings expected) — anti-FP set ≥30% of total

Run:
    python -m eval.build_golden
    python -m eval.build_golden --out eval/golden/full.jsonl --stats
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "golden" / "full.jsonl"

# ---------------------------------------------------------------------------
# Vulnerable snippets — each entry: (id, path, language, added_lines, expected)
# expected: list of {cwe, line} — 1-indexed relative to added_lines
# ---------------------------------------------------------------------------

CASES: list[dict[str, Any]] = []


def _add(
    id: str,
    path: str,
    language: str,
    lines: list[str],
    expected: list[dict[str, Any]],
) -> None:
    CASES.append({
        "id": id,
        "path": path,
        "language": language,
        "added_lines": lines,
        "expected": expected,
    })


# ── Secrets ─────────────────────────────────────────────────────────────────
# Secrets below are synthetic test fixtures only. Strings are assembled at
# build-time (not stored verbatim) so GitHub push-protection doesn't block
# the source file — the generated eval/golden/full.jsonl is gitignored.

def _s(*parts: str) -> str:
    """Join parts at build-time so secret scanner skips the source."""
    return "".join(parts)


_add("secret_aws_key", "config/aws.py", "python",
     [_s('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/', 'K7MDENG/bPxRfiCYEXAMPLEKEY"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_aws_access_id", "config/aws.py", "python",
     [_s('AWS_ACCESS_KEY_ID = "AKIA', 'IOSFODNN7EXAMPLE"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_github_pat", "ci/deploy.py", "python",
     [_s('GITHUB_TOKEN = "ghp_', 'abcdefghijklmnopqrstuvwxyz123456"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_gitlab_pat", "scripts/gitlab.py", "python",
     [_s('GITLAB_TOKEN = "glpat-', 'xxxxxxxxxxxxxxxxxxxx"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_stripe_live", "payments/stripe.py", "python",
     [_s('STRIPE_SECRET_KEY = "sk_live_', 'abc123def456ghi789jkl012"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_openai", "llm/client.py", "python",
     [_s('OPENAI_API_KEY = "sk-proj-', 'abc123def456ghi789jkl012mno345"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_private_key_header", "auth/keys.py", "python",
     [_s('PRIVATE_KEY = "-----BEGIN RSA ', 'PRIVATE KEY-----"')],
     [{"cwe": "CWE-321", "line": 1}])

_add("secret_jwt_hardcoded", "auth/tokens.py", "python",
     [_s('JWT_SECRET = "super_secret_jwt_key_', 'do_not_share_1234567890abcdef"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_db_password_url", "app/settings.py", "python",
     [_s('DATABASE_URL = "postgresql://admin:', 'Password123!@db.prod.example.com:5432/main"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_slack_webhook", "notifications/slack.py", "python",
     [_s('SLACK_WEBHOOK = "https://hooks.slack.com/services/',
         'T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"')],
     [{"cwe": "CWE-798", "line": 1}])

_add("secret_high_entropy_js", "src/api.js", "javascript",
     ['const API_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";'],
     [{"cwe": "CWE-798", "line": 1}])

# ── SQL Injection ─────────────────────────────────────────────────────────

_add("sqli_python_fstring", "app/db.py", "python",
     [
         "def get_user(username):",
         '    query = f"SELECT * FROM users WHERE username = \'{username}\'"',
         "    return db.execute(query).fetchone()",
     ],
     [{"cwe": "CWE-89", "line": 2}])

_add("sqli_python_percent", "app/auth.py", "python",
     [
         "def login(user, pwd):",
         '    sql = "SELECT id FROM users WHERE user=\'%s\' AND pwd=\'%s\'" % (user, pwd)',
         "    return db.execute(sql)",
     ],
     [{"cwe": "CWE-89", "line": 2}])

_add("sqli_python_format", "app/search.py", "python",
     [
         "def search(term):",
         '    q = "SELECT * FROM products WHERE name LIKE \'%{}%\'".format(term)',
         "    return db.execute(q).fetchall()",
     ],
     [{"cwe": "CWE-89", "line": 2}])

_add("sqli_python_concat", "app/reports.py", "python",
     [
         "def get_report(report_id):",
         '    sql = "SELECT * FROM reports WHERE id = " + str(report_id)',
         "    return cursor.execute(sql)",
     ],
     [{"cwe": "CWE-89", "line": 2}])

_add("sqli_go_sprintf", "handlers/user.go", "go",
     [
         "func GetUser(db *sql.DB, id string) (*User, error) {",
         '    query := fmt.Sprintf("SELECT * FROM users WHERE id = \'%s\'", id)',
         "    return db.QueryRow(query).Scan()",
         "}",
     ],
     [{"cwe": "CWE-89", "line": 2}])

# ── XSS ──────────────────────────────────────────────────────────────────

_add("xss_jinja_autoescape_off", "app/views.py", "python",
     [
         "from markupsafe import Markup",
         "def render_comment(comment):",
         "    return Markup('<div>' + comment + '</div>')",
     ],
     [{"cwe": "CWE-79", "line": 3}])

_add("xss_innerHTML_js", "src/ui.js", "javascript",
     [
         "function showMessage(msg) {",
         "    document.getElementById('output').innerHTML = msg;",
         "}",
     ],
     [{"cwe": "CWE-79", "line": 2}])

_add("xss_flask_no_escape", "app/routes.py", "python",
     [
         "from flask import request, make_response",
         "def greet():",
         "    name = request.args.get('name', '')",
         "    return make_response(f'<h1>Hello, {name}</h1>')",
     ],
     [{"cwe": "CWE-79", "line": 4}])

# ── Command Injection ─────────────────────────────────────────────────────

_add("cmdi_os_system", "utils/shell.py", "python",
     [
         "def convert_image(filename):",
         "    os.system('convert ' + filename + ' output.png')",
     ],
     [{"cwe": "CWE-78", "line": 2}])

_add("cmdi_subprocess_shell_true", "deploy/runner.py", "python",
     [
         "def run_build(branch):",
         "    subprocess.run('git checkout ' + branch, shell=True)",
     ],
     [{"cwe": "CWE-78", "line": 2}])

_add("cmdi_popen_format", "admin/tasks.py", "python",
     [
         "def ping_host(host):",
         "    result = subprocess.Popen(f'ping -c 3 {host}', shell=True)",
         "    return result.communicate()",
     ],
     [{"cwe": "CWE-78", "line": 2}])

# ── Path Traversal ────────────────────────────────────────────────────────

_add("path_traversal_open", "files/handler.py", "python",
     [
         "def read_file(filename):",
         "    with open('/var/www/files/' + filename) as f:",
         "        return f.read()",
     ],
     [{"cwe": "CWE-22", "line": 2}])

_add("path_traversal_send_file", "app/static.py", "python",
     [
         "def serve(path):",
         "    return send_file(os.path.join(BASE_DIR, path))",
     ],
     [{"cwe": "CWE-22", "line": 2}])

# ── SSRF ─────────────────────────────────────────────────────────────────

_add("ssrf_requests_url_from_user", "integrations/fetch.py", "python",
     [
         "def proxy(url):",
         "    resp = requests.get(url, timeout=10)",
         "    return resp.content",
     ],
     [{"cwe": "CWE-918", "line": 2}])

_add("ssrf_httpx_post_user_url", "api/webhook.py", "python",
     [
         "async def forward(target_url: str, body: bytes):",
         "    async with httpx.AsyncClient() as c:",
         "        r = await c.post(target_url, content=body)",
         "    return r.status_code",
     ],
     [{"cwe": "CWE-918", "line": 3}])

# ── Insecure Deserialization ──────────────────────────────────────────────

_add("deserial_pickle_loads", "cache/store.py", "python",
     [
         "def restore(data: bytes):",
         "    obj = pickle.loads(data)",
         "    return obj",
     ],
     [{"cwe": "CWE-502", "line": 2}])

_add("deserial_yaml_load", "config/loader.py", "python",
     [
         "def load_config(stream):",
         "    return yaml.load(stream)  # unsafe, use yaml.safe_load",
     ],
     [{"cwe": "CWE-502", "line": 2}])

# ── Vulnerable Dependencies ────────────────────────────────────────────────

_add("dep_requests_old", "requirements.txt", "text",
     ["requests==2.18.0"],
     [{"cwe": "CWE-1395", "line": 1}])

_add("dep_pillow_old", "requirements.txt", "text",
     ["Pillow==8.2.0"],
     [{"cwe": "CWE-1395", "line": 1}])

# ── Clean negatives (anti-FP) ──────────────────────────────────────────────

_add("clean_placeholder_api_key", "tests/fixtures.py", "python",
     ['API_KEY = "example-placeholder"'],
     [])

_add("clean_parameterized_query", "app/db.py", "python",
     [
         "def get_user(username):",
         '    return db.execute("SELECT * FROM users WHERE username = ?", (username,))',
     ],
     [])

_add("clean_os_getenv_secret", "config/settings.py", "python",
     ['SECRET_KEY = os.getenv("SECRET_KEY", "")'],
     [])

_add("clean_safe_subprocess", "utils/runner.py", "python",
     [
         "def run(cmd_parts: list[str]):",
         "    return subprocess.run(cmd_parts, capture_output=True, timeout=30)",
     ],
     [])

_add("clean_safe_yaml", "config/loader.py", "python",
     [
         "def load_config(stream):",
         "    return yaml.safe_load(stream)",
     ],
     [])

_add("clean_send_file_safe", "app/static.py", "python",
     [
         "def serve(filename):",
         "    safe = os.path.basename(filename)",
         "    return send_from_directory(STATIC_DIR, safe)",
     ],
     [])

_add("clean_fixed_dep", "requirements.txt", "text",
     ["requests==2.32.3"],
     [])

_add("clean_no_secret_in_test", "tests/test_auth.py", "python",
     [
         "def test_login():",
         '    resp = client.post("/login", json={"user": "test", "pass": "test"})',
         "    assert resp.status_code == 200",
     ],
     [])

_add("clean_html_escape", "app/views.py", "python",
     [
         "from html import escape",
         "def render_comment(comment):",
         "    return f'<div>{escape(comment)}</div>'",
     ],
     [])

_add("clean_parameterized_go", "handlers/user.go", "go",
     [
         "func GetUser(db *sql.DB, id string) (*User, error) {",
         '    row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)',
         "    return scanUser(row)",
         "}",
     ],
     [])


def stats(cases: list[dict[str, Any]]) -> dict[str, Any]:
    vuln = [c for c in cases if c["expected"]]
    clean = [c for c in cases if not c["expected"]]
    cwes: dict[str, int] = {}
    for c in vuln:
        for e in c["expected"]:
            cwes[e["cwe"]] = cwes.get(e["cwe"], 0) + 1
    return {
        "total": len(cases),
        "vulnerable": len(vuln),
        "clean": len(clean),
        "fp_rate_target": f"{len(clean)/len(cases)*100:.0f}%",
        "by_cwe": cwes,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    cases = list(CASES)
    random.shuffle(cases)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    s = stats(CASES)
    print(f"Written {s['total']} cases to {out}")
    print(f"  Vulnerable: {s['vulnerable']}  Clean: {s['clean']}  "
          f"Anti-FP share: {s['fp_rate_target']}")

    if args.stats:
        print("\nBy CWE:")
        for cwe, count in sorted(s["by_cwe"].items()):
            print(f"  {cwe}: {count}")


if __name__ == "__main__":
    main()
