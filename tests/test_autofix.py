"""Unit tests for the autofix pipeline stage."""

from __future__ import annotations

from aegis.pipeline.autofix import _env_var_name, _patch_dep_bump, _patch_secret_to_env


def test_patch_secret_to_env_python_assignment() -> None:
    content = 'import something\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nFOO = 1\n'
    patched = _patch_secret_to_env(content, 2, "AWS_KEY")
    assert patched is not None
    assert 'os.getenv("AWS_KEY", "")' in patched
    assert "import os" in patched
    assert "AKIAIOSFODNN7EXAMPLE" not in patched


def test_patch_secret_already_has_import() -> None:
    content = "import os\nSECRET = 'abc'\n"
    patched = _patch_secret_to_env(content, 2, "SECRET")
    assert patched is not None
    assert patched.count("import os") == 1


def test_patch_secret_non_assignment_line() -> None:
    content = "def foo():\n    pass\n"
    assert _patch_secret_to_env(content, 1, "X") is None


def test_patch_secret_out_of_range() -> None:
    content = "x = 1\n"
    assert _patch_secret_to_env(content, 99, "X") is None


def test_patch_dep_bump_requirements_txt() -> None:
    content = "flask==1.0.0\nrequests==2.20.0\nnumpy==1.21.0\n"
    patched = _patch_dep_bump(content, "sca:requests", "upgrade to 2.28.0")
    assert patched is not None
    assert "requests==2.28.0" in patched
    assert "flask==1.0.0" in patched  # untouched


def test_patch_dep_bump_no_version_in_fix() -> None:
    assert _patch_dep_bump("requests==2.20.0\n", "sca:requests", "upgrade to latest") is None


def test_patch_dep_bump_package_not_found() -> None:
    content = "flask==1.0.0\n"
    assert _patch_dep_bump(content, "sca:django", "upgrade to 4.2.0") is None


def test_env_var_name_strips_extension() -> None:
    name = _env_var_name("config/settings.py", 5)
    assert name.startswith("CONFIG_SETTINGS")
    assert "L5" in name
    assert "." not in name
