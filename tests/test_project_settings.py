"""Tests for hooks/ccusage/project_settings.py's config resolution.

`get()` resolves a plugin.json userConfig field from
`CLAUDE_PLUGIN_OPTION_<FIELD>` -- the value Claude Code injects into the hook
process once the field is set via `/config` -- and nothing else. A project's
own `.claude/settings.json` / `settings.local.json`, and a bare
`os.environ[name]` matching the field, must have no effect: Claude Code
copies a project's `env` block into every hook process's environment, so
without this guarantee a committed project file could silently override the
user's own Switch Trust API key, ingestion endpoint, report mode, or user-email
attribution.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage import project_settings  # noqa: E402
from ccusage.config import OPTION_SWITCH_TRUST_API_KEY  # noqa: E402

OPTION_VAR = "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    project_settings._project_env.cache_clear()
    yield
    project_settings._project_env.cache_clear()


def _project(tmp_path, monkeypatch, name: str, env: dict) -> None:
    _write_settings(str(tmp_path), name, env)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))


def _write_settings(project_dir: str, name: str, env: dict) -> None:
    claude_dir = os.path.join(project_dir, ".claude")
    os.makedirs(claude_dir, exist_ok=True)
    with open(os.path.join(claude_dir, name), "w") as fh:
        json.dump({"env": env}, fh)


def test_ignores_project_settings_json(tmp_path, monkeypatch) -> None:
    """A project's committed settings.json must never influence a resolved value.

    This plugin doesn't read the file directly, but assert the negative
    outcome (not just the absence of file-reading code) so a future
    regression -- reintroducing a read of this file -- is still caught.
    """
    project_dir = str(tmp_path)
    _write_settings(
        project_dir, "settings.json", {"SWITCH_TRUST_API_KEY": "sk_attacker"}
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", project_dir)
    monkeypatch.delenv("SWITCH_TRUST_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", raising=False)

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY, "fallback") == "fallback"


def test_ignores_bare_process_env_var(monkeypatch) -> None:
    """Regression: Claude Code injects a project's `env` block as a real process
    env var, so a bare `os.environ[name]` is indistinguishable from an
    attacker-controlled project file. Only CLAUDE_PLUGIN_OPTION_* may resolve.
    """
    monkeypatch.setenv("SWITCH_TRUST_API_KEY", "injected-by-project-settings")
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", raising=False)

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_resolves_from_plugin_option(monkeypatch) -> None:
    """A marketplace-set userConfig value (CLAUDE_PLUGIN_OPTION_<KEY>) is honored."""
    monkeypatch.delenv("SWITCH_TRUST_API_KEY", raising=False)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", "from-user-config")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) == "from-user-config"


def test_plugin_option_wins_even_with_a_same_named_env_var_set(monkeypatch) -> None:
    """A same-named env var must not win over, or even be read alongside, the option.

    A real shell/CI env var and one Claude Code injected from a project's
    settings file are indistinguishable, so only CLAUDE_PLUGIN_OPTION_* can
    resolve a value here.
    """
    monkeypatch.setenv("SWITCH_TRUST_API_KEY", "from-shell")
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", "from-user-config")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) == "from-user-config"


def test_returns_default_when_option_unset(monkeypatch) -> None:
    """No option env var set at all -- falls back to the default, not os.environ."""
    monkeypatch.delenv("SWITCH_TRUST_UNSET_EXAMPLE", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_UNSET_EXAMPLE", raising=False)

    assert project_settings.get("switch_trust_unset_example", "fallback") == "fallback"


def test_unsaved_option_supplied_by_project_resolves_to_default(
    tmp_path, monkeypatch
) -> None:
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: "sk_attacker"})
    monkeypatch.setenv(OPTION_VAR, "sk_attacker")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY, "fallback") == "fallback"


def test_project_settings_local_json_is_checked(tmp_path, monkeypatch) -> None:
    _project(tmp_path, monkeypatch, "settings.local.json", {OPTION_VAR: "sk_attacker"})
    monkeypatch.setenv(OPTION_VAR, "sk_attacker")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_saved_option_that_differs_from_project_value_is_honored(
    tmp_path, monkeypatch
) -> None:
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: "sk_attacker"})
    monkeypatch.setenv(OPTION_VAR, "sk_user")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) == "sk_user"


def test_settings_local_json_wins_over_settings_json(tmp_path, monkeypatch) -> None:
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: "sk_shared"})
    _write_settings(str(tmp_path), "settings.local.json", {OPTION_VAR: "sk_local"})

    monkeypatch.setenv(OPTION_VAR, "sk_local")
    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None

    monkeypatch.setenv(OPTION_VAR, "sk_shared")
    project_settings._project_env.cache_clear()
    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) == "sk_shared"


def test_non_string_project_value_is_treated_as_project_supplied(
    tmp_path, monkeypatch
) -> None:
    """Claude Code renders 1e3 as "1000"; Python would render "1000.0"."""
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: 1e3})
    monkeypatch.setenv(OPTION_VAR, "1000")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_settings_file_with_utf8_bom_is_read(tmp_path, monkeypatch) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps({"env": {OPTION_VAR: "sk_attacker"}}).encode()
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv(OPTION_VAR, "sk_attacker")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_unparseable_settings_file_is_ignored(tmp_path, monkeypatch) -> None:
    """Claude Code drops a settings file that isn't strict JSON, so it injects nothing."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text('{"env": {"%s": "sk_x",},}' % OPTION_VAR)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv(OPTION_VAR, "sk_user")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) == "sk_user"


def test_accept_from_project_can_keep_an_ambiguous_value(tmp_path, monkeypatch) -> None:
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: "safe"})
    monkeypatch.setenv(OPTION_VAR, "safe")

    assert (
        project_settings.get(
            OPTION_SWITCH_TRUST_API_KEY, accept_from_project=lambda v: v == "safe"
        )
        == "safe"
    )
    assert (
        project_settings.get(
            OPTION_SWITCH_TRUST_API_KEY, "fallback", accept_from_project=lambda v: False
        )
        == "fallback"
    )


def _raw_project(tmp_path, monkeypatch, payload: bytes) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_bytes(payload)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))


def test_invalid_utf8_in_settings_file_is_still_read(tmp_path, monkeypatch) -> None:
    payload = b'{"pad": "\xff", "env": {"%s": "sk_attacker"}}' % OPTION_VAR.encode()
    _raw_project(tmp_path, monkeypatch, payload)
    monkeypatch.setenv(OPTION_VAR, "sk_attacker")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_huge_integer_in_settings_file_is_still_read(tmp_path, monkeypatch) -> None:
    """Python 3.10+ refuses to parse integers past 4300 digits; Claude Code does not."""
    payload = b'{"env": {"%s": "sk_attacker"}, "pad": %s}' % (
        OPTION_VAR.encode(),
        b"9" * 5000,
    )
    _raw_project(tmp_path, monkeypatch, payload)
    monkeypatch.setenv(OPTION_VAR, "sk_attacker")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None


def test_settings_python_cannot_parse_treat_every_option_as_project_supplied(
    tmp_path, monkeypatch
) -> None:
    """Claude Code parses nesting deeper than Python's recursion limit allows."""
    _project(tmp_path, monkeypatch, "settings.json", {OPTION_VAR: "sk_attacker"})
    monkeypatch.setenv(OPTION_VAR, "sk_user")

    def too_deep(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(project_settings.json, "loads", too_deep)

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY, "fallback") == "fallback"


def test_lone_surrogate_is_compared_as_claude_code_injects_it(
    tmp_path, monkeypatch
) -> None:
    payload = b'{"env": {"%s": "sk_\\ud800"}}' % OPTION_VAR.encode()
    _raw_project(tmp_path, monkeypatch, payload)
    monkeypatch.setenv(OPTION_VAR, "sk_\ufffd")

    assert project_settings.get(OPTION_SWITCH_TRUST_API_KEY) is None
