"""Tests for hooks/ccusage/identity.py's user-email resolution."""

from __future__ import annotations

import os
import sys

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage import identity, project_settings  # noqa: E402
from ccusage.config import OPTION_SWITCH_TRUST_USER_EMAIL  # noqa: E402


def _isolate(monkeypatch, tmp_path) -> None:
    """Point state_dir()/project_settings at an empty, isolated location."""
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    monkeypatch.setattr(project_settings, "get", lambda option, default=None: default)


def test_get_user_email_throttles_retries_after_all_fallbacks_fail(
    tmp_path, monkeypatch
) -> None:
    """Once git/OS-username both fail, the chain isn't re-run on every call.

    Regression test: the anonymous-fallback path used to never be cached, so a
    user for whom all fallbacks fail re-ran the full (~5s worst-case)
    subprocess chain on every single hook invocation -- directly threatening
    the "hook must never block a session" design goal.
    """
    _isolate(monkeypatch, tmp_path)
    calls = {"n": 0}

    def _always_fails(*_args, **_kwargs):
        calls["n"] += 1
        return None

    monkeypatch.setattr(identity, "_email_from_git_config", _always_fails)
    monkeypatch.setattr(identity, "_os_username", _always_fails)

    first = identity.get_user_email()
    calls_after_first = calls["n"]
    second = identity.get_user_email()

    assert first == identity.ANONYMOUS_USER
    assert second == identity.ANONYMOUS_USER
    # Both fallbacks ran once for `first`; `second` was short-circuited by
    # the retry-throttle marker instead of re-running either of them.
    assert calls_after_first == 2
    assert calls["n"] == calls_after_first


def test_get_user_email_retries_after_interval_elapses(tmp_path, monkeypatch) -> None:
    """A later call, once the retry interval has passed, tries resolution again."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(identity, "_email_from_git_config", lambda *_a, **_k: None)
    monkeypatch.setattr(identity, "_os_username", lambda *_a, **_k: None)

    identity.get_user_email()

    retry_marker = os.path.join(tmp_path, "user_email.retry_at")
    with open(retry_marker, "w") as fh:
        fh.write("0")  # already-elapsed retry time

    monkeypatch.setattr(identity, "_os_username", lambda *_a, **_k: "someone")

    assert identity.get_user_email() == "someone"


def test_get_user_email_override_only_via_plugin_option(monkeypatch) -> None:
    """The email override is read via the switch_trust_user_email option, not a bare env var.

    Regression: a bare SWITCH_TRUST_USER_EMAIL is indistinguishable from a value
    injected by a project's .claude/settings.json env block, so it must not
    override attribution on its own.
    """
    option_env_var = f"CLAUDE_PLUGIN_OPTION_{OPTION_SWITCH_TRUST_USER_EMAIL.upper()}"
    monkeypatch.setenv("SWITCH_TRUST_USER_EMAIL", "attacker@example.com")
    monkeypatch.delenv(option_env_var, raising=False)

    assert project_settings.get(OPTION_SWITCH_TRUST_USER_EMAIL) is None

    monkeypatch.setenv(option_env_var, "real-user@example.com")

    assert (
        project_settings.get(OPTION_SWITCH_TRUST_USER_EMAIL) == "real-user@example.com"
    )


def test_no_gcloud_lookup() -> None:
    """Identity resolution must never shell out to gcloud or call a cloud userinfo
    endpoint -- using a customer's cloud credentials for this was undisclosed
    and unexpected. Regression guard beyond a one-off `grep -rn gcloud hooks/`.
    """
    assert not hasattr(identity, "_email_from_gcloud")
