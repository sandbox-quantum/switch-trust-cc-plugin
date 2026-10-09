"""Config resolution: every value comes from Claude Code's own plugin settings.

A `userConfig` field declared in `.claude-plugin/plugin.json` (e.g.
`switch_trust_api_key`) is set through Claude Code's `/config` UI, which injects
the resulting value into the hook process as `CLAUDE_PLUGIN_OPTION_<FIELD>`
(the field name, uppercased). `get()` resolves exactly that. See `config.py`'s
`OPTION_SWITCH_TRUST_*` constants for the field name backing each supported value.

A project's `.claude/settings*.json` `env` block can set the same name; a
saved `/config` value beats it, but an unsaved field takes the project's.
"""

from __future__ import annotations

import codecs
import json
import os
import re
from collections.abc import Callable
from functools import lru_cache

from .log import log

_PROJECT_SETTINGS_FILES = ("settings.json", "settings.local.json")


def _env_name(option: str) -> str:
    return f"CLAUDE_PLUGIN_OPTION_{option.upper()}"


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


class _UnreadableSettings(Exception):
    pass


def _read_env_block(path: str) -> dict[str, object]:
    """Claude Code accepts invalid UTF-8, huge integers and deep nesting; only
    a syntax error makes it ignore the file, so anything else must not read as empty."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return {}
    if raw.startswith(codecs.BOM_UTF8):
        raw = raw[len(codecs.BOM_UTF8) :]
    try:
        data = json.loads(
            raw.decode("utf-8", errors="replace"),
            parse_int=lambda _: 0,
            parse_float=lambda _: 0.0,
            parse_constant=lambda _: 0.0,
        )
    except json.JSONDecodeError:
        return {}
    except Exception as exc:
        raise _UnreadableSettings(path) from exc
    env = data.get("env") if isinstance(data, dict) else None
    return env if isinstance(env, dict) else {}


@lru_cache(maxsize=1)
def _project_env() -> dict[str, object] | None:
    """None if unparseable. Claude Code reads only `CLAUDE_PROJECT_DIR` (not the git
    root or `--add-dir`), sets that itself, and lets settings.local.json win."""
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project_dir:
        return {}
    merged: dict[str, object] = {}
    for name in _PROJECT_SETTINGS_FILES:
        try:
            merged.update(_read_env_block(os.path.join(project_dir, ".claude", name)))
        except _UnreadableSettings:
            return None
    return merged


def _project_supplied(option: str, value: str) -> bool:
    """A saved value beats the project's, so only a differing value is surely the
    user's. Non-strings are JS-stringified, which Python can't reproduce."""
    project_env = _project_env()
    if project_env is None:
        return True
    name = _env_name(option)
    if name not in project_env:
        return False
    supplied = project_env[name]
    if not isinstance(supplied, str):
        return True
    return _LONE_SURROGATE.sub("\ufffd", supplied) == value


def get(
    option: str,
    default: str | None = None,
    accept_from_project: Callable[[str], bool] | None = None,
) -> str | None:
    """Resolve a userConfig field; a possibly project-supplied value resolves to
    `default` unless `accept_from_project(value)` says it is safe either way."""
    value = os.environ.get(_env_name(option))
    if not value:
        return default
    if _project_supplied(option, value):
        if accept_from_project is not None and accept_from_project(value):
            return value
        log(f"ignoring {_env_name(option)} set by project settings")
        return default
    return value
