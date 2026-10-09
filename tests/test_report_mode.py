"""Tests for ccusage_reporter's report-mode resolution against project settings."""

from __future__ import annotations

import json
import os
import sys

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

import ccusage_reporter  # noqa: E402
from ccusage import project_settings  # noqa: E402
from ccusage.config import (  # noqa: E402
    REPORT_MODE_CONDENSED,
    REPORT_MODE_FULL,
    REPORT_MODE_NONE,
    REPORT_MODE_TEXT,
    VALID_REPORT_MODES,
)

MODE_VAR = "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_MODE"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.delenv(MODE_VAR, raising=False)
    project_settings._project_env.cache_clear()
    yield
    project_settings._project_env.cache_clear()


def _project_mode(tmp_path, monkeypatch, mode: str) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps({"env": {MODE_VAR: mode}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv(MODE_VAR, mode)


def test_report_modes_are_ordered_by_detail() -> None:
    """_no_less_private_than_default relies on this order."""
    assert VALID_REPORT_MODES == (
        REPORT_MODE_NONE,
        REPORT_MODE_CONDENSED,
        REPORT_MODE_TEXT,
        REPORT_MODE_FULL,
    )


def test_project_may_reduce_detail(tmp_path, monkeypatch) -> None:
    _project_mode(tmp_path, monkeypatch, REPORT_MODE_NONE)

    assert ccusage_reporter._configured_report_mode() == REPORT_MODE_NONE


def test_project_cannot_raise_detail_above_default(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ccusage_reporter, "DEFAULT_REPORT_MODE", REPORT_MODE_CONDENSED)
    _project_mode(tmp_path, monkeypatch, REPORT_MODE_FULL)

    assert ccusage_reporter._configured_report_mode() == REPORT_MODE_CONDENSED


def test_user_saved_mode_matching_the_project_is_kept(tmp_path, monkeypatch) -> None:
    _project_mode(tmp_path, monkeypatch, REPORT_MODE_CONDENSED)

    assert ccusage_reporter._configured_report_mode() == REPORT_MODE_CONDENSED


def test_invalid_project_mode_falls_back_to_default(tmp_path, monkeypatch) -> None:
    _project_mode(tmp_path, monkeypatch, "everything")

    assert (
        ccusage_reporter._configured_report_mode()
        == ccusage_reporter.DEFAULT_REPORT_MODE
    )
