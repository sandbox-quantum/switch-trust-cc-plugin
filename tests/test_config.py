"""Guards against config.py and plugin.json silently disagreeing about defaults.

A fresh install with no Report Mode chosen falls back to config.py's
DEFAULT_REPORT_MODE, but `/config`'s own UI shows plugin.json's userConfig
`default` -- the two are independent literals with nothing enforcing they
match. This is what let the plugin.json default drift out of step with the
documented behavior before.
"""

from __future__ import annotations

import json
import os
import sys

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage.config import (  # noqa: E402
    DEFAULT_REPORT_MODE,
    REPORT_MODE_FULL,
    SENSOR_VERSION,
)

PLUGIN_JSON_PATH = os.path.join(
    os.path.dirname(__file__), "..", ".claude-plugin", "plugin.json"
)


def test_default_report_mode_is_full() -> None:
    """full is the intentional default -- see README's Data & Privacy section."""
    assert DEFAULT_REPORT_MODE == REPORT_MODE_FULL


def test_plugin_json_default_matches_config_default() -> None:
    """plugin.json's /config default must match config.py's fallback default."""
    with open(PLUGIN_JSON_PATH) as fh:
        plugin_json = json.load(fh)

    assert (
        plugin_json["userConfig"]["switch_trust_mode"]["default"] == DEFAULT_REPORT_MODE
    )


def test_plugin_json_version_matches_sensor_version() -> None:
    """plugin.json's version and SENSOR_VERSION (reported on every event) must
    move together -- the release process bumps them in the same commit, but
    nothing else enforces it, and they already drifted once (0.1.0 vs 0.1.1).
    """
    with open(PLUGIN_JSON_PATH) as fh:
        plugin_json = json.load(fh)

    assert plugin_json["version"] == SENSOR_VERSION
