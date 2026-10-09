"""Configuration constants for the Claude Code usage reporter."""

from __future__ import annotations

SENSOR_TYPE = "claude_code_plugin"
SENSOR_VERSION = "0.2.0"
ASSET_ID = "claude_code"
INVENTORY_SESSION_ID = "claude_code"  # static org-wide session for currentness
EVENTS_PATH = "agent/events/v1"
DEFAULT_INGESTION_ENDPOINT = "https://ingestion.switchagents.ai"

# Agent provenance: Claude Code is Anthropic's own CLI, so these are constant
# for every agent this plugin reports.
AGENT_LIBRARY = "Claude Code"
AGENT_SUPPLIER = "Anthropic"
AGENT_MANUFACTURER = "Anthropic"
AGENT_TYPE_MANAGED = 2

# Links the Agent to the Model it used (see build_model_dependency in events.py).
AISPM_DEPENDENCY_TYPE_MODEL = 1

# Effective-token folding multipliers, relative to the base input price.
CACHE_READ_MULT = 0.10
CACHE_WRITE_5M_MULT = 1.25
CACHE_WRITE_1H_MULT = 2.00

# Throttle: on Stop, skip reporting unless enough time OR tokens accumulated.
STOP_MIN_INTERVAL_S = 60
STOP_MIN_TOKENS = 20000

# Report modes (switch_trust_mode userConfig option) -- see README.md's Report modes table.
REPORT_MODE_NONE = "none"
REPORT_MODE_CONDENSED = "condensed"
REPORT_MODE_TEXT = "text"
REPORT_MODE_FULL = "full"
VALID_REPORT_MODES = (
    REPORT_MODE_NONE,
    REPORT_MODE_CONDENSED,
    REPORT_MODE_TEXT,
    REPORT_MODE_FULL,
)
DEFAULT_REPORT_MODE = REPORT_MODE_FULL

HTTP_TIMEOUT_S = 8

HOOK_BUDGET_S = {"stop": 8.0, "end": 13.0}
MIN_POST_TIMEOUT_S = 1.0

STATE_MAX_AGE_S = 30 * 24 * 3600
STATE_MAX_SESSIONS = 500
GC_INTERVAL_S = 3600
GC_TIME_SLICE_S = 0.3

BREAKER_THRESHOLD = 3
BREAKER_BACKOFF_S = (60, 120, 240, 480, 900)

# Throttle for retrying user-email resolution once all fallbacks have failed
# (avoids a ~10s subprocess/network chain on every hook call).
USER_EMAIL_RETRY_INTERVAL_S = 3600

# project_settings.get() arguments -- the plugin.json userConfig field name
# for each value the plugin reads. Must match the keys under "userConfig" in
# .claude-plugin/plugin.json exactly.
OPTION_SWITCH_TRUST_API_KEY = "switch_trust_api_key"
OPTION_SWITCH_TRUST_ENVIRONMENT = "switch_trust_environment"
OPTION_SWITCH_TRUST_MODE = "switch_trust_mode"
OPTION_SWITCH_TRUST_USER_EMAIL = "switch_trust_user_email"
