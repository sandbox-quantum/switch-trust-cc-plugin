#!/usr/bin/env python3
"""Claude Code usage reporter -- CLI entrypoint.

Reports aggregated Claude Code session usage to Switch Trust as cost/ROI events.
See README.md for the full rationale.

How it works:
  * Fires on the Stop and SessionEnd hooks; stdin carries session_id,
    transcript_path, cwd, hook_event_name.
  * Parses the transcript delta since the last per-session checkpoint --
    except in `condensed` mode, which only reports at SessionEnd and so
    always covers the whole session in one delta.
  * Folds cache tokens into an effective input-token count for accurate cost.
  * Emits one Event per model (`condensed`) or per turn (`text`/`full`),
    fingerprinted so retries are idempotent.

Runs as a standalone script, outside any build system or source checkout, so
it's pure Python 3 standard library with no third-party dependencies. See
`ccusage/wire.py` for how events are serialized without a protobuf library.

Fail-open: any missing config or error exits 0 -- this hook must never block
or fail a Claude Code session.

Implementation lives in the sibling `ccusage/` package; this file is the CLI
entrypoint only.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Only for static analysis: run()/cmd_status() below use these names
    # unconditionally, which is only true at runtime when the guarded import
    # underneath succeeds (see _IMPORT_ERROR) -- a fact a type checker can't
    # verify across functions.
    from ccusage import identity, project_settings, state, transcript, upload
    from ccusage.config import (
        DEFAULT_INGESTION_ENDPOINT,
        DEFAULT_REPORT_MODE,
        GC_TIME_SLICE_S,
        HOOK_BUDGET_S,
        HTTP_TIMEOUT_S,
        MID_SESSION_BACKFILL_TOKENS_THRESHOLD,
        MIN_POST_TIMEOUT_S,
        OPTION_SWITCH_TRUST_API_KEY,
        OPTION_SWITCH_TRUST_ENVIRONMENT,
        OPTION_SWITCH_TRUST_MODE,
        OPTION_SWITCH_TRUST_PII_REDACTION,
        PII_REDACTION_DEFAULT,
        PII_REDACTION_LEVELS,
        REPORT_MODE_CONDENSED,
        REPORT_MODE_FULL,
        REPORT_MODE_NONE,
        VALID_REPORT_MODES,
    )
    from ccusage.events import (
        build_interaction_event,
        build_llm_interaction,
        build_llm_interaction_turn,
    )
    from ccusage.log import log, log_path
    from ccusage.pii import PiiRedactor
    from ccusage.redact import redact

# Wrapped so an import failure (bad edit, Python-version incompatibility) is
# caught by main()'s fail-open handling instead of crashing before any error
# handling exists.
_IMPORT_ERROR: Exception | None = None
try:
    from ccusage import identity, project_settings, state, transcript, upload
    from ccusage.config import (
        DEFAULT_INGESTION_ENDPOINT,
        DEFAULT_REPORT_MODE,
        GC_TIME_SLICE_S,
        HOOK_BUDGET_S,
        HTTP_TIMEOUT_S,
        MID_SESSION_BACKFILL_TOKENS_THRESHOLD,
        MIN_POST_TIMEOUT_S,
        OPTION_SWITCH_TRUST_API_KEY,
        OPTION_SWITCH_TRUST_ENVIRONMENT,
        OPTION_SWITCH_TRUST_MODE,
        OPTION_SWITCH_TRUST_PII_REDACTION,
        PII_REDACTION_DEFAULT,
        PII_REDACTION_LEVELS,
        REPORT_MODE_CONDENSED,
        REPORT_MODE_FULL,
        REPORT_MODE_NONE,
        VALID_REPORT_MODES,
    )
    from ccusage.events import (
        build_interaction_event,
        build_llm_interaction,
        build_llm_interaction_turn,
    )
    from ccusage.log import log, log_path
    from ccusage.pii import PiiRedactor
    from ccusage.redact import redact
except Exception as exc:  # noqa: BLE001 - fail-open entrypoint, see main()
    _IMPORT_ERROR = exc


def _fallback_log(msg: str) -> None:
    """Best-effort logging that doesn't depend on the ccusage package being importable."""
    try:
        sys.stderr.write(f"[ccusage] {msg}\n")
    except Exception:
        pass
    try:
        base = os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.join(
            os.path.expanduser("~"), ".switch-trust", "roi_cc_plugin"
        )
        os.makedirs(base, mode=0o700, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path = os.path.join(base, "ccusage.log")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", errors="replace") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            fh.write(f"{ts} {msg}\n")
    except Exception:
        pass


def _no_less_private_than_default(mode: str) -> bool:
    if mode not in VALID_REPORT_MODES:
        return False
    return VALID_REPORT_MODES.index(mode) <= VALID_REPORT_MODES.index(
        DEFAULT_REPORT_MODE
    )


def _configured_report_mode() -> str:
    """Read the switch_trust_mode userConfig option; a project may only reduce detail."""
    return (
        project_settings.get(
            OPTION_SWITCH_TRUST_MODE, accept_from_project=_no_less_private_than_default
        )
        or DEFAULT_REPORT_MODE
    )


def _no_less_redaction_than_default(level: str) -> bool:
    return level in PII_REDACTION_LEVELS and PII_REDACTION_LEVELS.index(
        level
    ) >= PII_REDACTION_LEVELS.index(PII_REDACTION_DEFAULT)


def _configured_pii_level() -> str:
    """Read switch_trust_pii_redaction; a project may only make it stricter, and an unknown value means default."""
    level = project_settings.get(
        OPTION_SWITCH_TRUST_PII_REDACTION,
        accept_from_project=_no_less_redaction_than_default,
    )
    return level if level in PII_REDACTION_LEVELS else PII_REDACTION_DEFAULT


class _Budget:
    """Starts a POST only if the last POST's duration still fits before the deadline."""

    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds
        self.last_post_s = 0.0

    def post_timeout(self) -> float | None:
        remaining = self.deadline - time.monotonic()
        if remaining < max(MIN_POST_TIMEOUT_S, self.last_post_s):
            return None
        return min(HTTP_TIMEOUT_S, remaining)

    def timed(self, fn: Any, *args: Any) -> Any:
        started = time.monotonic()
        try:
            return fn(*args)
        finally:
            self.last_post_s = time.monotonic() - started


def run(mode: str, hook_input: dict[str, Any], budget_s: float | None = None) -> int:
    """Report the transcript delta, then spend leftover time on state GC. Always returns 0."""
    if budget_s is None:
        budget_s = HOOK_BUDGET_S.get(mode, HOOK_BUDGET_S["stop"])
    budget = _Budget(budget_s)
    upload.begin_run()
    try:
        _report(mode, hook_input, budget)
    finally:
        _collect_garbage(hook_input.get("session_id") or "unknown", budget)
    return 0


def _report(mode: str, hook_input: dict[str, Any], budget: _Budget) -> int:
    """Read the transcript delta and report it. Always returns 0.

    `mode` is `"stop"` (throttled) or `"end"` (always reports, and clears
    state once everything is delivered). In `condensed` mode, `"stop"` is a
    no-op -- condensed reports the whole session once, at `"end"`. Reporting detail is controlled by
    the switch_trust_mode userConfig option -- see README's Report modes table.
    """
    report_mode = _configured_report_mode()
    if report_mode not in VALID_REPORT_MODES:
        log(f"unknown switch_trust_mode={report_mode!r}; using condensed")
        report_mode = REPORT_MODE_CONDENSED
    if report_mode == REPORT_MODE_NONE:
        return 0

    endpoint = (
        project_settings.get(OPTION_SWITCH_TRUST_ENVIRONMENT)
        or DEFAULT_INGESTION_ENDPOINT
    )
    api_key = project_settings.get(OPTION_SWITCH_TRUST_API_KEY)
    if not api_key:
        log(f"no {OPTION_SWITCH_TRUST_API_KEY} configured; skipping")
        return 0

    session_id = hook_input.get("session_id") or "unknown"
    transcript_path = hook_input.get("transcript_path")
    cwd = hook_input.get("cwd") or os.getcwd()
    if not transcript_path:
        log("no transcript_path in hook input; skipping")
        return 0

    sid = session_id[:8]
    pii = PiiRedactor(_configured_pii_level())
    if not os.path.isfile(state.meta_path(session_id)):
        state.write_meta(session_id, transcript_path)
    if report_mode == REPORT_MODE_CONDENSED and mode == "stop":
        # Condensed mode reports the whole session as a single artificial
        # turn per model, so it only ever reports at SessionEnd -- a Stop
        # here would fold just the delta-so-far into its own turn instead.
        return 0
    retry_at = upload.breaker_retry_at(endpoint, api_key)
    probing = time.time() < retry_at
    if probing and mode != "end":
        wait_s = int(retry_at - time.time())
        log(f"{sid} mode={mode}: ingestion failing; not posting for {wait_s}s more")
        return 0
    if probing:
        log(f"{sid} mode=end: breaker open; sending one probe POST")
    cursor = state.read_cursor(session_id)

    # Condensed vs. text/full produce differently-shaped data (one aggregate
    # bucket per model vs. a list of turns), so each branch below is fully
    # self-contained rather than sharing a loop body.
    if report_mode == REPORT_MODE_CONDENSED:
        per_model, title, branch, _new_cursor, total_new = (
            transcript.read_transcript_delta(transcript_path, cursor)
        )
        if not per_model:
            log(f"{sid} mode={mode}: no new messages since last report")
            state.cleanup_state(session_id)
            return 0

        if not title:
            title = "(untitled Claude Code session)"

        repo_url = identity.get_repo_url(cwd)
        repo_name = identity.repo_name_from_url(repo_url)
        agent_name = f"Claude Code — {identity.get_user_email(cwd)}"

        opened = _ensure_session_open(endpoint, api_key, session_id, repo_url, budget)
        if probing and opened is False:
            return 0

        log(
            f"{sid} mode={mode}: reporting delta, {len(per_model)} models, "
            f"{total_new} new tokens"
        )
        delivered = True
        for model_name, bucket in per_model.items():
            if bucket["input"] <= 0 and bucket["output"] <= 0:
                continue
            timeout = budget.post_timeout()
            if timeout is None:
                log(f"{sid} mode={mode}: out of hook time; keeping state for retry")
                delivered = False
                break
            try:
                interaction = build_llm_interaction(
                    session_id,
                    model_name,
                    bucket,
                    agent_name,
                    title,
                    repo_name,
                    repo_url,
                    branch,
                    window_start=cursor,
                    pii=pii,
                )
                event = build_interaction_event(interaction, repo_url)
            except Exception as exc:
                log(f"skipping model={model_name}: build failed: {type(exc).__name__}")
                continue
            status = budget.timed(
                upload.post_event_status, endpoint, api_key, event, repo_url, timeout
            )
            verb = "reported" if upload.is_success(status) else "send failed"
            log(
                f"{verb} model={model_name} input={bucket['input']} cache_read={bucket['cache_read']} "
                f"cache_write={bucket['cache_write']} output={bucket['output']} branch={redact(branch, pii) or '-'} "
                f"status={status}"
            )
            if not upload.is_success(status) and not upload.is_permanent_rejection(
                status
            ):
                delivered = False
                break

        if delivered:
            state.cleanup_state(session_id)
        return 0

    # report_mode is "text" or "full": one row per conversation turn.
    turns, new_cursor, total_new = transcript.read_transcript_turns(
        transcript_path, cursor, include_tools=report_mode == REPORT_MODE_FULL
    )
    if cursor is None and len(turns) > 1:
        # No cursor can mean either a brand-new session (the first Stop never
        # throttles, so a couple of turns can legitimately bunch up from a
        # missed/crashed prior invocation) or the plugin being enabled
        # partway through a session that already has substantial history --
        # the two look identical from here. Use scale to tell them apart:
        # only a backlog far past normal catch-up is treated as pre-existing
        # history that shouldn't be uploaded. Keep the turn that just
        # triggered this hook and let the cursor (still the full new_cursor
        # below) skip the rest for good.
        prior_tokens = sum(
            t["input"] + t["output"] + t["cache_read"] + t["cache_write"]
            for t in turns[:-1]
        )
        if prior_tokens > MID_SESSION_BACKFILL_TOKENS_THRESHOLD:
            skipped = len(turns) - 1
            log(
                f"{sid} mode={mode}: {skipped} prior turn(s) ({prior_tokens} tokens) "
                "already in the transcript at first report for this session; "
                "skipping backfill"
            )
            turns = turns[-1:]
            total_new = sum(
                t["input"] + t["output"] + t["cache_read"] + t["cache_write"]
                for t in turns
            )
    if not turns:
        log(f"{sid} mode={mode}: no new messages since last report")
        if mode == "end":
            state.cleanup_state(session_id)
        return 0

    if mode == "stop" and state.should_throttle_stop(session_id, total_new):
        # Do NOT advance the cursor: these tokens fold into the next report.
        log(f"{sid} mode=stop: throttled ({total_new} new tokens pending)")
        return 0

    repo_url = identity.get_repo_url(cwd)
    repo_name = identity.repo_name_from_url(repo_url)
    agent_name = f"Claude Code — {identity.get_user_email(cwd)}"

    opened = _ensure_session_open(endpoint, api_key, session_id, repo_url, budget)
    if probing and opened is False:
        return 0

    seq = state.read_sequence(session_id)
    log(
        f"{sid} mode={mode}: reporting {len(turns)} turns ({report_mode}), "
        f"{total_new} new tokens"
    )
    all_ok = True
    for index, turn in enumerate(turns):
        if turn["input"] <= 0 and turn["output"] <= 0:
            continue
        timeout = budget.post_timeout()
        if timeout is None:
            unsent = len(turns) - index
            log(f"{sid} mode={mode}: out of hook time; {unsent} turns kept for retry")
            all_ok = False
            break
        try:
            interaction = build_llm_interaction_turn(
                session_id, turn, agent_name, repo_name, repo_url, seq, pii
            )
            event = build_interaction_event(interaction, repo_url)
        except Exception as exc:
            log(f"skipping turn {index}: event build failed: {type(exc).__name__}")
            state.write_cursor(session_id, turn["uuid"])
            continue
        status = budget.timed(
            upload.post_event_status, endpoint, api_key, event, repo_url, timeout
        )
        verb = "reported turn" if upload.is_success(status) else "send failed turn"
        log(
            f"{verb} seq={seq} model={turn['model']} "
            f"input={turn['input']} cache_read={turn['cache_read']} cache_write={turn['cache_write']} output={turn['output']} status={status}"
        )
        if upload.is_success(status):
            seq += 1
            state.write_sequence(session_id, seq)
            state.write_cursor(session_id, turn["uuid"])
        elif upload.is_permanent_rejection(status):
            log(f"skipping turn uuid={turn['uuid']}: rejected with status={status}")
            state.write_cursor(session_id, turn["uuid"])
        else:
            all_ok = False
            break

    if all_ok:
        state.write_cursor(session_id, new_cursor)
        state.mark_emitted(session_id)
        if mode == "end":
            state.cleanup_state(session_id)
    return 0


def _collect_garbage(session_id: str, budget: _Budget) -> None:
    time_slice = min(GC_TIME_SLICE_S, budget.deadline - time.monotonic())
    if time_slice <= 0:
        return
    try:
        if not state.gc_due():
            return
        removed, complete = state.gc_sessions(session_id, time_slice)
    except Exception as exc:
        log(f"state GC failed: {type(exc).__name__}")
        return
    if removed or not complete:
        log(f"state GC removed {removed} stale sessions (complete={complete})")


def _ensure_session_open(
    endpoint: str, api_key: str, session_id: str, repo_url: str, budget: _Budget
) -> bool | None:
    timeout = budget.post_timeout()
    if timeout is None:
        return None
    return budget.timed(
        upload.ensure_session_open, endpoint, api_key, session_id, repo_url, timeout
    )


def _last_failure_line(
    state_dir_override: str | None, endpoint_override: str | None = None
) -> str:
    try:
        return _describe_last_failure(state_dir_override, endpoint_override)
    except Exception as exc:
        return f"last_failure: unreadable ({type(exc).__name__})"


def _describe_last_failure(
    state_dir_override: str | None, endpoint_override: str | None = None
) -> str:
    endpoint = (
        endpoint_override
        or project_settings.get(OPTION_SWITCH_TRUST_ENVIRONMENT)
        or DEFAULT_INGESTION_ENDPOINT
    )
    api_key = project_settings.get(OPTION_SWITCH_TRUST_API_KEY)
    suffix = ""
    if api_key:
        health = upload.current_health(endpoint, api_key, state_dir_override)
        if health.get("stale"):
            return "last_failure: none for the current key/endpoint"
    else:
        health = state.read_health(state_dir_override)
        suffix = " [key not visible here; may belong to another key/endpoint]"
    failure = health.get("last_failure")
    if not isinstance(failure, dict):
        return "last_failure: none"
    at = float(failure.get("at") or 0)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))
    parts = [f"status={failure.get('status')}"]
    if failure.get("reason"):
        parts.append(f"({failure['reason']})")
    if failure.get("location_host"):
        parts.append(f"location_host={failure['location_host']}")
    line = f"last_failure: {' '.join(parts)} at {stamp}"
    retry_at = float(health.get("retry_at") or 0)
    if time.time() < retry_at:
        until = time.strftime("%H:%M:%SZ", time.gmtime(retry_at))
        line += f"; breaker OPEN until {until}"
    else:
        line += "; breaker closed"
    consecutive = health.get("consecutive") or 0
    return line + f" ({consecutive} consecutive failed runs){suffix}"


def _parse_flag(args: list[str], name: str) -> str | None:
    """Parse `--<name> <value>` / `--<name>=<value>` from the `status` subcommand's args."""
    flag = f"--{name}"
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return None


def cmd_status(
    state_dir_override: str | None = None,
    mode_override: str | None = None,
    endpoint_override: str | None = None,
) -> int:
    """Print where state/logs live, config presence, and recent activity.

    `state_dir_override`, when given, is used in place of `${CLAUDE_PLUGIN_DATA}`
    -- see `state.state_dir()`'s docstring for why this matters when `status`
    is invoked from a command's Bash tool call rather than as a real hook.

    `mode_override`/`endpoint_override` are needed for the same reason:
    `CLAUDE_PLUGIN_OPTION_*` env vars are only exported to real hook
    subprocesses, not Bash-tool invocations, so `_configured_report_mode()`/
    `project_settings.get(OPTION_SWITCH_TRUST_ENVIRONMENT)` would otherwise
    silently fall back to the hardcoded defaults here even when the user has
    configured different values via `/config`. The `switch-trust-status`
    command passes its own already-resolved `${user_config.*}` values through
    these flags instead.
    """
    d = state.state_dir(state_dir_override)
    print("ccusage plugin status")
    print(f"  {_last_failure_line(state_dir_override, endpoint_override)}")
    print(f"  state dir : {d}")
    print(f"  log file  : {log_path(state_dir_override)}")
    report_mode = mode_override or _configured_report_mode()
    if report_mode not in VALID_REPORT_MODES:
        report_mode = f"{report_mode} (invalid, falls back to condensed)"
    print(f"  report mode : {report_mode}")
    print(f"  pii redaction : {_configured_pii_level()}")
    # Config (values never printed).
    endpoint = (
        endpoint_override
        or project_settings.get(OPTION_SWITCH_TRUST_ENVIRONMENT)
        or DEFAULT_INGESTION_ENDPOINT
    )
    print(f"  ingestion endpoint : {endpoint}")
    repo_url = identity.get_repo_url(os.getcwd())
    print(f"  slot id   : {identity.slot_id(repo_url)}")
    try:
        files = sorted(os.listdir(d))
    except Exception:
        files = []
    cursors = [f for f in files if f.endswith(".cursor")]
    print(f"  active session cursors: {len(cursors)}")
    for f in cursors:
        try:
            with open(os.path.join(d, f)) as fh:
                print(f"    - {f[:-7][:8]} -> {fh.read().strip()[:8]}")
        except Exception:
            pass
    lp = log_path(state_dir_override)
    if os.path.isfile(lp):
        print("  --- last 15 log lines ---")
        try:
            with open(lp) as fh:
                for line in fh.readlines()[-15:]:
                    print(f"  {line.rstrip()}")
        except Exception:
            pass
    else:
        print("  (no log yet — the hook hasn't run)")
    return 0


def main() -> int:
    """CLI entrypoint: dispatch to `cmd_status()` or parse hook stdin and call `run()`.

    Must never surface a traceback or a non-zero exit to Claude Code -- any
    failure is logged locally (see `_fallback_log`) and swallowed.
    """
    try:
        if _IMPORT_ERROR is not None:
            _fallback_log(f"import failed; hook disabled: {_IMPORT_ERROR}")
            return 0

        mode = sys.argv[1] if len(sys.argv) > 1 else "stop"

        if mode in ("status", "where"):
            rest = sys.argv[2:]
            return cmd_status(
                _parse_flag(rest, "state-dir"),
                _parse_flag(rest, "mode"),
                _parse_flag(rest, "endpoint"),
            )

        try:
            raw = sys.stdin.read()
            hook_input = json.loads(raw) if raw.strip() else {}
        except Exception:
            hook_input = {}

        # Allow the hook_event_name to override the CLI arg if present.
        event_name = hook_input.get("hook_event_name")
        if event_name == "SessionEnd":
            mode = "end"
        elif event_name == "Stop":
            mode = "stop"

        run(mode, hook_input)
    except Exception as exc:
        # Absolutely never fail the hook.
        _fallback_log(f"unexpected error: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
