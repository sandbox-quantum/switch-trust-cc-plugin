"""Tests for hooks/ccusage_reporter.py's turn-reporting loop."""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

import ccusage_reporter  # noqa: E402
from ccusage import fingerprints, state, upload  # noqa: E402


def _write_transcript(path, n_turns: int, surrogate_turn: int = 0) -> str:
    with open(path, "w") as fh:
        for i in range(1, n_turns + 1):
            user = {
                "type": "user",
                "uuid": f"u{i}",
                "message": {"role": "user", "content": f"TURN-{i} prompt"},
            }
            text = f"answer {i}" + ("\ud800" if i == surrogate_turn else "")
            assistant = {
                "type": "assistant",
                "uuid": f"a{i}",
                "timestamp": f"2026-10-06T10:00:{i:02d}Z",
                "message": {
                    "id": f"m{i}",
                    "model": "claude-opus-4",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 100, "output_tokens": 50},
                    "content": [{"type": "text", "text": text}],
                },
            }
            fh.write(json.dumps(user) + "\n" + json.dumps(assistant) + "\n")
    return str(path)


def _setup(tmp_path, monkeypatch, results=None) -> list[list[int]]:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", "sk_test")
    monkeypatch.setenv(
        "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_ENVIRONMENT", "http://127.0.0.1:1"
    )
    monkeypatch.setenv(
        "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_USER_EMAIL", "dev@example.com"
    )
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_MODE", raising=False)
    sent: list[list[int]] = []
    statuses = iter(results or [])

    def _fake_post(_endpoint, _key, event, _repo_url=None, _timeout=None):
        turns = [int(t) for t in re.findall(rb"TURN-(\d+)", event)]
        status = next(statuses, 200) if turns else 200
        if 200 <= status < 300:
            sent.append(turns)
        return status

    monkeypatch.setattr(upload, "post_event_status", _fake_post)
    return sent


def _hook_input(transcript: str) -> dict:
    return {"session_id": "s1", "transcript_path": transcript, "cwd": "/nonexistent"}


def test_lone_surrogate_turn_does_not_block_other_turns(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 4, surrogate_turn=2)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2], [3], [4]]
    assert state.read_cursor("s1") == "a4"


def test_turn_that_fails_to_build_is_skipped(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)
    real_build = ccusage_reporter.build_llm_interaction_turn

    def _build(session_id, turn, *args):
        if turn["uuid"] == "a3":
            raise ValueError("boom")
        return real_build(session_id, turn, *args)

    monkeypatch.setattr(ccusage_reporter, "build_llm_interaction_turn", _build)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2]]
    assert state.read_cursor("s1") == "a3"


def test_transient_failure_at_stop_keeps_cursor_for_retry(
    tmp_path, monkeypatch
) -> None:
    sent = _setup(tmp_path, monkeypatch, results=[200, 200, 503])
    transcript = _write_transcript(tmp_path / "t.jsonl", 4)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2]]
    assert state.read_cursor("s1") == "a2"
    assert state.read_sequence("s1") == 2
    assert not os.path.exists(state.last_emit_path("s1"))

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2], [3], [4]]
    assert state.read_cursor("s1") == "a4"
    assert state.read_sequence("s1") == 4


def test_auth_failure_at_stop_keeps_cursor_until_key_fixed(
    tmp_path, monkeypatch
) -> None:
    sent = _setup(tmp_path, monkeypatch, results=[401])
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[]]
    assert state.read_cursor("s1") is None

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2], [3]]
    assert state.read_cursor("s1") == "a3"


def test_non_200_success_advances_cursor(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch, results=[201, 202, 204])
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [2], [3]]
    assert state.read_cursor("s1") == "a3"


def test_transient_failure_at_session_end_stops_and_keeps_state(
    tmp_path, monkeypatch
) -> None:
    sent = _setup(tmp_path, monkeypatch, results=[200, 0, 200])
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)

    ccusage_reporter.run("end", _hook_input(transcript))

    assert sent == [[], [1]]
    assert state.read_cursor("s1") == "a1"

    ccusage_reporter.run("end", _hook_input(transcript))

    assert sent == [[], [1], [2], [3]]
    assert state.read_cursor("s1") is None
    assert not os.path.exists(state.meta_path("s1"))


def test_session_end_out_of_budget_keeps_state(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)
    state.write_cursor("s1", "a1")

    ccusage_reporter.run("end", _hook_input(transcript), budget_s=0)

    assert sent == []
    assert state.read_cursor("s1") == "a1"


def test_rejected_turn_is_skipped_and_later_turns_sent(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch, results=[200, 413, 200])
    transcript = _write_transcript(tmp_path / "t.jsonl", 3)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == [[], [1], [3]]
    assert state.read_cursor("s1") == "a3"
    assert os.path.exists(state.last_emit_path("s1"))


def test_condensed_mode_respects_budget(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_MODE", "condensed")
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)

    ccusage_reporter.run("stop", _hook_input(transcript))
    ccusage_reporter.run("end", _hook_input(transcript), budget_s=0)
    assert sent == []

    ccusage_reporter.run("end", _hook_input(transcript))
    assert sent == [[], []]


def test_spent_budget_sends_nothing_and_keeps_cursor(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)

    ccusage_reporter.run("stop", _hook_input(transcript), budget_s=0)

    assert sent == []
    assert state.read_cursor("s1") is None


def test_budget_caps_timeout_and_skips_post_that_cannot_fit(monkeypatch) -> None:
    now = {"t": 100.0}
    monkeypatch.setattr(ccusage_reporter.time, "monotonic", lambda: now["t"])
    budget = ccusage_reporter._Budget(8.0)

    assert budget.post_timeout() == ccusage_reporter.HTTP_TIMEOUT_S

    def _slow_post():
        now["t"] += 4.0

    budget.timed(_slow_post)
    assert budget.post_timeout() == 4.0
    now["t"] += 0.5
    assert budget.post_timeout() is None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits (0600) don't exist on Windows; os.chmod "
    "there only toggles a read-only attribute.",
)
def test_fallback_log_tightens_existing_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    log_file = tmp_path / "ccusage.log"
    log_file.write_text("old\n")
    os.chmod(log_file, 0o644)

    ccusage_reporter._fallback_log("boom")

    assert os.stat(log_file).st_mode & 0o777 == 0o600
    assert log_file.read_text().endswith("boom\n")


def test_condensed_failure_keeps_state_and_retry_reuses_fingerprint(
    tmp_path, monkeypatch
) -> None:
    _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_MODE", "condensed")
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    outcomes = iter([200, 503, 200])
    fingerprints_sent = []

    def _post(_endpoint, _key, event, _repo_url=None, _timeout=None):
        fingerprints_sent.append(re.findall(rb"cci_[0-9a-f]{32}", event))
        return next(outcomes, 200)

    monkeypatch.setattr(upload, "post_event_status", _post)

    ccusage_reporter.run("end", _hook_input(transcript))
    assert os.path.exists(state.meta_path("s1"))

    _write_transcript(tmp_path / "t.jsonl", 4)
    ccusage_reporter.run("end", _hook_input(transcript))

    expected = fingerprints.condensed_fingerprint("s1", "claude-opus-4", None)
    assert fingerprints_sent == [[], [expected.encode()], [expected.encode()]]
    assert not os.path.exists(state.meta_path("s1"))


def test_condensed_fingerprint_is_keyed_on_window_start() -> None:
    first = fingerprints.condensed_fingerprint("s1", "m", None)

    assert first == fingerprints.condensed_fingerprint("s1", "m", None)
    assert first != fingerprints.condensed_fingerprint("s1", "m", "a3")
    assert first != fingerprints.interaction_fingerprint("s1", "m", None)


def test_open_breaker_skips_posting_at_stop(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    monkeypatch.setattr(upload, "breaker_retry_at", lambda *_a: 4_102_444_800.0)

    ccusage_reporter.run("stop", _hook_input(transcript))

    assert sent == []
    assert os.path.exists(state.meta_path("s1"))


def _open_breaker_until_success(monkeypatch, outcomes):
    attempts = []
    breaker = {"open": True}

    def _post(_endpoint, _key, event, _repo_url=None, _timeout=None):
        status = next(outcomes, 200)
        attempts.append([int(t) for t in re.findall(rb"TURN-(\d+)", event)])
        if 200 <= status < 300:
            breaker["open"] = False
        return status

    monkeypatch.setattr(upload, "post_event_status", _post)
    monkeypatch.setattr(
        upload,
        "breaker_retry_at",
        lambda *_a: 4_102_444_800.0 if breaker["open"] else 0.0,
    )
    return attempts


def test_session_end_probes_once_when_breaker_open(tmp_path, monkeypatch) -> None:
    _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    attempts = _open_breaker_until_success(monkeypatch, iter([503]))

    ccusage_reporter.run("end", _hook_input(transcript))

    assert attempts == [[]]
    assert os.path.exists(state.meta_path("s1"))


def test_session_end_probe_success_reports_everything(tmp_path, monkeypatch) -> None:
    _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    attempts = _open_breaker_until_success(monkeypatch, iter([200]))

    ccusage_reporter.run("end", _hook_input(transcript))

    assert attempts == [[], [1], [2]]
    assert not os.path.exists(state.meta_path("s1"))


def test_session_end_probe_uses_first_turn_when_already_opened(
    tmp_path, monkeypatch
) -> None:
    _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    state.write_private_file(state.opened_path("s1"), "1")
    attempts = _open_breaker_until_success(monkeypatch, iter([503]))

    ccusage_reporter.run("end", _hook_input(transcript))

    assert attempts == [[1]]
    assert os.path.exists(state.meta_path("s1"))


def test_build_failure_log_omits_exception_text(tmp_path, monkeypatch) -> None:
    _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)

    def _build(*_args):
        raise ValueError("password=hunter2 from the transcript")

    monkeypatch.setattr(ccusage_reporter, "build_llm_interaction_turn", _build)

    ccusage_reporter.run("stop", _hook_input(transcript))

    log_text = (tmp_path / "data" / "ccusage.log").read_text()
    assert "hunter2" not in log_text
    assert "skipping turn 1: event build failed: ValueError" in log_text


def test_status_shows_last_failure_without_secrets(
    tmp_path, monkeypatch, capsys
) -> None:
    import time  # noqa: PLC0415

    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    monkeypatch.setenv(
        "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", "sk_test_secretvalue"
    )
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_ENVIRONMENT", raising=False)
    endpoint = ccusage_reporter.DEFAULT_INGESTION_ENDPOINT
    state.write_health(
        {
            "id": upload._health_id(endpoint, "sk_test_secretvalue"),
            "consecutive": 4,
            "retry_at": time.time() + 600,
            "last_failure": {"status": 401, "at": 0, "reason": "invalid key"},
        }
    )

    ccusage_reporter.cmd_status()

    lines = capsys.readouterr().out.splitlines()
    assert lines[1].strip().startswith("last_failure: status=401 (invalid key) at")
    assert "breaker OPEN" in lines[1]
    assert "secretvalue" not in "\n".join(lines)


def test_status_ignores_record_for_another_key(tmp_path, monkeypatch, capsys) -> None:
    import time  # noqa: PLC0415

    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", "sk_new")
    state.write_health(
        {
            "id": "old-key-hash",
            "retry_at": time.time() + 600,
            "last_failure": {"status": 401, "at": 0, "reason": "invalid key"},
        }
    )

    ccusage_reporter.cmd_status()

    line = capsys.readouterr().out.splitlines()[1]
    assert line.strip() == "last_failure: none for the current key/endpoint"


def test_status_survives_corrupt_health(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY", raising=False)
    state.write_health({"last_failure": {"status": 500, "at": "yesterday"}})

    assert ccusage_reporter.cmd_status() == 0

    line = capsys.readouterr().out.splitlines()[1]
    assert line.strip().startswith("last_failure:")


def test_status_shows_redirect_location_host(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    state.write_health(
        {"last_failure": {"status": 302, "at": 0, "location_host": "sso.example"}}
    )

    ccusage_reporter.cmd_status()

    line = capsys.readouterr().out.splitlines()[1]
    assert "status=302 location_host=sso.example" in line
    assert "key not visible here" in line
    assert "breaker closed" in line


def test_gc_runs_after_reporting_with_leftover_budget(tmp_path, monkeypatch) -> None:
    sent = _setup(tmp_path, monkeypatch)
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    calls = []

    def _gc(session_id, time_slice_s):
        calls.append((len(sent), time_slice_s))
        return 0, True

    monkeypatch.setattr(state, "gc_sessions", _gc)

    ccusage_reporter.run("stop", _hook_input(transcript))
    ccusage_reporter.run("stop", _hook_input(transcript), budget_s=0)

    assert len(calls) == 1
    assert calls[0][0] == 3
    assert 0 < calls[0][1] <= 0.3


def test_condensed_session_end_probes_once(tmp_path, monkeypatch) -> None:
    _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_MODE", "condensed")
    transcript = _write_transcript(tmp_path / "t.jsonl", 2)
    attempts = _open_breaker_until_success(monkeypatch, iter([503]))

    ccusage_reporter.run("end", _hook_input(transcript))

    assert len(attempts) == 1
    assert os.path.exists(state.meta_path("s1"))
