"""Tests for hooks/ccusage/state.py's sequence-number persistence."""

from __future__ import annotations

import os
import sys

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage import state  # noqa: E402


def test_read_sequence_defaults_to_zero(tmp_path, monkeypatch) -> None:
    """No sequence file yet (a new session) starts numbering at 0."""
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))

    assert state.read_sequence("session-1") == 0


def test_write_then_read_sequence_round_trips(tmp_path, monkeypatch) -> None:
    """A written sequence number is what the next read returns."""
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))

    state.write_sequence("session-1", 5)

    assert state.read_sequence("session-1") == 5


def test_cleanup_state_removes_sequence_file(tmp_path, monkeypatch) -> None:
    """SessionEnd's cleanup resets numbering for the next conversation on this session id."""
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    state.write_sequence("session-1", 5)

    state.cleanup_state("session-1")

    assert state.read_sequence("session-1") == 0


def test_state_dir_override_wins_over_claude_plugin_data(tmp_path, monkeypatch) -> None:
    """An explicit override (e.g. from `status --state-dir`) beats CLAUDE_PLUGIN_DATA.

    Needed because a command's Bash tool call never receives
    CLAUDE_PLUGIN_DATA -- only real hook subprocesses do -- so `status` must
    be able to be told the true directory via an explicit argument instead.
    """
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "wrong"))
    override = str(tmp_path / "right")

    assert state.state_dir(override) == override


def test_state_dir_falls_back_without_override_or_env(tmp_path, monkeypatch) -> None:
    """With neither an override nor CLAUDE_PLUGIN_DATA, the ~/.switch-trust fallback applies."""
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)

    assert state.state_dir() == os.path.join(
        os.path.expanduser("~"), ".switch-trust", "roi_cc_plugin"
    )


def _mode(path) -> int:
    return os.stat(path).st_mode & 0o777


def test_state_dir_and_files_are_owner_only(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))

    state.write_cursor("session-1", "uuid-1")
    state.write_sequence("session-1", 1)
    state.mark_emitted("session-1")

    assert _mode(base) == 0o700
    for name in os.listdir(base):
        assert _mode(base / name) == 0o600, name


def test_existing_world_readable_state_is_tightened(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    base.mkdir(mode=0o755)
    os.chmod(base, 0o755)
    cursor = base / "session-1.cursor"
    cursor.write_text("old")
    os.chmod(cursor, 0o644)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))

    state.write_cursor("session-1", "uuid-2")

    assert _mode(base) == 0o700
    assert _mode(cursor) == 0o600


def test_existing_override_dir_is_not_chmodded(tmp_path) -> None:
    override = tmp_path / "mine"
    override.mkdir()
    os.chmod(override, 0o755)

    state.state_dir(str(override))

    assert _mode(override) == 0o755


def test_overwrite_replaces_symlink_not_its_target(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    os.chmod(target, 0o644)
    os.makedirs(base)
    os.symlink(target, base / "session-1.cursor")

    state.write_cursor("session-1", "uuid-1")

    assert target.read_text() == "keep"
    assert _mode(target) == 0o644
    assert not os.path.islink(base / "session-1.cursor")
    assert state.read_cursor("session-1") == "uuid-1"
    assert sorted(os.listdir(base)) == ["session-1.cursor"]


def test_append_refuses_symlink(tmp_path) -> None:
    import pytest  # noqa: PLC0415

    target = tmp_path / "elsewhere"
    target.write_text("keep")
    os.chmod(target, 0o644)
    link = tmp_path / "ccusage.log"
    os.symlink(target, link)

    with pytest.raises(OSError):
        state.write_private_file(str(link), "line\n", append=True)

    assert target.read_text() == "keep"
    assert _mode(target) == 0o644


def test_rotated_log_is_owner_only(tmp_path, monkeypatch) -> None:
    from ccusage import log  # noqa: PLC0415

    base = tmp_path / "data"
    base.mkdir()
    big = base / "ccusage.log"
    big.write_text("x" * 1_000_001)
    os.chmod(big, 0o644)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))

    log.log("hello")

    assert _mode(base / "ccusage.log.1") == 0o600


def test_symlinked_state_dir_is_not_chmodded(tmp_path, monkeypatch) -> None:
    real = tmp_path / "real"
    real.mkdir()
    os.chmod(real, 0o755)
    link = tmp_path / "link"
    os.symlink(real, link)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(link))

    state.state_dir()

    assert _mode(real) == 0o755


def test_read_only_dir_falls_back_to_in_place_write(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    base.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    state.write_cursor("session-1", "uuid-1")
    os.chmod(base, 0o500)
    try:
        state.write_cursor("session-1", "uuid-2")
        assert state.read_cursor("session-1") == "uuid-2"
    finally:
        os.chmod(base, 0o700)


def test_cleanup_state_removes_stale_temp_files(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    state.write_cursor("session-1", "uuid-1")
    (base / ".session-1.cursor.abc123").write_text("partial")
    (base / ".session-1.seq.def456").write_text("partial")
    (base / ".session-2.cursor.xyz789").write_text("other")

    state.cleanup_state("session-1")

    assert sorted(os.listdir(base)) == [".session-2.cursor.xyz789"]


def _session(base, sid: str, transcript: str, age_s: float = 0) -> None:
    import time  # noqa: PLC0415

    state.write_cursor(sid, "uuid")
    state.write_meta(sid, transcript)
    stamp = time.time() - age_s
    for suffix in (".cursor", ".meta"):
        os.utime(base / f"{sid}{suffix}", (stamp, stamp))


def _aged_file(path, age_s: float) -> str:
    import time  # noqa: PLC0415

    path.write_text("")
    os.utime(path, (time.time() - age_s, time.time() - age_s))
    return str(path)


_DAY = 24 * 3600


def test_gc_drops_missing_transcript_and_old_sessions(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    alive = _aged_file(tmp_path / "alive.jsonl", 0)
    stale = _aged_file(tmp_path / "stale.jsonl", 40 * _DAY)
    _session(base, "keep", alive)
    _session(base, "long_running", alive, age_s=31 * _DAY)
    _session(base, "gone", str(tmp_path / "deleted.jsonl"))
    _session(base, "old", stale, age_s=31 * _DAY)
    state.write_cursor("legacy", "uuid")
    os.utime(base / "legacy.cursor", (0, 0))
    (base / ".gone.cursor.abc123").write_text("partial")
    _session(base, "current", str(tmp_path / "deleted.jsonl"))
    state.write_health({"consecutive": 1})

    assert state.gc_sessions("current") == (3, True)

    remaining = sorted(os.listdir(base))
    for kept in ("keep.cursor", "long_running.cursor", "current.cursor", "health.json"):
        assert kept in remaining
    assert not [f for f in remaining if f.lstrip(".").startswith(("gone.", "old."))]
    assert "legacy.cursor" not in remaining
    assert "gc.stamp" in remaining


def test_gc_caps_sessions_oldest_first(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    monkeypatch.setattr(state, "STATE_MAX_SESSIONS", 3)
    for i in range(5):
        transcript = _aged_file(tmp_path / f"t{i}.jsonl", 100 - i)
        _session(base, f"s{i}", transcript, age_s=100 - i)

    assert state.gc_sessions("s0") == (2, True)

    cursors = sorted(f for f in os.listdir(base) if f.endswith(".cursor"))
    assert cursors == ["s0.cursor", "s3.cursor", "s4.cursor"]


def test_gc_is_bounded_and_resumes(tmp_path, monkeypatch) -> None:
    base = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(base))
    for i in range(30):
        state.write_cursor(f"s{i}", "uuid")
        os.utime(base / f"s{i}.cursor", (0, 0))

    assert state.gc_sessions("cur", max_deletions=10) == (10, False)
    assert state.gc_due()
    assert state.gc_sessions("cur", time_slice_s=0) == (0, False)
    assert state.gc_sessions("cur") == (20, True)
    assert not state.gc_due()


def test_gc_due_respects_interval(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    assert state.gc_due(now=1_000_000.0)

    state.gc_sessions("cur", now=1_000_000.0)
    os.utime(tmp_path / "gc.stamp", (1_000_000.0, 1_000_000.0))

    assert not state.gc_due(now=1_000_000.0 + 3599)
    assert state.gc_due(now=1_000_000.0 + 3601)
    assert _mode(tmp_path / "gc.stamp") == 0o600
