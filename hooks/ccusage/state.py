"""Cursor / session state persisted on disk between hook invocations."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time

from .config import (
    GC_INTERVAL_S,
    STATE_MAX_AGE_S,
    STATE_MAX_SESSIONS,
    STOP_MIN_INTERVAL_S,
    STOP_MIN_TOKENS,
)

_PRIVATE_DIR_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def state_dir(override: str | None = None) -> str:
    """Location for cursors, markers, cache, and the log.

    Prefers Claude Code's own per-plugin data directory
    (`${CLAUDE_PLUGIN_DATA}`), set for every hook invocation. Falls back to
    `~/.switch-trust/roi_cc_plugin/` for invocations outside a hook (e.g.
    `ccusage_reporter.py status` run by hand), where that env var is unset.

    `override`, when given, wins over both: it's how a Bash-tool-invoked
    command (which Claude Code does NOT export `CLAUDE_PLUGIN_DATA` to --
    only real hook subprocesses get it) can still be told the true directory,
    by passing `${CLAUDE_PLUGIN_DATA}` as a CLI flag instead of relying on
    the process environment. See `ccusage_reporter.py`'s `--state-dir`.
    """
    base = (
        override
        or os.environ.get("CLAUDE_PLUGIN_DATA")
        or os.path.join(os.path.expanduser("~"), ".switch-trust", "roi_cc_plugin")
    )
    try:
        os.makedirs(base, mode=_PRIVATE_DIR_MODE, exist_ok=True)
        if not override and not os.path.islink(base) and os.stat(base).st_mode & 0o077:
            os.chmod(base, _PRIVATE_DIR_MODE)
    except Exception:
        pass
    return base


def write_private_file(path: str, text: str, append: bool = False) -> None:
    """Write `text` to `path` as an owner-only (0600) file without following a symlink.

    Overwrites go through a temp file and `os.replace`, so a kill mid-write
    leaves the previous content; if that fails (read-only dir), rewrite in place.
    """
    if append:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
        fd = os.open(path, flags, _PRIVATE_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8", errors="replace") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, _PRIVATE_FILE_MODE)
            fh.write(text)
        return
    try:
        _replace_atomically(path, text)
    except OSError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW
        fd = os.open(path, flags, _PRIVATE_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, _PRIVATE_FILE_MODE)
            fh.write(text)


def _replace_atomically(path: str, text: str) -> None:
    directory, name = os.path.split(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=directory or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def cursor_path(session_id: str | None) -> str:
    """Path to the file tracking the last-reported transcript message for a session."""
    return os.path.join(state_dir(), f"{session_id or 'unknown'}.cursor")


def opened_path(session_id: str | None) -> str:
    """Path to the marker file recording that a session-open event was sent."""
    return os.path.join(state_dir(), f"{session_id or 'unknown'}.opened")


def last_emit_path(session_id: str | None) -> str:
    """Path to the file recording when a session last reported (for throttling)."""
    return os.path.join(state_dir(), f"{session_id or 'unknown'}.last_emit")


def sequence_path(session_id: str | None) -> str:
    """Path to the file tracking the next LlmInteraction.sequence_number to use.

    Only used by turn-based report modes (text/full); each hook invocation is
    a short-lived process, so the next sequence number must be persisted
    between invocations to keep a conversation's rows in order.
    """
    return os.path.join(state_dir(), f"{session_id or 'unknown'}.seq")


def meta_path(session_id: str | None) -> str:
    """Path to the file recording which transcript a session's state belongs to (for GC)."""
    return os.path.join(state_dir(), f"{session_id or 'unknown'}.meta")


def health_path(override: str | None = None) -> str:
    return os.path.join(state_dir(override), "health.json")


_SESSION_SUFFIXES = (".cursor", ".seq", ".opened", ".last_emit", ".meta")


def _log_unexpected(msg: str, exc: Exception) -> None:
    """Log everything except a missing file -- that's the normal first-run case.

    Lazy import: log.py imports state_dir() from this module, so a top-level
    `from .log import log` here would be circular.
    """
    if isinstance(exc, FileNotFoundError):
        return
    from .log import log  # noqa: PLC0415 - circular import at module scope

    log(f"{msg}: {exc}")


def read_cursor(session_id: str | None) -> str | None:
    """Return the last-reported transcript message uuid, or None if unset/unreadable."""
    try:
        with open(cursor_path(session_id)) as fh:
            val = fh.read().strip()
            return val or None
    except Exception as exc:
        _log_unexpected(f"read_cursor({session_id!r}) failed", exc)
        return None


def write_cursor(session_id: str | None, cursor_uuid: str | None) -> None:
    """Persist the last-reported transcript message uuid. A no-op if `cursor_uuid` is falsy."""
    if not cursor_uuid:
        return
    try:
        write_private_file(cursor_path(session_id), cursor_uuid)
    except Exception as exc:
        _log_unexpected(f"write_cursor({session_id!r}) failed", exc)


def should_throttle_stop(session_id: str | None, total_new_tokens: int) -> bool:
    """On Stop, skip if too soon AND not enough new tokens accumulated."""
    if total_new_tokens >= STOP_MIN_TOKENS:
        return False
    try:
        with open(last_emit_path(session_id)) as fh:
            last = float(fh.read().strip())
        if (time.time() - last) < STOP_MIN_INTERVAL_S:
            return True
    except Exception as exc:
        _log_unexpected(f"should_throttle_stop({session_id!r}) failed", exc)
        return False
    return False


def read_sequence(session_id: str | None) -> int:
    """Return the next sequence_number to use for turn-mode reporting (0 if unset)."""
    try:
        with open(sequence_path(session_id)) as fh:
            return int(fh.read().strip() or 0)
    except Exception as exc:
        _log_unexpected(f"read_sequence({session_id!r}) failed", exc)
        return 0


def write_sequence(session_id: str | None, next_seq: int) -> None:
    """Persist the next sequence_number to use for turn-mode reporting."""
    try:
        write_private_file(sequence_path(session_id), str(next_seq))
    except Exception as exc:
        _log_unexpected(f"write_sequence({session_id!r}) failed", exc)


def mark_emitted(session_id: str | None) -> None:
    """Record the current time as the last successful report, for throttling."""
    try:
        write_private_file(last_emit_path(session_id), str(time.time()))
    except Exception as exc:
        _log_unexpected(f"mark_emitted({session_id!r}) failed", exc)


def cleanup_state(session_id: str | None) -> None:
    """Remove all on-disk state (cursor, opened marker, throttle timestamp) for a session."""
    sid = session_id or "unknown"
    try:
        entries = _session_files(state_dir()).get(sid, [])
    except OSError as exc:
        _log_unexpected(f"cleanup_state({session_id!r}) failed listing", exc)
        return
    for entry in entries:
        try:
            os.remove(entry.path)
        except Exception as exc:
            _log_unexpected(
                f"cleanup_state({session_id!r}) failed removing {entry.path!r}", exc
            )


def write_meta(session_id: str | None, transcript_path: str) -> None:
    try:
        write_private_file(meta_path(session_id), transcript_path)
    except Exception as exc:
        _log_unexpected(f"write_meta({session_id!r}) failed", exc)


def read_health(override: str | None = None) -> dict:
    try:
        with open(health_path(override)) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        _log_unexpected("read_health failed", exc)
        return {}


def write_health(data: dict) -> None:
    try:
        write_private_file(health_path(), json.dumps(data, sort_keys=True))
    except Exception as exc:
        _log_unexpected("write_health failed", exc)


def gc_due(now: float | None = None) -> bool:
    """True unless a sweep completed within the GC interval; an unfinished sweep resumes next run."""
    now = time.time() if now is None else now
    try:
        return now - os.stat(_gc_stamp_path()).st_mtime >= GC_INTERVAL_S
    except OSError:
        return True


def _gc_stamp_path() -> str:
    return os.path.join(state_dir(), "gc.stamp")


def _session_files(directory: str) -> dict[str, list[os.DirEntry]]:
    sessions: dict[str, list[os.DirEntry]] = {}
    for entry in os.scandir(directory):
        name = entry.name
        if name.startswith("."):
            name = name[1:].rsplit(".", 1)[0]
        for suffix in _SESSION_SUFFIXES:
            if name.endswith(suffix) and len(name) > len(suffix):
                sessions.setdefault(name[: -len(suffix)], []).append(entry)
                break
    return sessions


def _last_activity(directory: str, entries: list[os.DirEntry]) -> float | None:
    """Newest of the state files and the session's transcript; None if the transcript is gone."""
    newest = max(entry.stat(follow_symlinks=False).st_mtime for entry in entries)
    meta = [entry for entry in entries if entry.name.endswith(".meta")]
    if not meta or meta[0].name.startswith("."):
        return newest
    try:
        with open(meta[0].path) as fh:
            transcript = fh.read().strip()
    except OSError:
        return newest
    if not transcript:
        return newest
    try:
        return max(newest, os.stat(transcript).st_mtime)
    except OSError:
        return None


def gc_sessions(
    current_session_id: str | None,
    time_slice_s: float = 0.3,
    max_deletions: int = 500,
    now: float | None = None,
) -> tuple[int, bool]:
    """Drop sessions whose transcript is gone, idle over 30 days, or past the cap.

    Bounded by `time_slice_s` and `max_deletions`; returns (sessions removed,
    sweep completed). gc.stamp is only written once a sweep completes.
    """
    now = time.time() if now is None else now
    stop_at = time.monotonic() + time_slice_s
    directory = state_dir()
    sessions = _session_files(directory)
    sessions.pop(current_session_id or "unknown", None)
    removed = 0

    def _remove(sid: str) -> bool:
        nonlocal removed
        for entry in sessions.pop(sid):
            with contextlib.suppress(OSError):
                os.remove(entry.path)
        removed += 1
        return removed < max_deletions and time.monotonic() < stop_at

    activity: dict[str, float] = {}
    for sid in list(sessions):
        if time.monotonic() >= stop_at:
            return removed, False
        last = _last_activity(directory, sessions[sid])
        if last is None or now - last > STATE_MAX_AGE_S:
            if not _remove(sid):
                return removed, False
        else:
            activity[sid] = last
    overflow = sorted(activity, key=activity.__getitem__)
    for sid in overflow[: max(len(overflow) - (STATE_MAX_SESSIONS - 1), 0)]:
        if not _remove(sid):
            return removed, False
    write_private_file(_gc_stamp_path(), str(now))
    return removed, True
