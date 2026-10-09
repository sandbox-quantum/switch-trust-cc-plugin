"""Best-effort logging to stderr and a persistent log file."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from .state import state_dir, write_private_file


def log_path(state_dir_override: str | None = None) -> str:
    """Path to the persistent, size-capped log file.

    `state_dir_override` is forwarded to `state.state_dir()` -- see its
    docstring.
    """
    return os.path.join(state_dir(state_dir_override), "ccusage.log")


def log(msg: str) -> None:
    """Best-effort log to stderr AND a persistent file.

    stderr is visible with `claude --debug`; the file (see log_path()) is always
    written so you can inspect activity after the fact.
    """
    try:
        sys.stderr.write(f"[ccusage] {msg}\n")
    except Exception:
        pass
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} {msg}\n"
        path = log_path()
        write_private_file(path, line, append=True)
        # Simple size cap so the log can't grow unbounded (~1 MB rotation).
        try:
            if os.path.getsize(path) > 1_000_000:
                os.replace(path, path + ".1")
        except OSError:
            pass
    except Exception:
        pass
