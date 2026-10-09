"""Identity resolution (user email, slot id, repo origin)."""

from __future__ import annotations

import getpass
import os
import subprocess
import time

from . import project_settings
from .config import (
    OPTION_SWITCH_TRUST_USER_EMAIL,
    SENSOR_TYPE,
    USER_EMAIL_RETRY_INTERVAL_S,
)
from .fingerprints import app_asset_id
from .state import state_dir, write_private_file

ANONYMOUS_USER = "anonymous"


def slot_id(repo_url: str | None) -> str:
    """Slot events are attributed to: one per repo, derived from its URL."""
    return f"{SENSOR_TYPE}-{app_asset_id(repo_url)}"


def _email_from_git_config(cwd: str | None) -> str | None:
    """Best-effort `git config user.email`, scoped to the session's repo. None on any error."""
    try:
        out = (
            subprocess.check_output(
                ["git", "config", "--get", "user.email"],
                cwd=cwd or None,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            .decode("utf-8")
            .strip()
        )
        return out or None
    except Exception:
        return None


def _os_username() -> str | None:
    """Best-effort OS login name -- last resort before ANONYMOUS_USER."""
    try:
        return getpass.getuser() or None
    except Exception:
        return None


def get_user_email(cwd: str | None = None) -> str:
    """Resolve a per-user identifier, cached aggressively, never blocking.

    Precedence: the `switch_trust_user_email` userConfig override > cached value
    from a previous resolution > `git config user.email` > OS login name >
    `ANONYMOUS_USER`. Each layer falls through to the next on any error, so
    this function itself never raises. Resolution is entirely local -- no
    cloud provider or identity service is ever contacted.

    Unlike a real email, `ANONYMOUS_USER` isn't cached long-term, so a later
    run can pick up a newly-configured identity -- but the full fallback
    chain (up to ~5s for the `git config` subprocess call) is only retried
    once per `USER_EMAIL_RETRY_INTERVAL_S`, not on every hook invocation.
    """
    override = project_settings.get(OPTION_SWITCH_TRUST_USER_EMAIL)
    if override:
        return override

    cache_file = os.path.join(state_dir(), "user_email")
    try:
        if os.path.isfile(cache_file):
            with open(cache_file) as fh:
                cached = fh.read().strip()
            if cached:
                return cached
    except Exception:
        pass

    retry_marker = os.path.join(state_dir(), "user_email.retry_at")
    try:
        if os.path.isfile(retry_marker):
            with open(retry_marker) as fh:
                retry_at = float(fh.read().strip())
            if time.time() < retry_at:
                return ANONYMOUS_USER
    except Exception:
        pass

    email = _email_from_git_config(cwd) or _os_username()
    if not email:
        try:
            write_private_file(
                retry_marker, str(time.time() + USER_EMAIL_RETRY_INTERVAL_S)
            )
        except Exception:
            pass
        return ANONYMOUS_USER

    try:
        write_private_file(cache_file, email)
    except Exception:
        pass
    return email


def get_repo_url(cwd: str | None) -> str:
    """Read the origin remote URL from <cwd>/.git/config (no git dependency)."""
    if not cwd:
        return ""
    git_path = os.path.join(cwd, ".git")
    git_dir = git_path
    try:
        if os.path.isfile(git_path):
            # Worktree: .git is a file "gitdir: <path>".
            with open(git_path) as fh:
                for line in fh:
                    if line.startswith("gitdir:"):
                        git_dir = line.split(":", 1)[1].strip()
                        break
        config = os.path.join(git_dir, "config")
        if not os.path.isfile(config):
            return ""
        in_origin = False
        with open(config) as fh:
            for line in fh:
                s = line.strip()
                if s.startswith("["):
                    in_origin = s == '[remote "origin"]'
                elif in_origin and s.startswith("url"):
                    return s.split("=", 1)[1].strip()
    except Exception:
        return ""
    return ""


def repo_name_from_url(url: str) -> str:
    """Extract the bare repo name from a git remote URL, e.g. `.../owner/repo.git` -> `repo`."""
    if not url:
        return "unknown"
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or "unknown"
