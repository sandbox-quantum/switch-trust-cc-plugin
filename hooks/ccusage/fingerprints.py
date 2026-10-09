"""Fingerprint algorithms for models, agents, and interactions.

These SHAKE-256/SHA-256 based fingerprints match the backend's own
fingerprinting algorithm byte-for-byte, so a fingerprint computed here and
one computed by the backend for the same input are identical and join
correctly. Correctness is pinned against a shared set of golden test
vectors rather than by sharing code — see tests/test_fingerprints.py.
"""

from __future__ import annotations

import hashlib


def make_model_fingerprint(manufacturer: str, model_name: str) -> str:
    """mdl_ + SHAKE-256(16)("<manufacturer>:<model>"), both lowercased."""
    data = f"{manufacturer.lower()}:{model_name.lower()}".encode("utf-8", "replace")
    digest = hashlib.shake_256(data).hexdigest(16)
    return f"mdl_{digest}"


def make_agent_fingerprint(agent_name: str) -> str:
    """agn_ + SHAKE-256(16)(name). Case-sensitive (no lowercasing)."""
    digest = hashlib.shake_256(agent_name.encode("utf-8", "replace")).hexdigest(16)
    return f"agn_{digest}"


def interaction_fingerprint(session_id: str, model: str, last_uuid: str | None) -> str:
    """cci_ + SHA-256(16 bytes)("session:model:last_message_uuid").

    Unique per (session, model, delta window); deterministic so a retry of the
    same window produces the same row id (idempotent).
    """
    data = f"{session_id}:{model}:{last_uuid}".encode("utf-8", "replace")
    digest = hashlib.sha256(data).hexdigest()[:32]
    return f"cci_{digest}"


def condensed_fingerprint(session_id: str, model: str, window_start: str | None) -> str:
    """Keyed on where the window starts, so a wider retry upserts the same row (tokens overwrite)."""
    return interaction_fingerprint(session_id, model, f"from:{window_start or ''}")


def app_asset_id(repo_url: str | None) -> str:
    """app_ + SHA-256(16 bytes)(repo_url), or a fixed id when the url is unknown."""
    digest = hashlib.sha256(
        (repo_url or "unknown").encode("utf-8", "replace")
    ).hexdigest()[:32]
    return f"app_{digest}"
