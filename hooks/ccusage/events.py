"""Builds Event/LlmInteraction message bytes for the ingestion endpoint.

Built with the minimal wire encoder in wire.py rather than a general
protobuf library, so the plugin has no third-party runtime dependency.
Byte-for-byte correctness against the real backend schema is verified by
tests/test_wire_compatibility.py.
"""

from __future__ import annotations

import time
import uuid

from . import wire
from .config import (
    AGENT_LIBRARY,
    AGENT_MANUFACTURER,
    AGENT_SUPPLIER,
    AGENT_TYPE_MANAGED,
    AISPM_DEPENDENCY_TYPE_MODEL,
    ASSET_ID,
    INVENTORY_SESSION_ID,
    SENSOR_TYPE,
    SENSOR_VERSION,
)
from .fingerprints import (
    app_asset_id,
    condensed_fingerprint,
    interaction_fingerprint,
    make_agent_fingerprint,
    make_model_fingerprint,
)
from .identity import slot_id
from .pii import PiiRedactor
from .redact import nul_free, redact, sanitize_turn
from .transcript import TranscriptBucket, TranscriptTurn

# Role and InteractionType enum values this plugin ever sends (see the real
# schema's Role/InteractionType enums for the full set).
ROLE_USER = 5
ROLE_ASSISTANT = 2  # ROLE_ASSISTANT_MODEL
INTERACTION_TYPE_MESSAGE = 2


def build_model(model_name: str) -> bytes:
    """Build a Model message. Manufacturer/supplier are hardcoded to Anthropic."""
    body = b""
    body += wire.string_field(1, make_model_fingerprint("Anthropic", model_name))
    body += wire.string_field(2, model_name)
    body += wire.string_field(3, "unknown")
    body += wire.string_field(4, "Anthropic")
    body += wire.string_field(5, "Anthropic")
    body += wire.string_field(7, "Managed")
    return body


def build_model_dependency(model_name: str) -> bytes:
    """Build a dependency linking the Agent to the Model it used."""
    ref_data = wire.string_field(1, model_name) + wire.string_field(2, "Anthropic")
    body = wire.varint_field(1, AISPM_DEPENDENCY_TYPE_MODEL)
    body += wire.string_field(2, make_model_fingerprint("Anthropic", model_name))
    body += wire.string_field(3, model_name)
    body += wire.message_field(4, ref_data)
    return body


def build_agent(agent_name: str, model_name: str) -> bytes:
    """Build an Agent message identifying who/what produced the interaction.

    Library/supplier/manufacturer/type are hardcoded: Claude Code is
    Anthropic's own managed CLI, not something defined in the scanned
    codebase, so provenance is the same for every agent this plugin reports.
    """
    body = b""
    body += wire.string_field(1, make_agent_fingerprint(agent_name))
    body += wire.string_field(2, agent_name)
    body += wire.string_field(3, AGENT_LIBRARY)
    body += wire.string_field(4, AGENT_SUPPLIER)
    body += wire.string_field(5, AGENT_MANUFACTURER)
    body += wire.message_field(12, build_model_dependency(model_name))
    body += wire.varint_field(13, AGENT_TYPE_MANAGED)
    return body


def build_content(text: str, role: int = ROLE_USER) -> bytes:
    """Build a text LlmInteractionContent. Defaults to ROLE_USER."""
    text_content = wire.string_field(1, text)
    body = wire.message_field(1, text_content)
    body += wire.varint_field(4, role)
    return body


def build_text_block(text: str) -> bytes:
    """Build a ContentBlock{text=TextBlock} (nested inside a tool_result's own text)."""
    text_block = wire.string_field(1, text)
    return wire.message_field(1, text_block)


def build_tool_result_block(tool_use_id: str, text: str, is_error: bool) -> bytes:
    """Build a ContentBlock{tool_result=ToolResultBlock} (report mode "full" only)."""
    body = wire.string_field(1, tool_use_id)
    if text:
        body += wire.message_field(2, build_text_block(text))
    if is_error:
        body += wire.varint_field(3, 1)
    return wire.message_field(3, body)


def build_turn_content(blocks: list[dict], role: int) -> bytes:
    """Build an LlmInteractionContent for one side of a turn (report modes text/full).

    Real conversation text goes in `text_content`. `tool_use` blocks (response
    side, "full" only) go in the dedicated `tool_use` field; `tool_result`
    blocks (prompt side, "full" only) go in `content_blocks`.
    """
    text_parts = [b["text"] for b in blocks if b["kind"] == "text" and b["text"]]

    body = b""
    if text_parts:
        body += wire.message_field(1, wire.string_field(1, "\n\n".join(text_parts)))
    for block in blocks:
        if block["kind"] == "tool_use":
            tool_use_body = wire.string_field(1, block["id"])
            tool_use_body += wire.string_field(2, block["name"])
            tool_use_body += wire.string_field(3, block["input_json"])
            body += wire.message_field(3, tool_use_body)
    body += wire.varint_field(4, role)
    for block in blocks:
        if block["kind"] == "tool_result":
            body += wire.message_field(
                5,
                build_tool_result_block(
                    block["tool_use_id"], block["text"], block["is_error"]
                ),
            )
    return body


def build_usage(
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
) -> bytes:
    """Build a Usage message from already-folded token counts."""
    body = wire.varint_field(1, input_tokens)
    body += wire.varint_field(2, output_tokens)
    body += wire.varint_field(3, cache_read_tokens)
    body += wire.varint_field(4, cache_write_tokens)
    return body


def build_app_info(repo_name: str, repo_url: str) -> bytes:
    """Build an LlmInteractionApplicationInfo identifying the reporting repo."""
    body = wire.string_field(1, repo_name)
    body += wire.string_field(2, app_asset_id(repo_url))
    return body


def build_prompt_text(
    title: str, repo_name: str, branch: str | None, pii: PiiRedactor | None = None
) -> str:
    """Combine repo/branch/title into the single string sent as `prompt`.

    See README's "Why repo/branch/title all ride in prompt" for why `response`
    is always left empty instead.
    """
    pii = pii if pii is not None else PiiRedactor()
    title, repo_name = redact(title, pii), redact(repo_name, pii)
    location = f"{repo_name}:{redact(branch, pii)}" if branch else repo_name
    return f"{title} ({location})"


def build_llm_interaction(
    session_id: str,
    model_name: str,
    bucket: TranscriptBucket,
    agent_name: str,
    title: str,
    repo_name: str,
    repo_url: str,
    branch: str | None = None,
    window_start: str | None = None,
    pii: PiiRedactor | None = None,
) -> bytes:
    """Build the LlmInteraction for one model's slice of a transcript delta."""
    session_id, model_name, agent_name, title, repo_name, repo_url = map(
        nul_free, (session_id, model_name, agent_name, title, repo_name, repo_url)
    )
    branch = nul_free(branch) if branch else branch
    pii = pii if pii is not None else PiiRedactor()
    fp = condensed_fingerprint(session_id, model_name, window_start)
    body = wire.string_field(1, fp)
    body += wire.timestamp_field(2, bucket["last_seconds"], bucket["last_nanos"])
    body += wire.message_field(3, build_model(model_name))
    body += wire.message_field(
        5, build_content(build_prompt_text(title, repo_name, branch, pii))
    )
    body += wire.message_field(11, build_app_info(redact(repo_name, pii), repo_url))
    body += wire.varint_field(12, INTERACTION_TYPE_MESSAGE)
    body += wire.message_field(
        13,
        build_usage(
            bucket["input"],
            bucket["output"],
            bucket["cache_read"],
            bucket["cache_write"],
        ),
    )
    body += wire.string_field(17, session_id)
    body += wire.message_field(18, build_agent(agent_name, model_name))
    return body


def build_llm_interaction_turn(
    session_id: str,
    turn: TranscriptTurn,
    agent_name: str,
    repo_name: str,
    repo_url: str,
    sequence_number: int,
    pii: PiiRedactor | None = None,
) -> bytes:
    """Build the LlmInteraction for one conversation turn (report modes text/full)."""
    session_id, agent_name, repo_name, repo_url = map(
        nul_free, (session_id, agent_name, repo_name, repo_url)
    )
    model_name = nul_free(turn["model"])
    pii = pii if pii is not None else PiiRedactor()
    prompt_blocks, response_blocks = sanitize_turn(
        turn["prompt_blocks"], turn["response_blocks"], pii
    )
    fp = interaction_fingerprint(session_id, model_name, turn["uuid"])
    body = wire.string_field(1, fp)
    body += wire.timestamp_field(2, turn["seconds"], turn["nanos"])
    body += wire.message_field(3, build_model(model_name))
    body += wire.message_field(5, build_turn_content(prompt_blocks, ROLE_USER))
    body += wire.message_field(6, build_turn_content(response_blocks, ROLE_ASSISTANT))
    body += wire.message_field(11, build_app_info(redact(repo_name, pii), repo_url))
    body += wire.varint_field(12, INTERACTION_TYPE_MESSAGE)
    body += wire.message_field(
        13,
        build_usage(
            turn["input"], turn["output"], turn["cache_read"], turn["cache_write"]
        ),
    )
    body += wire.string_field(14, session_id)
    body += wire.varint_field(15, sequence_number)
    body += wire.string_field(17, session_id)
    body += wire.message_field(18, build_agent(agent_name, model_name))
    return body


def build_event(
    *,
    session_open: bytes | None = None,
    data: bytes | None = None,
    repo_url: str | None = None,
) -> bytes:
    """Build an Event with the common envelope fields plus exactly one payload.

    Exactly one of `session_open` (a SessionOpen body) or `data` (a Data
    body) must be provided, matching the real schema's `payload` oneof.
    """
    now = time.time()
    seconds = int(now)
    nanos = int(round((now - seconds) * 1e9))
    body = wire.string_field(1, str(uuid.uuid4()))
    body += wire.string_field(3, ASSET_ID)
    body += wire.string_field(4, INVENTORY_SESSION_ID)  # static, inventory/currentness
    body += wire.string_field(5, slot_id(repo_url))
    body += wire.timestamp_field(6, seconds, nanos)
    body += wire.string_field(8, SENSOR_TYPE)
    if session_open is not None and data is None:
        body += wire.message_field(100, session_open)
    elif data is not None and session_open is None:
        body += wire.message_field(101, data)
    else:
        raise ValueError("exactly one of session_open/data is required")
    return body


def build_interaction_event(interaction: bytes, repo_url: str | None = None) -> bytes:
    """Wrap an LlmInteraction in an Event with a `data` payload."""
    aispm_interaction = wire.message_field(1, interaction)
    data = wire.message_field(121, aispm_interaction)
    return build_event(data=data, repo_url=repo_url)


def build_session_open_event(repo_url: str | None = None) -> bytes:
    """Build the one-time Event sent to mark a session as opened."""
    open_msg = wire.string_field(2, SENSOR_TYPE) + wire.string_field(3, SENSOR_VERSION)
    return build_event(session_open=open_msg, repo_url=repo_url)
