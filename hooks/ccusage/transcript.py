"""Transcript delta parsing.

Reads new assistant messages since a per-session cursor and folds cache
tokens into a billing-equivalent effective input-token count.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, TypedDict

from .config import CACHE_READ_MULT, CACHE_WRITE_1H_MULT, CACHE_WRITE_5M_MULT
from .log import log
from .redact import guard_shell_blocks


class TranscriptBucket(TypedDict):
    eff_input: int
    output: int
    last_uuid: str | None
    last_seconds: int
    last_nanos: int


class TranscriptTurn(TypedDict):
    model: str
    eff_input: int
    output: int
    uuid: str | None
    seconds: int
    nanos: int
    prompt_blocks: list[dict[str, Any]]
    response_blocks: list[dict[str, Any]]
    stop_reason: str


def parse_ts(ts: str | None) -> tuple[int, int]:
    """ISO-8601 (with trailing Z) -> (epoch_seconds, nanos)."""
    if not ts:
        return 0, 0
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        epoch = dt.timestamp()
        seconds = int(epoch)
        nanos = int(round((epoch - seconds) * 1e9))
        return seconds, nanos
    except Exception:
        return 0, 0


def fold_effective_input(usage: dict[str, Any]) -> int:
    """Fold raw + cache tokens into a billing-equivalent input-token count."""
    inp = usage.get("input_tokens") or 0
    cache_read = usage.get("cache_read_input_tokens") or 0
    cache_creation = usage.get("cache_creation") or {}
    cr5 = cache_creation.get("ephemeral_5m_input_tokens")
    cr1 = cache_creation.get("ephemeral_1h_input_tokens")
    if cr5 is None and cr1 is None:
        # No breakdown available: treat all cache-creation as 5m.
        cr5 = usage.get("cache_creation_input_tokens") or 0
        cr1 = 0
    else:
        cr5 = cr5 or 0
        cr1 = cr1 or 0
    effective = (
        inp
        + CACHE_READ_MULT * cache_read
        + CACHE_WRITE_5M_MULT * cr5
        + CACHE_WRITE_1H_MULT * cr1
    )
    return int(round(effective))


def read_transcript_delta(
    transcript_path: str, cursor_uuid: str | None
) -> tuple[dict[str, TranscriptBucket], str | None, str | None, str | None, int]:
    """Return (per_model, latest_title, latest_branch, new_cursor, total_new).

    Only assistant entries after cursor_uuid are considered, deduped by
    message id. latest_branch is the newest `gitBranch` seen in the file,
    even if the user switched branches mid-session.
    """
    per_model: dict[str, TranscriptBucket] = {}
    latest_title: str | None = None
    latest_branch: str | None = None
    new_cursor = cursor_uuid
    seen_ids: set[str] = set()
    total_new = 0
    passed_cursor = cursor_uuid is None  # if no cursor, everything is new

    try:
        with open(transcript_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                # Isolated per-entry so one malformed line doesn't discard
                # entries already accumulated in this delta, or permanently
                # stall the cursor on the same bad line.
                try:
                    branch = obj.get("gitBranch")
                    if branch:
                        latest_branch = branch

                    etype = obj.get("type")
                    if etype == "ai-title":
                        title = obj.get("aiTitle")
                        if title:
                            latest_title = title
                        continue
                    if etype != "assistant":
                        continue

                    entry_uuid = obj.get("uuid")
                    # Fast-forward until we're past the cursor line.
                    if not passed_cursor:
                        if entry_uuid == cursor_uuid:
                            passed_cursor = True
                        continue

                    new_cursor = entry_uuid or new_cursor

                    message = obj.get("message") or {}
                    model = message.get("model")
                    usage = message.get("usage")
                    if not model or not usage:
                        continue

                    msg_id = message.get("id") or entry_uuid
                    if msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    eff = fold_effective_input(usage)
                    out = usage.get("output_tokens") or 0
                    total_new += eff + out

                    secs, nanos = parse_ts(obj.get("timestamp"))
                    bucket = per_model.get(model)
                    if bucket is None:
                        bucket = {
                            "eff_input": 0,
                            "output": 0,
                            "last_uuid": entry_uuid,
                            "last_seconds": secs,
                            "last_nanos": nanos,
                        }
                        per_model[model] = bucket
                    bucket["eff_input"] += eff
                    bucket["output"] += out
                    if entry_uuid:
                        bucket["last_uuid"] = entry_uuid
                    bucket["last_seconds"] = secs
                    bucket["last_nanos"] = nanos
                except Exception as exc:
                    log(f"skipping malformed transcript entry: {exc}")
                    continue
    except FileNotFoundError:
        return {}, None, None, cursor_uuid, 0
    except Exception as exc:
        log(f"transcript read error: {exc}")
        return {}, None, None, cursor_uuid, 0

    return per_model, latest_title, latest_branch, new_cursor, total_new


def _normalize_content(content: Any) -> list[dict[str, Any]]:
    """A message's `content` is either a plain string or a list of typed blocks."""
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def _tool_result_text(content: Any) -> str:
    """Flatten a tool_result block's `content` (string or list of blocks) into text.

    Binary output (any NUL) is replaced with a placeholder: it can't be stored
    in Postgres text/jsonb, and it's already lossy by the time it reaches the
    transcript.
    """
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            b.get("text")
            for b in content
            if isinstance(b, dict) and b.get("type") == "text" and b.get("text")
        )
    else:
        return ""
    if "\x00" in text:
        return f"[binary output omitted: {len(text)} chars]"
    return text


def _extract_blocks(
    raw_blocks: list[dict[str, Any]], include_tools: bool
) -> list[dict[str, Any]]:
    """Turn raw message content blocks into the block shape events.py expects.

    Thinking blocks are dropped in every mode (internal reasoning, not
    conversation content). tool_use/tool_result are only kept when
    `include_tools` (report mode "full").
    """
    blocks: list[dict[str, Any]] = []
    for b in raw_blocks:
        btype = b.get("type")
        if btype == "text":
            text = b.get("text")
            if text:
                blocks.append({"kind": "text", "text": text})
        elif include_tools and btype == "tool_use":
            blocks.append(
                {
                    "kind": "tool_use",
                    "id": b.get("id") or "",
                    "name": b.get("name") or "",
                    "input_json": json.dumps(b.get("input") or {}),
                }
            )
        elif include_tools and btype == "tool_result":
            blocks.append(
                {
                    "kind": "tool_result",
                    "tool_use_id": b.get("tool_use_id") or "",
                    "text": _tool_result_text(b.get("content")),
                    "is_error": bool(b.get("is_error")),
                }
            )
    return blocks


def _is_real_prompt(raw_blocks: list[dict[str, Any]]) -> bool:
    """A user entry is a new logical turn iff it carries more than tool results.

    Claude Code logs each tool round-trip as its own `user`-role entry (the
    API represents tool results as user messages), interleaved with one
    `assistant` entry per model completion. A user entry made up entirely of
    `tool_result` blocks is a continuation of the in-flight agent turn, not a
    new prompt from the human.
    """
    return any(b.get("type") != "tool_result" for b in raw_blocks)


def _new_turn(prompt_blocks: list[dict[str, Any]]) -> TranscriptTurn:
    return {
        "model": "",
        "eff_input": 0,
        "output": 0,
        "uuid": None,
        "seconds": 0,
        "nanos": 0,
        "prompt_blocks": prompt_blocks,
        "response_blocks": [],
        "stop_reason": "",
    }


def read_transcript_turns(
    transcript_path: str, cursor_uuid: str | None, include_tools: bool
) -> tuple[list[TranscriptTurn], str | None, int]:
    """Return (turns, new_cursor, total_new) for turn-based (text/full) report modes.

    One `TranscriptTurn` per human-initiated exchange, not per model
    completion: a real user prompt opens a turn, and everything until the
    next real user prompt -- every intermediate assistant completion, tool
    call, and tool result -- folds into that same turn (token counts summed,
    blocks concatenated in order). A trailing turn with no assistant reply
    yet is left buffered for the next delta window, since it isn't persisted
    across runs.

    The same buffering applies mid-tool-call: an assistant completion with
    `stop_reason == "tool_use"` is still waiting on its tool result and a
    follow-up reply. If the file ends there (the Stop hook can fire and read
    the transcript before that follow-up is appended), the whole turn is
    deferred -- not just the trailing message -- by rewinding the cursor to
    where the turn started, so the next call re-reads and merges it whole
    instead of splitting it into a headless continuation turn.
    """
    turns: list[TranscriptTurn] = []
    new_cursor = cursor_uuid
    turn_start_cursor = cursor_uuid
    seen_ids: set[str] = set()
    total_new = 0
    passed_cursor = cursor_uuid is None  # if no cursor, everything is new
    current: TranscriptTurn | None = None
    shell_pending = False

    def flush() -> None:
        nonlocal current
        # Only a turn that actually closed out an assistant completion is
        # reportable -- one opened by a lone user prompt with no reply yet
        # is dropped here and naturally re-read next call (its cursor never
        # advanced).
        if current is not None and current["uuid"] is not None:
            turns.append(current)
        current = None

    try:
        with open(transcript_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                # See read_transcript_delta's comment on why malformed entries
                # are isolated rather than aborting the whole delta.
                try:
                    etype = obj.get("type")
                    entry_uuid = obj.get("uuid")

                    if etype == "user":
                        if not passed_cursor:
                            if entry_uuid == cursor_uuid:
                                passed_cursor = True
                            continue
                        message = obj.get("message") or {}
                        if message.get("role") != "user":
                            continue
                        raw_blocks, shell_pending = guard_shell_blocks(
                            _normalize_content(message.get("content")), shell_pending
                        )
                        if _is_real_prompt(raw_blocks):
                            flush()
                            current = _new_turn(
                                _extract_blocks(raw_blocks, include_tools)
                            )
                            turn_start_cursor = new_cursor
                        elif current is not None:
                            # Tool-result continuation of the in-flight turn.
                            current["prompt_blocks"].extend(
                                _extract_blocks(raw_blocks, include_tools)
                            )
                        continue

                    if etype != "assistant":
                        continue

                    if not passed_cursor:
                        if entry_uuid == cursor_uuid:
                            passed_cursor = True
                        continue

                    message = obj.get("message") or {}
                    model = message.get("model")
                    usage = message.get("usage")
                    if not model or not usage:
                        # Can't advance the cursor here: an in-progress
                        # `current` isn't persisted across runs, so skipping
                        # past it would lose the buffered turn for good.
                        continue

                    cursor_before_entry = new_cursor
                    new_cursor = entry_uuid or new_cursor

                    # Claude Code splits one model completion across several
                    # transcript lines sharing the same message id (e.g. a
                    # `thinking` line followed by its `tool_use`/`text`
                    # sibling), each carrying a full copy of that
                    # completion's usage. Dedup by id so usage is only
                    # counted once -- but every line's content is still
                    # unique and must be extracted, so the dedup can't
                    # `continue` past that or it silently drops whichever
                    # block didn't land on the first line (typically the
                    # final answer's own text).
                    msg_id = message.get("id") or entry_uuid
                    already_counted = msg_id in seen_ids
                    seen_ids.add(msg_id)

                    secs, nanos = parse_ts(obj.get("timestamp"))
                    raw_blocks = _normalize_content(message.get("content"))
                    response_blocks = _extract_blocks(raw_blocks, include_tools)

                    if current is None:
                        # An assistant reply with no buffered prompt (e.g. the
                        # cursor landed mid-turn): still report it, just with
                        # an empty prompt side.
                        current = _new_turn([])
                        turn_start_cursor = cursor_before_entry

                    current["model"] = model
                    current["uuid"] = entry_uuid
                    current["seconds"] = secs
                    current["nanos"] = nanos
                    current["response_blocks"].extend(response_blocks)
                    current["stop_reason"] = message.get("stop_reason") or ""

                    if not already_counted:
                        eff = fold_effective_input(usage)
                        out = usage.get("output_tokens") or 0
                        total_new += eff + out
                        current["eff_input"] += eff
                        current["output"] += out
                except Exception as exc:
                    log(f"skipping malformed transcript entry: {exc}")
                    continue
    except FileNotFoundError:
        return [], cursor_uuid, 0
    except Exception as exc:
        log(f"transcript read error: {exc}")
        return [], cursor_uuid, 0

    if current is not None and current["stop_reason"] == "tool_use":
        # The file ends mid tool-call: the tool result and follow-up reply
        # haven't been appended yet. Rewind the cursor to where this turn
        # started so the next call re-reads and merges it whole, instead of
        # flushing a headless piece here and stranding the rest as its own
        # turn with an empty prompt.
        new_cursor = turn_start_cursor
    else:
        flush()
    return turns, new_cursor, total_new
