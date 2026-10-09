"""Tests for hooks/ccusage/transcript.py: cache-token folding and delta parsing."""

from __future__ import annotations

import json
import os
import sys

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage.transcript import (  # noqa: E402
    _tool_result_text,
    fold_effective_input,
    read_transcript_delta,
    read_transcript_turns,
)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "state"))


def test_fold_effective_input_folds_cache_tokens() -> None:
    """Cache-read and both cache-creation buckets fold into the effective total."""
    usage = {
        "input_tokens": 100,
        "cache_read_input_tokens": 1000,
        "cache_creation": {
            "ephemeral_5m_input_tokens": 200,
            "ephemeral_1h_input_tokens": 50,
        },
    }
    # 100 + 0.10*1000 + 1.25*200 + 2.00*50 = 100 + 100 + 250 + 100 = 550
    assert fold_effective_input(usage) == 550


def test_fold_effective_input_no_cache_breakdown_treated_as_5m() -> None:
    """Without a 5m/1h breakdown, all cache-creation tokens are priced as 5m."""
    usage = {"input_tokens": 10, "cache_creation_input_tokens": 40}
    # 10 + 1.25*40 = 60
    assert fold_effective_input(usage) == 60


def _assistant_line(uuid: str, usage: dict) -> str:
    return json.dumps(
        {
            "type": "assistant",
            "uuid": uuid,
            "message": {"model": "claude-sonnet-5", "id": uuid, "usage": usage},
        }
    )


def test_read_transcript_delta_skips_one_malformed_entry_without_losing_others(
    tmp_path,
) -> None:
    """A single entry with an unexpected `usage` shape doesn't drop the whole delta.

    Regression test: the per-entry processing used to run inside the same
    try/except as the file read itself, so one bad entry discarded every
    valid entry already accumulated in the delta *and* the cursor advancement
    past them -- silently and permanently stalling reporting for the session.
    """
    good_usage = {"input_tokens": 10, "output_tokens": 5}
    # A non-empty cache_creation list (not a dict) makes fold_effective_input's
    # `.get()` call raise, simulating an unexpected transcript shape. (An
    # empty list would be falsy and silently replaced by `or {}` instead.)
    malformed_usage = {
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_creation": ["unexpected"],
    }

    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _assistant_line("u1", good_usage),
                _assistant_line("u2", malformed_usage),
                _assistant_line("u3", good_usage),
            ]
        )
    )

    per_model, _title, _branch, new_cursor, total_new = read_transcript_delta(
        str(transcript_path), cursor_uuid=None
    )

    # Only u1 and u3's tokens are counted; u2 is skipped, not fatal.
    assert per_model["claude-sonnet-5"]["eff_input"] == 20
    assert per_model["claude-sonnet-5"]["output"] == 10
    assert total_new == 30
    # The cursor still advances all the way to the last entry, so u2 is never
    # re-processed on the next call.
    assert new_cursor == "u3"


def _user_turn_line(uuid: str, content) -> str:
    return json.dumps(
        {"type": "user", "uuid": uuid, "message": {"role": "user", "content": content}}
    )


def _assistant_turn_line(
    uuid: str,
    content,
    usage: dict | None = None,
    stop_reason: str | None = None,
    msg_id: str | None = None,
) -> str:
    return json.dumps(
        {
            "type": "assistant",
            "uuid": uuid,
            "message": {
                "model": "claude-sonnet-5",
                "id": msg_id or uuid,
                "usage": usage or {"input_tokens": 10, "output_tokens": 5},
                "content": content,
                "stop_reason": stop_reason,
            },
        }
    )


def test_read_transcript_turns_pairs_user_text_with_assistant_response(
    tmp_path,
) -> None:
    """A plain-string user turn and text-block assistant reply become one turn."""
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "please fix the bug"),
                _assistant_turn_line(
                    "b1", [{"type": "text", "text": "done, fixed it"}]
                ),
            ]
        )
    )

    turns, new_cursor, _total_new = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=False
    )

    assert len(turns) == 1
    assert turns[0]["model"] == "claude-sonnet-5"
    assert turns[0]["prompt_blocks"] == [{"kind": "text", "text": "please fix the bug"}]
    assert turns[0]["response_blocks"] == [{"kind": "text", "text": "done, fixed it"}]
    assert new_cursor == "b1"


def test_read_transcript_turns_merges_tool_round_trip_into_one_turn(tmp_path) -> None:
    """A prompt -> tool call -> tool result -> reply exchange is one turn.

    Regression test: each `assistant` entry is one model completion, not one
    human-facing turn -- a tool round-trip must fold into the turn opened by
    the preceding real user prompt rather than splitting into two turns (one
    with the real prompt and an intermediate response, one with an empty
    prompt and the final response).
    """
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "run ls"),
                _assistant_turn_line(
                    "b1",
                    [
                        {"type": "text", "text": "Sure:"},
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "bash",
                            "input": {"command": "ls"},
                        },
                    ],
                    usage={"input_tokens": 10, "output_tokens": 5},
                ),
                _user_turn_line(
                    "a2",
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t1",
                            "content": "file1\nfile2",
                        }
                    ],
                ),
                _assistant_turn_line(
                    "b2",
                    [{"type": "text", "text": "Found 2 files"}],
                    usage={"input_tokens": 20, "output_tokens": 8},
                ),
            ]
        )
    )

    text_turns, new_cursor, total_new = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=False
    )
    assert len(text_turns) == 1
    assert text_turns[0]["prompt_blocks"] == [{"kind": "text", "text": "run ls"}]
    assert text_turns[0]["response_blocks"] == [
        {"kind": "text", "text": "Sure:"},
        {"kind": "text", "text": "Found 2 files"},
    ]
    assert text_turns[0]["eff_input"] == 30
    assert text_turns[0]["output"] == 13
    assert new_cursor == "b2"
    assert total_new == 43

    full_turns, _, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    assert len(full_turns) == 1
    assert full_turns[0]["prompt_blocks"] == [
        {"kind": "text", "text": "run ls"},
        {
            "kind": "tool_result",
            "tool_use_id": "t1",
            "text": "file1\nfile2",
            "is_error": False,
        },
    ]
    assert full_turns[0]["response_blocks"] == [
        {"kind": "text", "text": "Sure:"},
        {
            "kind": "tool_use",
            "id": "t1",
            "name": "bash",
            "input_json": '{"command": "ls"}',
        },
        {"kind": "text", "text": "Found 2 files"},
    ]


def test_tool_result_text_replaces_binary_output_with_placeholder() -> None:
    assert _tool_result_text("PNG\x00data") == "[binary output omitted: 8 chars]"
    assert (
        _tool_result_text([{"type": "text", "text": "a\x00b"}])
        == "[binary output omitted: 3 chars]"
    )


def test_tool_result_text_keeps_text_without_nul() -> None:
    assert _tool_result_text("日本語") == "日本語"
    assert _tool_result_text("lossy � but no nul") == "lossy � but no nul"
    assert (
        _tool_result_text(
            [{"type": "text", "text": "one"}, {"type": "text", "text": "two"}]
        )
        == "one\ntwo"
    )


def test_read_transcript_turns_omits_binary_tool_result(tmp_path) -> None:
    """Binary tool output (e.g. `head` on a PNG) is sent as a placeholder, never raw NULs."""
    png_head = "�PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "show the png header"),
                _assistant_turn_line(
                    "b1",
                    [
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "bash",
                            "input": {"command": "head -c 600 image.png"},
                        }
                    ],
                    usage={"input_tokens": 10, "output_tokens": 5},
                ),
                _user_turn_line(
                    "a2",
                    [{"type": "tool_result", "tool_use_id": "t1", "content": png_head}],
                ),
                _assistant_turn_line(
                    "b2",
                    [{"type": "text", "text": "That's a PNG"}],
                    usage={"input_tokens": 20, "output_tokens": 8},
                ),
            ]
        )
    )

    turns, _, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    assert len(turns) == 1
    assert turns[0]["prompt_blocks"][1] == {
        "kind": "tool_result",
        "tool_use_id": "t1",
        "text": f"[binary output omitted: {len(png_head)} chars]",
        "is_error": False,
    }
    assert "\x00" not in json.dumps(turns, ensure_ascii=False)


def test_read_transcript_turns_leaves_trailing_user_message_buffered(tmp_path) -> None:
    """A user message with no assistant reply yet isn't emitted as a turn.

    It should surface as `prompt_blocks` on the *next* call once a resuming
    reply appears, not be lost or emitted prematurely -- mirrors
    read_transcript_delta's cursor-resumption contract.
    """
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "first"),
                _assistant_turn_line("b1", [{"type": "text", "text": "reply1"}]),
                _user_turn_line("a2", "second"),
            ]
        )
    )

    turns, new_cursor, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=False
    )
    assert len(turns) == 1
    assert new_cursor == "b1"

    with open(transcript_path, "a") as fh:
        fh.write(
            "\n" + _assistant_turn_line("b2", [{"type": "text", "text": "reply2"}])
        )

    turns2, new_cursor2, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=new_cursor, include_tools=False
    )
    assert len(turns2) == 1
    assert turns2[0]["prompt_blocks"] == [{"kind": "text", "text": "second"}]
    assert new_cursor2 == "b2"


def _tool_use_block(tool_id: str, name: str = "bash") -> dict:
    return {"type": "tool_use", "id": tool_id, "name": name, "input": {}}


def _tool_result_line(uuid: str, tool_id: str, text: str) -> str:
    return _user_turn_line(
        uuid, [{"type": "tool_result", "tool_use_id": tool_id, "content": text}]
    )


def test_read_transcript_turns_merges_many_tool_calls_into_one_turn(tmp_path) -> None:
    """Several sequential tool calls within one exchange still fold into one turn."""
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "investigate"),
                _assistant_turn_line("b1", [_tool_use_block("t1")]),
                _tool_result_line("a2", "t1", "result1"),
                _assistant_turn_line("b2", [_tool_use_block("t2")]),
                _tool_result_line("a3", "t2", "result2"),
                _assistant_turn_line("b3", [_tool_use_block("t3")]),
                _tool_result_line("a4", "t3", "result3"),
                _assistant_turn_line("b4", [{"type": "text", "text": "done"}]),
            ]
        )
    )

    turns, new_cursor, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    assert len(turns) == 1
    turn = turns[0]
    assert turn["prompt_blocks"][0] == {"kind": "text", "text": "investigate"}
    tool_result_ids = [
        b["tool_use_id"] for b in turn["prompt_blocks"] if b["kind"] == "tool_result"
    ]
    assert tool_result_ids == ["t1", "t2", "t3"]
    tool_use_ids = [b["id"] for b in turn["response_blocks"] if b["kind"] == "tool_use"]
    assert tool_use_ids == ["t1", "t2", "t3"]
    assert turn["response_blocks"][-1] == {"kind": "text", "text": "done"}
    assert turn["eff_input"] == 40  # 4 assistant completions x 10 input tokens
    assert turn["output"] == 20  # 4 assistant completions x 5 output tokens
    assert new_cursor == "b4"


def test_read_transcript_turns_splits_two_exchanges_in_one_delta(tmp_path) -> None:
    """Two full prompt/tool/response exchanges in one delta report as two turns."""
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "first task"),
                _assistant_turn_line("b1", [_tool_use_block("t1")]),
                _tool_result_line("a2", "t1", "result1"),
                _assistant_turn_line(
                    "b2", [{"type": "text", "text": "done with first"}]
                ),
                _user_turn_line("a3", "second task"),
                _assistant_turn_line(
                    "b3", [{"type": "text", "text": "done with second"}]
                ),
            ]
        )
    )

    turns, new_cursor, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    assert len(turns) == 2
    assert turns[0]["prompt_blocks"][0] == {"kind": "text", "text": "first task"}
    assert turns[0]["response_blocks"][-1] == {
        "kind": "text",
        "text": "done with first",
    }
    assert turns[1]["prompt_blocks"] == [{"kind": "text", "text": "second task"}]
    assert turns[1]["response_blocks"] == [{"kind": "text", "text": "done with second"}]


def test_read_transcript_turns_defers_turn_ending_mid_tool_call(tmp_path) -> None:
    """A delta ending right after a tool_use completion doesn't get flushed early.

    Regression test: the Stop hook can fire (and this function can read the
    transcript) before the tool result and follow-up reply for an in-flight
    tool call are appended. The old code treated any assistant completion
    that had closed out `current` (`uuid` set) as a reportable turn, so it
    flushed a headless turn for just the tool_use half, then merged the tool
    result + final reply into a *second*, prompt-less turn on the next call --
    splitting one human exchange into two rows. A turn must only be flushed
    once its last completion's `stop_reason` isn't `tool_use`.
    """
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "run ls"),
                _assistant_turn_line(
                    "b1",
                    [_tool_use_block("t1")],
                    usage={"input_tokens": 100, "output_tokens": 20},
                    stop_reason="tool_use",
                ),
            ]
        )
    )

    turns, new_cursor, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    # Deferred entirely: nothing reported, and the cursor doesn't advance past
    # the tool_use completion, so the next call re-reads the whole exchange.
    assert turns == []
    assert new_cursor is None

    # The rest of the exchange lands in the transcript before the next call.
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "run ls"),
                _assistant_turn_line(
                    "b1",
                    [_tool_use_block("t1")],
                    usage={"input_tokens": 100, "output_tokens": 20},
                    stop_reason="tool_use",
                ),
                _tool_result_line("a2", "t1", "file1\nfile2"),
                _assistant_turn_line(
                    "b2",
                    [{"type": "text", "text": "Found 2 files"}],
                    usage={"input_tokens": 5, "output_tokens": 8},
                    stop_reason="end_turn",
                ),
            ]
        )
    )

    turns2, new_cursor2, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=new_cursor, include_tools=True
    )
    assert len(turns2) == 1
    turn = turns2[0]
    assert turn["prompt_blocks"][0] == {"kind": "text", "text": "run ls"}
    assert turn["response_blocks"] == [
        {"kind": "tool_use", "id": "t1", "name": "bash", "input_json": "{}"},
        {"kind": "text", "text": "Found 2 files"},
    ]
    assert turn["eff_input"] == 105
    assert turn["output"] == 28
    assert new_cursor2 == "b2"


def test_read_transcript_turns_keeps_content_from_all_lines_of_a_split_message(
    tmp_path,
) -> None:
    """A completion split across sibling lines (same message id) keeps every block.

    Regression test: Claude Code logs one model completion as multiple
    transcript lines sharing one `message.id` (e.g. a `thinking` line
    followed by its `tool_use`/`text` sibling), each carrying a full copy of
    that completion's usage. The old code deduped by id with a bare
    `continue`, which correctly avoided double-counting tokens but also
    skipped extracting the sibling line's content entirely -- silently
    dropping whichever block didn't land on the first line. For a
    thinking-then-text final reply, that meant the turn's actual answer text
    (and any non-first tool_use in a multi-tool-use split) never made it into
    `response_blocks`.
    """
    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                _user_turn_line("a1", "run ls"),
                _assistant_turn_line(
                    "b1",
                    [_tool_use_block("t1")],
                    usage={"input_tokens": 100, "output_tokens": 20},
                    stop_reason="tool_use",
                    msg_id="msg1",
                ),
                _tool_result_line("a2", "t1", "file1\nfile2"),
                # The final reply is split: a thinking-only line first, then
                # its text sibling, both sharing "msg2" and identical usage.
                _assistant_turn_line(
                    "b2",
                    [{"type": "thinking", "thinking": ""}],
                    usage={"input_tokens": 5, "output_tokens": 8},
                    stop_reason="end_turn",
                    msg_id="msg2",
                ),
                _assistant_turn_line(
                    "b3",
                    [{"type": "text", "text": "Found 2 files"}],
                    usage={"input_tokens": 5, "output_tokens": 8},
                    stop_reason="end_turn",
                    msg_id="msg2",
                ),
            ]
        )
    )

    turns, new_cursor, _ = read_transcript_turns(
        str(transcript_path), cursor_uuid=None, include_tools=True
    )
    assert len(turns) == 1
    turn = turns[0]
    assert turn["response_blocks"] == [
        {"kind": "tool_use", "id": "t1", "name": "bash", "input_json": "{}"},
        {"kind": "text", "text": "Found 2 files"},
    ]
    # msg2's usage is counted once, not twice, despite two lines.
    assert turn["eff_input"] == 105
    assert turn["output"] == 28
    assert new_cursor == "b3"
