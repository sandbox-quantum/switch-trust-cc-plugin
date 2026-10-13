"""Tests for hooks/ccusage/pii.py: structured PII detection, tokens, and the redaction setting."""

from __future__ import annotations

import json
import os
import random
import sys
import time

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

import ccusage_reporter  # noqa: E402
from ccusage import events, project_settings  # noqa: E402
from ccusage.config import (  # noqa: E402
    PII_REDACTION_DEFAULT,
    PII_REDACTION_LEVELS,
    PII_REDACTION_OFF,
    PII_REDACTION_STRICT,
)
from ccusage.pii import PiiRedactor, luhn_valid  # noqa: E402
from ccusage.redact import redact, sanitize_turn  # noqa: E402

VISA = "4539578763621486"
VISA_2 = "4916338506082832"
AMEX = "371449635398431"
MASTERCARD = "5425233430109903"
VISA_19 = "4111111111111111110"
SSN = "219-09-9998"
IBAN_DE = "DE89370400440532013000"
IBAN_GB_SPACED = "GB82 WEST 1234 5698 7654 32"
LEVEL_VAR = "CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_PII_REDACTION"
PLUGIN_JSON = os.path.join(
    os.path.dirname(__file__), "..", ".claude-plugin", "plugin.json"
)


def _redact(text: str, level: str = PII_REDACTION_DEFAULT) -> str:
    return PiiRedactor(level)(text)


@pytest.mark.parametrize(
    "text",
    [
        f"card {VISA} ok",
        "card 4539 5787 6362 1486 ok",
        "card 4539-5787-6362-1486 ok",
        "amex 3714 496353 98431 ok",
        f"amex {AMEX} ok",
        f"mc {MASTERCARD}",
        f"id,name,card\n1,Test Person,{VISA}\n",
        f"INSERT INTO payments VALUES (7, {VISA}, 'x');",
        f"[{VISA}, {MASTERCARD}]",
        f'{{"pan": {VISA}}}',
        f"Visa card: {VISA_19}",
        f"SSN{SSN}",
    ],
)
def test_card_and_ssn_shapes_are_redacted(text: str) -> None:
    out = _redact(text)
    for value in (VISA, AMEX, MASTERCARD, VISA_19, SSN, "4539 5787", "3714 496353"):
        assert value not in out
    assert "[card-1]" in out or "[ssn-1]" in out


@pytest.mark.parametrize(
    "text",
    [
        VISA[:-1] + str((int(VISA[-1]) + 1) % 10),
        "1234567812345670",
        "sha256:" + "ab12" * 4 + VISA + "cd34" * 8,
        "123e4567-e89b-12d3-a456-426614174000",
        "created 1728400000000 and 1728400000000000000",
        f"ratio 0.{VISA}",
        f"{VISA}.5",
        f"pid {VISA_19} running",
        f"order_id: {VISA}",
        f'"orderId": "{VISA}"',
        "pr numbers 4539 5787 6362 1486 2345",
        "version 4.5.3.9",
    ],
)
def test_card_lookalikes_are_kept(text: str) -> None:
    assert _redact(text) == text


def test_nbsp_grouped_and_non_ascii_digit_cards_are_redacted() -> None:
    nbsp = "4539\u00a05787\u00a06362\u00a01486"
    fullwidth = VISA.translate({ord(d): 0xFF10 + int(d) for d in "0123456789"})
    assert _redact(f"card {nbsp} and {fullwidth}") == "card [card-1] and [card-1]"


def test_well_known_test_cards_are_redacted() -> None:
    for card in ("4111111111111111", "4242424242424242", "378282246310005"):
        assert luhn_valid(card)
        assert _redact(f"stripe test card {card}") == "stripe test card [card-1]"


@pytest.mark.parametrize(
    "text",
    [
        f"SSN {SSN}",
        f"customer {SSN} on file",
        "ssn: 219099998",
        "SSN# 219 09 9998",
        "social security number is 219099998",
        "social_security_number=219099998",
        '{"taxpayer_id": "219099998"}',
        "TIN: 219-09-9998",
        "customerSsn=219099998",
    ],
)
def test_ssn_forms_are_redacted(text: str) -> None:
    out = _redact(text)
    assert "219" not in out and "[ssn-1]" in out


@pytest.mark.parametrize(
    "text",
    [
        "batch 219099998 done",
        "000-12-3456",
        "666-12-3456",
        "912-34-5678",
        "219-00-9998",
        "219-09-0000",
        "part 219-09-9998",
        "P/N: 219-09-9998",
        "sku=219-09-9998",
        "x9f3a2b1c219-09-9998",
        "1-219-09-9998",
        "tin can 219099998",
    ],
)
def test_ssn_lookalikes_are_kept(text: str) -> None:
    assert _redact(text) == text


def test_ibans_are_checksum_validated() -> None:
    assert _redact(f"pay {IBAN_DE} now") == "pay [iban-1] now"
    assert _redact(f"to {IBAN_GB_SPACED}.") == "to [iban-1]."
    bad = IBAN_DE[:2] + "90" + IBAN_DE[4:]
    for text in (bad, IBAN_DE[:-1], "aGVsbG8+" + IBAN_DE + "/d29ybGQ="):
        assert _redact(text) == text


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("passport number X1234567", "passport"),
        ("Passport No. 123456789", "passport"),
        ('"passport_no": "C01X00T47"', "passport"),
        ("driver's license D1234567", "driver_licence"),
        ("Driving licence number SMITH-751-01", "driver_licence"),
        ("DL# F12345678", "driver_licence"),
        ("MRN: 00123456", "mrn"),
        ("medical record number 7654321", "mrn"),
        ("DOB: 1980-03-14", "dob"),
        ("date of birth 03/14/1980", "dob"),
        ("born on 14 March 1980", "dob"),
        ("birthdate=March 14, 1980", "dob"),
        ('"dateOfBirth": "14-Mar-1980"', "dob"),
        ("dob 19800314", "dob"),
    ],
)
def test_keyword_gated_ids_are_redacted(text: str, kind: str) -> None:
    out = _redact(text)
    assert f"[{kind}-1]" in out
    assert not any(c.isdigit() for c in out.replace(f"[{kind}-1]", ""))


@pytest.mark.parametrize(
    "text",
    [
        "X1234567",
        "D1234567 and 00123456",
        "released 1980-03-14",
        "passport photo 1234567",
        "DOB: 2999-01-01",
        "born on 1850-01-01",
        "dob 19801399",
        "driver's license required",
        "the MRN field is 12 chars",
    ],
)
def test_ids_without_their_keyword_are_kept(text: str) -> None:
    assert _redact(text) == text


def test_phones_only_in_strict() -> None:
    text = "call +14155552671 or phone: (415) 555-2671"
    assert _redact(text) == text
    assert _redact(text, PII_REDACTION_STRICT) == "call [phone-1] or phone: [phone-2]"
    kept = "diff +12345 -678, port 4155552671, pid 415-555-2671"
    assert _redact(kept, PII_REDACTION_STRICT) == kept


def test_off_redacts_nothing() -> None:
    text = f"SSN {SSN} card {VISA} {IBAN_DE}"
    assert _redact(text, PII_REDACTION_OFF) == text
    pii = PiiRedactor(PII_REDACTION_OFF)
    assert pii.structured({"ssn": "219099998", "n": int(VISA)}) == {
        "ssn": "219099998",
        "n": int(VISA),
    }


def test_tokens_are_stable_per_value_and_distinct_across_values() -> None:
    pii = PiiRedactor()
    first = pii(
        f"{VISA} {VISA_2} or 4539 5787 6362 1486 and {SSN} {SSN.replace('-', '')}"
    )
    assert first == "[card-1] [card-2] or [card-1] and [ssn-1] 219099998"
    assert pii(f"ssn {SSN} then {VISA_2}") == "ssn [ssn-1] then [card-2]"
    assert PiiRedactor()(VISA_2) == "[card-1]"


def test_structured_tool_input_uses_key_context() -> None:
    pii = PiiRedactor()
    tool_input = {
        "ssn": "219099998",
        "user": {
            "dateOfBirth": "1980-03-14",
            "passport_number": "X1234567",
            "driverLicenseNumber": "D1234567",
            "mrn": 123456,
            "cards": [int(VISA), int(MASTERCARD)],
            "phone": "415 555 2671",
        },
        "order_id": 219099998,
        "flag": True,
    }
    assert pii.structured(tool_input) == {
        "ssn": "[ssn-1]",
        "user": {
            "dateOfBirth": "[dob-1]",
            "passport_number": "[passport-1]",
            "driverLicenseNumber": "[driver_licence-1]",
            "mrn": "[mrn-1]",
            "cards": ["[card-1]", "[card-2]"],
            "phone": "415 555 2671",
        },
        "order_id": 219099998,
        "flag": True,
    }
    assert tool_input["ssn"] == "219099998"
    strict = PiiRedactor(PII_REDACTION_STRICT).structured(
        {"mobile": "+44 20 7946 0958"}
    )
    assert strict == {"mobile": "[phone-1]"}


def test_sanitize_turn_shares_tokens_across_blocks() -> None:
    use = {
        "kind": "tool_use",
        "id": "t1",
        "name": "Bash",
        "input_json": json.dumps(
            {"command": f"grep {VISA} payments.csv", "limit": int(MASTERCARD)}
        ),
    }
    res = {
        "kind": "tool_result",
        "tool_use_id": "t1",
        "text": f"7,{VISA},{SSN}\n8,{MASTERCARD},ok",
        "is_error": False,
    }
    prompt, response = sanitize_turn(
        [{"kind": "text", "text": f"find {VISA}"}, res], [use]
    )
    assert prompt[0]["text"] == "find [card-1]"
    assert prompt[1]["text"] == "7,[card-1],[ssn-1]\n8,[card-2],ok"
    assert json.loads(response[0]["input_json"]) == {
        "command": "grep [card-1] payments.csv",
        "limit": "[card-2]",
    }


def test_sanitize_turn_honours_level() -> None:
    text = f"SSN {SSN}"
    prompt, _ = sanitize_turn(
        [{"kind": "text", "text": text}], [], PiiRedactor(PII_REDACTION_OFF)
    )
    assert prompt[0]["text"] == text


def test_credentials_are_redacted_before_pii() -> None:
    assert redact(f"password={VISA}", PiiRedactor()) == "password=[REDACTED:credential]"


def test_condensed_title_is_pii_redacted() -> None:
    assert events.build_prompt_text(f"refund {VISA}", "hoot", None) == (
        "refund [card-1] (hoot)"
    )
    bucket = {"eff_input": 1, "output": 1, "last_seconds": 1, "last_nanos": 0}
    body = events.build_llm_interaction("s", "m", bucket, "a", f"ssn {SSN}", "r", "")
    assert SSN.encode() not in body and b"[ssn-1]" in body


@pytest.mark.parametrize("seed", [VISA, SSN])
def test_no_metadata_field_carries_seeded_pii(seed: str) -> None:
    repo, branch, title = f"cust-{seed}", f"fix/{seed}", f"Refund {seed}"
    bucket = {"eff_input": 1, "output": 1, "last_seconds": 1, "last_nanos": 0}
    turn = {
        "model": "m",
        "eff_input": 1,
        "output": 1,
        "uuid": "u",
        "seconds": 1,
        "nanos": 0,
        "prompt_blocks": [{"kind": "text", "text": title}],
        "response_blocks": [],
        "stop_reason": "end_turn",
    }
    url = f"https://example.com/{repo}.git"
    bodies = [
        events.build_llm_interaction("s", "m", bucket, "a", title, repo, url, branch),
        events.build_llm_interaction_turn("s", turn, "a", repo, url, 0),
    ]
    for body in bodies:
        event = events.build_interaction_event(body, url)
        assert seed.encode() not in event
        assert b"cust-[" in event


def test_one_mib_scans_within_the_stop_budget() -> None:
    rng = random.Random(3368)
    lines = [
        f"{i},{rng.randrange(10**15, 10**16)},{rng.randrange(10**8, 10**9)},"
        f"{rng.randrange(1000, 9999)}-{rng.randrange(10, 99)}-{rng.randrange(1000, 9999)}"
        for i in range(40_000)
    ]
    text = "\n".join(lines)[: 1024 * 1024]
    start = time.perf_counter()
    for i in range(0, len(text), 64 * 1024):
        PiiRedactor()(text[i : i + 64 * 1024])
    assert time.perf_counter() - start < 3.0


@pytest.fixture
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.delenv(LEVEL_VAR, raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    project_settings._project_env.cache_clear()
    yield
    project_settings._project_env.cache_clear()


def _project_level(tmp_path, monkeypatch, level: str) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps({"env": {LEVEL_VAR: level}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv(LEVEL_VAR, level)


@pytest.mark.usefixtures("_isolated")
@pytest.mark.parametrize(
    ("project", "expected"),
    [
        (PII_REDACTION_OFF, PII_REDACTION_DEFAULT),
        (PII_REDACTION_STRICT, PII_REDACTION_STRICT),
        ("none", PII_REDACTION_DEFAULT),
    ],
)
def test_project_may_only_tighten_pii_redaction(
    tmp_path, monkeypatch, project: str, expected: str
) -> None:
    _project_level(tmp_path, monkeypatch, project)
    assert ccusage_reporter._configured_pii_level() == expected


@pytest.mark.usefixtures("_isolated")
@pytest.mark.parametrize(
    ("saved", "expected"),
    [
        (None, PII_REDACTION_DEFAULT),
        (PII_REDACTION_OFF, PII_REDACTION_OFF),
        (PII_REDACTION_STRICT, PII_REDACTION_STRICT),
        ("bogus", PII_REDACTION_DEFAULT),
    ],
)
def test_user_saved_pii_level(monkeypatch, saved: str | None, expected: str) -> None:
    if saved is not None:
        monkeypatch.setenv(LEVEL_VAR, saved)
    assert ccusage_reporter._configured_pii_level() == expected


def test_plugin_json_declares_the_pii_option() -> None:
    with open(PLUGIN_JSON) as fh:
        option = json.load(fh)["userConfig"]["switch_trust_pii_redaction"]
    assert option["default"] == PII_REDACTION_DEFAULT
    assert sorted(option["options"]) == sorted(PII_REDACTION_LEVELS)
