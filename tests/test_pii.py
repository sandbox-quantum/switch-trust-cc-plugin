"""Tests for hooks/ccusage/pii.py: structured PII detection, tokens, and the redaction setting."""

from __future__ import annotations

import json
import os
import random
import re
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
    text = f"SSN {SSN} card {VISA} {IBAN_DE} jane@corp.io 54.12.88.3 AB123456C"
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
    bucket = {
        "input": 1,
        "output": 1,
        "cache_read": 2,
        "cache_write": 2,
        "last_seconds": 1,
        "last_nanos": 0,
    }
    body = events.build_llm_interaction("s", "m", bucket, "a", f"ssn {SSN}", "r", "")
    assert SSN.encode() not in body and b"[ssn-1]" in body


@pytest.mark.parametrize(
    "seed", [VISA, SSN, "jane.roe@corp.io", "54.12.88.3", "AB123456C", "ABCPE1234F"]
)
def test_no_metadata_field_carries_seeded_pii(seed: str) -> None:
    repo, branch, title = f"cust-{seed}", f"fix/{seed}", f"Refund {seed}"
    bucket = {
        "input": 1,
        "output": 1,
        "cache_read": 2,
        "cache_write": 2,
        "last_seconds": 1,
        "last_nanos": 0,
    }
    turn = {
        "model": "m",
        "input": 1,
        "output": 1,
        "cache_read": 2,
        "cache_write": 2,
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
        assert b"cust-[" in event or b"[email-1]" in event


def test_one_mib_of_emails_and_ips_scans_within_the_stop_budget() -> None:
    rng = random.Random(2522)
    lines = [
        f"{i} Author: Dev {i} <dev{i}@corp{i % 50}.io> from "
        f"{rng.randrange(11, 223)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"
        f" v{rng.randrange(9)}.{rng.randrange(20)}.{rng.randrange(99)} 2a00:1450:4009::{i:x}"
        for i in range(20_000)
    ]
    text = "\n".join(lines)[: 1024 * 1024]
    start = time.perf_counter()
    for i in range(0, len(text), 64 * 1024):
        PiiRedactor()(text[i : i + 64 * 1024])
    assert time.perf_counter() - start < 5.0


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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail jane.roe@corp.io now", "mail [email-1] now"),
        ("JANE+billing@Mail.Corp.co.uk.", "[email-1]."),
        ("<a href='mailto:jane@corp.io'>", "<a href='mailto:[email-1]'>"),
        ('{"email":"jane@corp.io"}', '{"email":"[email-1]"}'),
        ("Author: Jane Roe <jane@corp.io>", "Author: [email-1]"),
        ("Author: jroe-sb <jane@corp.io>", "Author: [email-1]"),
        (
            "    Co-authored-by: Jane Roe <jane@corp.io>",
            "    Co-authored-by: [email-1]",
        ),
        ("Signed-off-by: Jane van Roe <jane@corp.io>", "Signed-off-by: [email-1]"),
        ("    42\tJane Roe <jane@corp.io>", "    42\t[email-1]"),
        (
            '"author": "Jane Roe <jane@corp.io> (https://x.dev)"',
            '"author": "[email-1] (https://x.dev)"',
        ),
        ('From: "Roe, Jane" <jane@corp.io>', "From: [email-1]"),
        ("see the docs <jane@corp.io>", "see the docs [email-1]"),
        ("Author: 123+jroe@users.noreply.github.com", "Author: [email-1]"),
        ('"line\\njane@corp.io"', '"line\\n[email-1]"'),
        ("+jane@corp.io added", "+[email-1] added"),
    ],
)
def test_emails_and_their_display_names_are_redacted(text: str, expected: str) -> None:
    assert _redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "git clone git@github.com:sandbox-quantum/hoot.git",
        "dev@example.com and qa@test.example.org and a@b.test",
        "icon@2x.png logo@3x.webp",
        "@pytest.fixture\n+@mcp.tool\n-@app.route('/x')",
        "lodash@4.17.21 @types/node@18.11.9 react@^18.2.0",
        "image: nginx@sha256:" + "ab" * 32,
        "this@MainActivity.finish() super@Outer.run()",
        "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org",
        "pgxpool@pool.go:683 and user@localhost",
        "x = a @ b.T",
    ],
)
def test_email_lookalikes_are_kept(text: str) -> None:
    assert _redact(text) == text


def test_same_email_shares_a_token_with_its_named_form() -> None:
    pii = PiiRedactor()
    out = pii(
        "Author: Jane Roe <Jane@Corp.io>\n\n    fix\n\ncc jane@corp.io, bob@corp.io"
    )
    assert out == "Author: [email-1]\n\n    fix\n\ncc [email-1], [email-2]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("from 54.12.88.3 port 22", "from [ip-1] port 22"),
        ("curl http://54.12.88.3:8080/x", "curl http://[ip-1]:8080/x"),
        ('"sourceIPAddress": "13.41.85.156",', '"sourceIPAddress": "[ip-1]",'),
        ("ssh ubuntu@54.12.88.3", "ssh ubuntu@[ip-1]"),
        ("dst 2a00:1450:4009:81f::200e", "dst [ip-1]"),
        ("[2A00:1450:4009:081F:0000:0000:0000:200E]:443", "[[ip-1]]:443"),
        ("peer ::ffff:54.12.88.3 ok", "peer [ip-1] ok"),
        ("addr fe80::21a:2bff:fe3c:4d5e%en0", "addr [ip-1]%en0"),
        ("host 54.12.88.3/32", "host [ip-1]/32"),
        ("ip 1.20.30.40", "ip [ip-1]"),
    ],
)
def test_public_ips_are_redacted(text: str, expected: str) -> None:
    assert _redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "listen 127.0.0.1:8080 and 0.0.0.0 and [::1]:443 and ::",
        "metadata 169.254.169.254 fd00:ec2::254 168.63.129.16 and fe80::1%lo0",
        "docs 192.0.2.10 198.51.100.7 203.0.113.99 2001:db8::42 3fff::1",
        "dns 8.8.8.8 1.1.1.1 9.9.9.9 2606:4700:4700::1111",
        "netmask 255.255.255.0 multicast 224.0.0.251 bcast 255.255.255.255",
        "allow 130.211.0.0/22 and 35.191.0.0/16 and 2a00:1450::/32",
        "version 54.12.88.3, Version: 10.0.19041.1, build 23.4.5.67",
        "numpy==1.26.4 grpcio>=1.62.1.2 semver 1.2.3 v1.2.3.4",
        "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
        '"2.5.29.14" -> "subjectKeyIdentifier" 1.3.6.1.4.1.311.20.2 1.3.101.112',
        "pkginfo-1.12.1.2.tar.gz and lib.so.1.2.3.4",
        '{"v8":"9.6.180.15"} see section 13.3.3.7',
        "at 12:34:56 on 2026-10-13T20:15:30Z mac 2c:54:91:88:c9:e3",
        "id 123e4567-e89b-12d3-a456-426614174000 sha deadbeefcafe",
        "std::vector<int> v; Foo::Bar::baz(); a::b",
        "phone 415.555.2671 and 1.555.123.4567",
    ],
)
def test_ip_lookalikes_and_non_personal_ranges_are_kept(text: str) -> None:
    assert _redact(text) == text


def test_private_ips_are_redacted_by_default() -> None:
    text = (
        "pod 10.244.1.17 node 192.168.1.20 svc 172.20.0.10 cgnat 100.64.3.4 "
        "ula fd12:3456:789a::1 apipa 169.254.7.8 lo 127.0.0.1"
    )
    expected = (
        "pod [ip-1] node [ip-2] svc [ip-3] cgnat [ip-4] "
        "ula [ip-5] apipa [ip-6] lo 127.0.0.1"
    )
    assert _redact(text) == expected
    assert _redact(text, PII_REDACTION_STRICT) == expected


@pytest.mark.parametrize(
    "prefix",
    [
        "server ",
        "nameserver ",
        "Server:\t\t",
        "resolver ",
        "prev ",
        "android ",
        "avoid ",
    ],
)
def test_words_ending_in_a_version_cue_do_not_hide_ips(prefix: str) -> None:
    assert _redact(f"{prefix}81.2.69.142 up") == f"{prefix}[ip-1] up"


def test_k8s_manifest_keeps_ranges_and_loopback() -> None:
    manifest = (
        "spec:\n  clusterIP: 10.96.0.10\n  podCIDR: 10.244.0.0/16\n"
        "  loadBalancerIP: 34.135.255.90\n  ports:\n  - port: 53\n"
        "livenessProbe:\n  httpGet:\n    host: 127.0.0.1\n"
    )
    expected = manifest.replace("10.96.0.10", "[ip-1]").replace(
        "34.135.255.90", "[ip-2]"
    )
    assert _redact(manifest) == expected


AADHAAR = "2341 2341 2346"
AADHAAR_COMPACT = AADHAAR.replace(" ", "")
NATIONAL_IDS = [
    ("nino", "AB123456C", "JG 10 37 59 A"),
    ("in_pan", "ABCPE1234F", "BMNTS4321K"),
    ("dni", "12345678Z", "X1234567L"),
    ("codice_fiscale", "RSSMRA85T10A562S", "MRTMTT25D09F205Z"),
    ("nir", "1 84 12 76 451 089 46", "2 55 08 14 168 025 38"),
    ("aadhaar", AADHAAR, "8233 4734 7957"),
    ("be_nn", "85.07.30-033.28", "17.07.30-033.84"),
]
KEYWORD_IDS = [
    ("sin", "SIN", "130 692 544", "130692544"),
    ("bsn", "BSN", "111222333", "1112.22.333"),
    ("pesel", "PESEL", "44051401359", "02070803628"),
    ("aadhaar", "Aadhaar no.", AADHAAR_COMPACT, AADHAAR.replace(" ", "-")),
    ("nir", "numéro de sécu", "184127645108946", "2550814168025 38"),
    ("be_nn", "rijksregisternummer", "85073003328", "85.07.30-033.28"),
]


@pytest.mark.parametrize(("kind", "first", "second"), NATIONAL_IDS)
def test_checksum_shaped_national_ids_are_redacted_bare(
    kind: str, first: str, second: str
) -> None:
    text = f"id {first}, other: {second}; again ({first})"
    assert _redact(text) == f"id [{kind}-1], other: [{kind}-2]; again ([{kind}-1])"


@pytest.mark.parametrize(("kind", "label", "first", "second"), KEYWORD_IDS)
def test_collision_prone_national_ids_need_a_label(
    kind: str, label: str, first: str, second: str
) -> None:
    assert _redact(f"{label}: {first}") == f"{label}: [{kind}-1]"
    assert _redact(f"{label} {second}") == f"{label} [{kind}-1]"
    bare = f"total {first.replace(' ', '')} rows"
    assert _redact(bare) == bare


@pytest.mark.parametrize(
    "text",
    [
        "AB123456E BG123456A GB123456A NK123456A DA123456A AO123456A",
        "ABCDE1234F ABCXE1234F abcpe1234f XABCPE1234F",
        "12345678A X1234567A 123456789Z",
        "RSSMRA85T10A562X RSSMRA85T10A562",
        "1 84 12 76 451 089 47 and 5 84 12 76 451 089 46",
        "1234 5678 9012 and 0123 4567 8901 and 2341 2341 2347",
        "85.07.30-033.29 and 85.13.30-033.28",
        "SIN 130 692 545 and SIN 830 692 540 and BSN 111222334",
        "PESEL 44051401358 and PESEL 44133101359",
        "sin(130692544) cos(x)",
        "order AB123456C, part ABCPE1234F, sku 12345678Z",
    ],
)
def test_national_id_lookalikes_are_kept(text: str) -> None:
    assert _redact(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "commit 1a943a05f0e1c2d3b4a5968778695a4b3c2d1e0f\nAuthor: [email-1]\n"
        "Date:   Tue Oct 13 08:53:00 2026 +0100\n\n    fix(sdk/py): bump pins (#2576)\n",
        "requests==2.32.3\nurllib3==2.2.3\ncryptography==43.0.1\nprotobuf==5.28.2.1\n",
        "├── react@18.3.1\n├─┬ @babel/core@7.25.2\n│ └── semver@6.3.1\n",
        "2026-10-13 2026-10-13T08:53:00.123456789Z 1728400000 1728400000123",
        "+44 20 7946 0958 (415) 555-2671 +91 98765 43210",
        "aGVsbG8gd29ybGQgQUIxMjM0NTZDIEFCQ1BFMTIzNEY=",
        "sha256:4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
        "uuid 0f8fad5b-d9cb-469f-a165-70867728950e k8s.gcr.io/pause:3.9",
        f"SELECT * FROM orders WHERE id IN ({AADHAAR_COMPACT}, 111222333, 44051401359);",
    ],
)
def test_developer_text_is_kept(text: str) -> None:
    assert _redact(text) == text


def test_random_digit_runs_are_not_national_ids() -> None:
    rng = random.Random(3371)
    for width in (9, 11, 12, 15):
        run = " ".join(
            str(rng.randrange(10 ** (width - 1), 10**width)) for _ in range(2000)
        )
        tokens = set(re.findall(r"\[([a-z_]+)-\d+\]", _redact(run)))
        assert tokens <= {"card"}


def test_structured_national_id_keys() -> None:
    out = PiiRedactor().structured(
        {
            "nino": "ab 12 34 56 c",
            "aadhaar_number": int(AADHAAR_COMPACT),
            "pan": "ABCPE1234F",
            "nationalId": "111222333",
            "sin": "not-a-sin",
            "bsn": "111222334",
        }
    )
    assert out == {
        "nino": "[nino-1]",
        "aadhaar_number": "[aadhaar-1]",
        "pan": "[in_pan-1]",
        "nationalId": "[bsn-1]",
        "sin": "not-a-sin",
        "bsn": "111222334",
    }


def test_versions_in_paths_and_filenames_are_kept() -> None:
    text = (
        "releases/download/5.36.0.1/perl.tar.xz strawberry-perl-5.32.1.1-64bit.msi "
        "modules/rules_robolectric/4.14.1.2/MODULE.bazel"
    )
    assert _redact(text) == text
    assert _redact("branch fix/54.12.88.3") == "branch fix/[ip-1]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("?u=jane.doe%40acme-corp.io&x=1", "?u=[email-1]&x=1"),
        ("juan.perez@empresa.com.py", "[email-1]"),
        ("j\u00f6hn.smith@acme.de", "[email-1]"),
        ("user@xn--e1afmkfd.xn--p1ai", "[email-1]"),
    ],
)
def test_encoded_unicode_and_file_like_tld_emails(text: str, expected: str) -> None:
    assert _redact(text) == expected


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("AB 12 34 56 C", "nino"),
        ("AB-12-34-56-C", "nino"),
        ("AB 123456 C", "nino"),
        ("nino: ab123456c", "nino"),
        ("NI number ab 12 34 56 c", "nino"),
        ("PAN abcpe1234f", "in_pan"),
        ("DNI 12345678z", "dni"),
        ("NIE: x1234567l", "dni"),
        ("Aadhaar 2341-2341-2346", "aadhaar"),
    ],
)
def test_national_id_variants_are_redacted(text: str, kind: str) -> None:
    out = _redact(f"id {text} ok")
    assert f"[{kind}-1]" in out
    assert not any(c.isdigit() for c in out.replace(f"[{kind}-1]", ""))


def test_lowercase_and_dashed_forms_need_a_label() -> None:
    text = (
        "index be898453d..14316554c 100644 ab123456c abcpe1234f 12345678z "
        "account 4400-2299-1187"
    )
    assert _redact(text) == text
