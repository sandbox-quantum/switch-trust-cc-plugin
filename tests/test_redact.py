"""Tests for hooks/ccusage/redact.py: secret patterns, sensitive paths, size caps."""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage import events  # noqa: E402
from ccusage.redact import (  # noqa: E402
    BLOCK_CAP_BYTES,
    EVENT_CAP_BYTES,
    TEXT_BLOCK_CAP_BYTES,
    guard_shell_blocks,
    is_sensitive_path,
    redact,
    redact_capped,
    sanitize_turn,
    truncate_utf8,
)
from ccusage.transcript import read_transcript_turns  # noqa: E402

F = "FAKE"
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + F * 12 + "\n" + F * 8 + "==\n"
    "-----END RSA PRIVATE KEY-----"
)

PGP = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: x\n\nlQOYBF"
    + F * 12
    + "\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----"
)
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + F + "FAKEKY"

CASES = [
    ("aws_access_key_id", "AK" + "IA" + F * 3 + "1234", "key {} ok"),
    ("aws_access_key_id", "AS" + "IA" + F * 3 + "5678", "key {} ok"),
    ("aws_credential", F.lower() * 9 + "/k+0", "AWS_SECRET_ACCESS_KEY={} ok"),
    ("aws_credential", F * 9 + "/k+0", '{{"aws_secret_access_key": "{}"}} ok'),
    ("github_token", "gh" + "p_" + F * 9, "token is {} ok"),
    ("github_token", "gh" + "o_" + F * 9, "token is {} ok"),
    ("github_token", "gh" + "s_" + F * 9, "token is {} ok"),
    ("github_token", "gh" + "u_" + F * 9, "token is {} ok"),
    ("github_token", "gh" + "r_" + F * 9, "token is {} ok"),
    ("github_token", "github" + "_pat_11" + F * 6 + "_" + F * 10, "pat {} ok"),
    ("slack_token", "xo" + "xb-0000000000-" + F * 6, "slack {} ok"),
    ("google_api_key", "AI" + "za" + F * 8 + "_FA", "google {} ok"),
    ("anthropic_key", "sk-" + "ant-api03-" + F * 10, "key {} ok"),
    ("openai_key", "sk-" + "proj-" + F * 10, "key {} ok"),
    ("openai_key", "sk-" + F * 12, "key {} ok"),
    ("switch_key", "sk_" + "live_" + F * 7 + "01", "SWITCH_TRUST_API_KEY={} ok"),
    ("switch_key", "sk_" + F * 7 + "01", "key {} ok"),
    ("switch_key", "sk_" + "example_1234567890abcdef", "key {} ok"),
    ("switch_key", "sk_" + "test_a2V5XzAxABCD_EFGH-ijkl_tail9", "key {} ok"),
    ("switch_key", "sk_" + "A1b2C3d4E5f6G7h8I9j0K1l2-yz12", "key {} ok"),
    ("switch_key", "sk_" + "live_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf", "key {} ok"),
    ("credential", "pgvalue", '{{"POSTGRES_PASSWORD": "{}"}} ok'),
    ("credential", "Zebravalue", "{{'API_TOKEN': '{}'}} ok"),
    ("credential", "shhhh", 'SECRET_TOKEN = "{}" ok'),
    ("credential", "hunter", 'password: "{}" ok'),
    ("credential", "postgres", '{{"db_password": "{}"}} ok'),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0." + F * 4, "jwt {} ok"),
    ("authorization", F + "bearer0123456789", "Authorization: Bearer {} ok"),
    ("authorization", "ZmFrZTpmYWtlZmFrZQ==", "authorization: Basic {} ok"),
    ("authorization", F + "apikey0123456789", "Authorization: ApiKey {} ok"),
    ("credential", "Hunter2!" + F, "password={} ok"),
    ("credential", F + "Secret01", "DB_SECRET = {} ok"),
    ("credential", F + "Api01", 'curl -d "api_key={}" ok'),
    ("credential", F + "Token01", '{{"token": "{}"}} ok'),
    ("credential", F + "Yaml01", "password: {}\nok"),
    ("private_key", PEM, "before\n{}\nafter ok"),
    ("private_key", PGP, "before\n{}\nafter ok"),
    ("aws_credential", AWS_SECRET, '{{"SecretAccessKey": "{}"}} ok'),
    ("aws_credential", "IQoJb3JpZ2lu" + F * 70, '{{"SessionToken": "{}"}} ok'),
    ("aws_credential", AWS_SECRET, "aws_secret_access_key: {}\nok"),
    ("credential", "IQoJ" + "A1b/" * 100 + "TAIL", "MY_SERVICE_TOKEN={} ok"),
    ("credential", "p@ss$w0rd,x;y&z%2F", "PASSWORD={} ok"),
    ("credential", "correcthorsebatterystaple", "DB_PASSWORD={} ok"),
    ("credential", "correcthorsebatterystaple", "export GH_TOKEN={} ok"),
    ("credential", "correcthorsebatterystaple", "DB_PASSWORD: {}\nok"),
    ("credential", "IQo%2FAAfake%2Bfake", "s3?X-Amz-Security-Token={} ok"),
    ("credential", F + "Camel01", '{{"accessToken": "{}"}} ok'),
    ("slack_token", "xa" + "pp-1-A01" + F * 4 + "-1234567890123-" + "f" * 64, "{} ok"),
    ("slack_webhook", "T0000/B0000/" + F * 6, "https://hooks.slack.com/services/{} ok"),
    ("url_credentials", "Pg5" + F + "pass99", "postgres://app:{}@db:5432/app ok"),
    (
        "url_credentials",
        "gh" + F + "notaprefix",
        "git clone https://u:{}@github.com/o ok",
    ),
    ("basic_auth_flag", "S3cr3t" + F, "curl -u admin:{} https://x ok"),
    ("credential", "LEAKPGPASSpw", "PGPASSWORD={} psql ok"),
    ("credential", "LEAKMYSQLpw", "MYSQL_PWD={} mysql ok"),
    ("credential", "LEAKNPMRClegacy99", "//npm.corp/:_auth={}\nok"),
    ("credential", "Ym9iOkxFQUtET0NLRVJwdw==", '{{"auth": "{}"}} ok'),
    ("npm_token", "npm_" + F * 9, "//registry.npmjs.org/:_authToken={} ok"),
    ("password_hash", "$apr1$" + F + "salt$" + F * 4, "bob:{}\nok"),
    ("credential", "hunter2xyz", "password = {} ok"),
]


@pytest.mark.parametrize(("kind", "secret", "template"), CASES)
def test_pattern_redacts_only_the_secret(kind: str, secret: str, template: str) -> None:
    out = redact(template.format(secret))
    assert secret not in out
    assert f"[REDACTED:{kind}]" in out
    assert out.rstrip().endswith("ok")


@pytest.mark.parametrize(
    "text",
    [
        "STOP_MIN_TOKENS = 20000",
        'usage(input_tokens=1000, "cache_read_input_tokens": 1000)',
        "def f(token: str) -> None: token = get_token()",
        "password = Optional[str]",
        'OPTION_SWITCH_TRUST_API_KEY = "switch_trust_api_key"',
        "risk_assessment_framework_identifier and pip install sk-learn",
        'export TOKEN="$GITHUB_TOKEN"',
        "id_rsa.pub is public",
        'if line.startswith("-----BEGIN RSA PRIVATE KEY-----"):\n    return True',
        "token = self.token; password = get_password(user)",
        "_CHARS_PER_TOKEN = 4.0; MAX_TOKENS=4096",
        "new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY })",
        "AISPM_DB_PASSWORD=... bazel run //x",
        "the `password=`-style rule",
        "def load_cert_chain(self, certfile, keyfile=None, password=None):",
        "def read(self, name, pwd=None):",
        "password = base64.b16encode(random_bytes[8:])",
        "token = s3_client.get(x); secret = sha256(data).hexdigest()",
        "token = utf8_decode(b); token=tok, password=pw)",
        "token: string | undefined; refreshToken: null; secret: true",
        "PWD=/home/bob/p OLDPWD=/tmp",
        "INFO token: refreshed for user=bob",
        "it('rejects bad token: returns 401')",
        '  "forgotPassword": "Forgot your password?",',
        '  "invalidToken": "Invalid-token",',
        "nextPageToken: abc",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-AbC123",
        "use a bearer credential on the request",
        "const UNDEFINED_TOKEN = /*@__PURE__*/ require('./x')",
        "SOCKET_CLI_API_TOKEN: envAsString(env['SOCKET_CLI_API_TOKEN']) ||",
        "const auth = !er.headers['x']; token = !!githubToken",
        'url = "postgres://%s:%s@%s/db" % (u, p, h)',
        "next_page_token=CAESabc123def456 continuation_token: Zx9-abc_123",
        "x = sk_learn_model_v2; task_queue_name_2024 = 1",
        '{"token_type": "bearer", "auth": "oauth", "secret": "none"}',
        'password = "xxx"; {"password": "your_password_here"}',
        'SECRET_TOKEN = "<redacted>"',
    ],
)
def test_code_and_prose_are_not_redacted(text: str) -> None:
    assert redact(text) == text


def test_json_escaped_tool_input_is_redacted_and_stays_valid_json() -> None:
    raw = json.dumps({"command": f"echo {PEM}\nexport password='Hunter2!xyz'"})
    out = redact(raw)
    assert "MIIE" not in out
    assert "Hunter2" not in out
    assert json.loads(out)["command"].startswith("echo [REDACTED:private_key]")


def test_unterminated_pem_redacts_its_base64_run() -> None:
    out = redact("keep\n-----BEGIN PRIVATE KEY-----\nMIIE" + F * 50)
    assert out == "keep\n[REDACTED:private_key]"


@pytest.mark.parametrize(
    ("path", "sensitive"),
    [
        ("/repo/.env", True),
        ("/repo/.env.local", True),
        ("/repo/.env.example", False),
        ("/repo/certs/server.pem", True),
        ("/home/u/.ssh/id_ed25519", True),
        ("/home/u/.ssh/id_rsa.pub", False),
        ("/home/u/.netrc", True),
        ("/home/u/.aws/credentials", True),
        ("/repo/src/credentials", False),
        ("/repo/src/id_utils.py", False),
        ("/repo/.envrc", True),
        ("~/.npmrc", True),
        ("/home/u/.docker/config.json", True),
        ("/home/u/.git-credentials", True),
        ("/home/u/.kube/config", True),
        ("/home/u/.pgpass", True),
        ("/srv/.htpasswd", True),
        ("/repo/config.json", False),
        (".env*", True),
        ("**/*.pem", True),
    ],
)
def test_is_sensitive_path(path: str, sensitive: bool) -> None:
    assert is_sensitive_path(path) is sensitive


def _tool_pair(tool_id: str, name: str, tool_input: dict, result: str):
    use = {
        "kind": "tool_use",
        "id": tool_id,
        "name": name,
        "input_json": json.dumps(tool_input),
    }
    res = {
        "kind": "tool_result",
        "tool_use_id": tool_id,
        "text": result,
        "is_error": False,
    }
    return use, res


def test_sensitive_path_tool_results_get_a_placeholder() -> None:
    read_env = _tool_pair("t1", "Read", {"file_path": "/r/.env"}, "PLAIN=visible")
    cat_key = _tool_pair("t2", "Bash", {"command": "cat ~/.ssh/id_rsa"}, "KEYDATA")
    normal = _tool_pair("t3", "Read", {"file_path": "/r/main.py"}, "print('hi')")
    prompt, response = sanitize_turn(
        [read_env[1], cat_key[1], normal[1]], [read_env[0], cat_key[0], normal[0]]
    )
    assert [b["text"] for b in prompt] == [
        "[REDACTED:sensitive_file]",
        "[REDACTED:sensitive_file]",
        "print('hi')",
    ]
    assert response[0]["input_json"] == read_env[0]["input_json"]


def test_truncate_utf8_never_splits_a_character() -> None:
    text = "é日🙂x" * 5000
    out = truncate_utf8(text, 1001)
    encoded = out.encode("utf-8")
    assert len(encoded) <= 1001
    assert "[TRUNCATED:" in out
    assert text.startswith(out.split("\n[TRUNCATED:")[0])


def test_truncate_utf8_replaces_lone_surrogates() -> None:
    assert truncate_utf8("a\ud83db", 100) == "a?b"


def test_redaction_runs_before_truncation() -> None:
    secret = "AK" + "IA" + F * 3 + "1234"
    text = "x" * (TEXT_BLOCK_CAP_BYTES - 120) + secret + "y" * 1000
    prompt, _ = sanitize_turn([{"kind": "text", "text": text}], [])
    assert "AKIA" not in prompt[0]["text"]
    assert "[TRUNCATED:" in prompt[0]["text"]


def test_event_stays_under_cap_with_many_large_tool_results() -> None:
    uses, results = [], []
    for i in range(300):
        use, res = _tool_pair(
            f"t{i}", "Read", {"file_path": f"/r/{i}.log"}, "zz " * 33_000
        )
        uses.append(use)
        results.append(res)
    turn = {
        "model": "claude-opus-4-8",
        "eff_input": 1,
        "output": 1,
        "uuid": "u1",
        "seconds": 1700000000,
        "nanos": 0,
        "prompt_blocks": [{"kind": "text", "text": "prompt kept"}, *results],
        "response_blocks": [{"kind": "text", "text": "reply kept"}, *uses],
        "stop_reason": "end_turn",
    }
    interaction = events.build_llm_interaction_turn("s", turn, "a", "r", "", 0)
    event = events.build_interaction_event(interaction, "")
    assert len(event) <= EVENT_CAP_BYTES
    assert b"prompt kept" in event and b"reply kept" in event
    assert b"blocks omitted, event size cap]" in event


def test_redact_is_linear_on_adversarial_input() -> None:
    for text in ("token=" * 40_000, "eyJ" * 80_000, "sk_" + "a" * 240_000):
        start = time.perf_counter()
        redact(text)
        assert time.perf_counter() - start < 2.0


def test_pem_in_escaped_json_and_header_lines_stop_at_the_key() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + F * 8
    single = (
        '"-----BEGIN PRIVATE KEY-----\\n' + body + '\\n-----END PRIVATE KEY-----\\n"'
    )
    double = single.replace("\\n", "\\\\n")
    encrypted = (
        "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES,F\n\n"
        + body
        + "\n-----END EC PRIVATE KEY-----"
    )
    for text in (single, double, encrypted):
        assert body not in redact(text)
    ij = json.dumps(
        {
            "command": f"printf '-----BEGIN PRIVATE KEY-----\n{body}\nNote: x' > k",
            "description": "keep me",
        }
    )
    _, response = sanitize_turn(
        [], [{"kind": "tool_use", "id": "t", "name": "Bash", "input_json": ij}]
    )
    decoded = json.loads(response[0]["input_json"])
    assert body not in decoded["command"]
    assert decoded["description"] == "keep me"


def test_tool_input_stays_valid_json_when_redacted_and_truncated() -> None:
    use = {
        "kind": "tool_use",
        "id": "w",
        "name": "Write",
        "input_json": json.dumps(
            {
                "file_path": "/r/big.py",
                "content": "password='Hunter2!x'\n" + "é" * 200_000,
            }
        ),
    }
    _, response = sanitize_turn([], [use])
    out = response[0]["input_json"]
    assert len(out.encode("utf-8")) <= BLOCK_CAP_BYTES
    decoded = json.loads(out)
    assert decoded["file_path"] == "/r/big.py"
    assert "Hunter2" not in decoded["content"]
    assert "[TRUNCATED:" in decoded["content"]


def test_sensitive_writes_greps_and_envrc_reads_are_placeheld() -> None:
    write = _tool_pair(
        "w", "Write", {"file_path": "/r/.env", "content": "A=leak1"}, "ok"
    )
    edit = _tool_pair(
        "e",
        "MultiEdit",
        {
            "file_path": "/r/k.pem",
            "edits": [{"old_string": "x", "new_string": "leak2"}],
        },
        "ok",
    )
    grep = _tool_pair(
        "g", "Grep", {"pattern": "PASS", "glob": ".env*"}, ".env:1:X=leak3"
    )
    envrc = _tool_pair("r", "Read", {"file_path": "/r/.envrc"}, "export X=leak4")
    prompt, response = sanitize_turn(
        [write[1], edit[1], grep[1], envrc[1]], [write[0], edit[0], grep[0], envrc[0]]
    )
    sent = json.dumps([prompt, response])
    for leak in ("leak1", "leak2", "leak3", "leak4"):
        assert leak not in sent
    assert (
        json.loads(response[0]["input_json"])["content"] == "[REDACTED:sensitive_file]"
    )
    assert json.loads(response[1]["input_json"])["file_path"] == "/r/k.pem"


def test_shell_mode_output_of_sensitive_command_is_placeheld(tmp_path) -> None:
    entries = [
        {
            "type": "user",
            "uuid": "u1",
            "message": {"role": "user", "content": "<bash-input>cat .env</bash-input>"},
        },
        {
            "type": "user",
            "uuid": "u2",
            "message": {
                "role": "user",
                "content": "<bash-stdout>X=leak5</bash-stdout>",
            },
        },
        {
            "type": "user",
            "uuid": "u3",
            "message": {"role": "user", "content": "<bash-input>ls</bash-input>"},
        },
        {
            "type": "user",
            "uuid": "u4",
            "message": {
                "role": "user",
                "content": "<bash-stdout>README.md</bash-stdout>",
            },
        },
        {
            "type": "assistant",
            "uuid": "a1",
            "message": {
                "id": "m1",
                "model": "m",
                "usage": {"input_tokens": 1},
                "content": "hi",
            },
        },
    ]
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries))
    blocks, pending = guard_shell_blocks(
        [{"type": "text", "text": "<bash-input>cat ~/.aws/credentials</bash-input>"}],
        False,
    )
    assert pending
    turns, _, _ = read_transcript_turns(str(path), None, include_tools=True)
    sent = json.dumps(turns)
    assert "leak5" not in sent
    assert "README.md" in sent


def test_secret_straddling_the_scan_window_is_not_exposed() -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        + "A" * (2 * BLOCK_CAP_BYTES - 40)
        + "\n-----END PRIVATE KEY-----"
    )
    text = pem + " AK" + "IA" + F * 3 + "1234 tail" + "zz " * 33_000
    out = redact_capped(text, BLOCK_CAP_BYTES)
    assert "AKIA" not in out and "[REDACTED:private_key]" in out
    assert "[TRUNCATED:" in out


def _input(tool_input) -> str:
    use = {
        "kind": "tool_use",
        "id": "t",
        "name": "mcp__x",
        "input_json": json.dumps(tool_input),
    }
    _, response = sanitize_turn([], [use])
    return response[0]["input_json"]


def test_json_keys_name_credentials_and_key_names_are_redacted() -> None:
    out = json.loads(
        _input(
            {
                "password": "hunter",
                "env": {"API_TOKEN": "letters", "PWD": "/srv"},
                "apiKey": "x1",
                "passwords": ["a", "b"],
                "max_tokens": "4096",
                "tokenCount": "12",
                "secret": "true",
                "gh" + "p_" + F * 9: "v",
            }
        )
    )
    assert out["password"] == out["apiKey"] == "[REDACTED:credential]"
    assert out["env"] == {"API_TOKEN": "[REDACTED:credential]", "PWD": "/srv"}
    assert out["passwords"] == ["[REDACTED:credential]"] * 2
    assert (out["max_tokens"], out["tokenCount"], out["secret"]) == (
        "4096",
        "12",
        "true",
    )
    assert "[REDACTED:github_token]" in out


def test_deep_or_failing_input_never_raises(monkeypatch) -> None:
    deep = "[" * 5000 + '"x"' + "]" * 5000
    use = {"kind": "tool_use", "id": "t", "name": "x", "input_json": deep}
    sanitize_turn([], [use])
    nested: object = "x"
    for _ in range(600):
        nested = [nested]
    json.loads(_input(nested))

    def boom(*_args):
        raise RuntimeError("boom")

    monkeypatch.setattr("ccusage.redact.redact_capped", boom)
    prompt, response = sanitize_turn([{"kind": "text", "text": "hi"}], [use])
    assert prompt[0]["text"] == "[REDACTED:unprocessable]"
    assert json.loads(response[0]["input_json"]) == "[REDACTED:unprocessable]"


def test_oversized_input_json_becomes_a_valid_placeholder_quickly() -> None:
    start = time.perf_counter()
    out = _input({"l": ["abcdefgh"] * 300_000, **{f"k{i}": 1 for i in range(50_000)}})
    assert time.perf_counter() - start < 3.0
    assert json.loads(out).startswith("[TRUNCATED: input_json over")


def test_no_token_fragment_survives_a_cut_without_boundary() -> None:
    token = "gh" + "p_" + F * 9
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0." + "Q" * 20000
    cut = 2 * BLOCK_CAP_BYTES - 8192
    text = jwt + " " + "a=1&" * ((cut - 21 - len(jwt)) // 4)
    text = text + "x" * (cut - 20 - len(text)) + token + "&b=2" * 3000
    out = redact_capped(text, BLOCK_CAP_BYTES)
    assert "ghp_" not in out and "[TRUNCATED:" in out
    assert redact_capped("A" * 9000, 3000).startswith("\n[TRUNCATED:")


def test_yaml_list_under_credential_key_is_redacted() -> None:
    out = redact(
        "users:\n  passwords:\n    - LEAKa1xyz9\n    - LEAK-b2-q\n  name: bob\n- other"
    )
    assert "LEAK" not in out and "name: bob" in out and "- other" in out
    names = (
        "imagePullSecrets:\n  - name: regcred\nsecrets:\n- name: datadog-api-key\n"
        "Tokens:\n- refresh tokens rotate daily\n- datadog-api-key"
    )
    assert redact(names) == names


def test_shell_guard_same_block_reset_and_env_dumps() -> None:
    same = [
        {
            "type": "text",
            "text": "<bash-input>cat .pgpass</bash-input><bash-stdout>leak</bash-stdout>",
        }
    ]
    out, pending = guard_shell_blocks(same, False)
    assert "leak" not in out[0]["text"] and not pending
    _, pending = guard_shell_blocks(
        [{"type": "text", "text": "<bash-input>printenv</bash-input>"}], False
    )
    unrelated, pending = guard_shell_blocks(
        [{"type": "text", "text": "hello"}], pending
    )
    assert not pending and unrelated[0]["text"] == "hello"
    later, _ = guard_shell_blocks(
        [{"type": "text", "text": "<bash-stdout>keep</bash-stdout>"}], pending
    )
    assert "keep" in later[0]["text"]
    env_dump = _tool_pair("b", "Bash", {"command": "env | sort"}, "X=leak6")
    prompt, _ = sanitize_turn([env_dump[1]], [env_dump[0]])
    assert prompt[0]["text"] == "[REDACTED:sensitive_file]"


def test_big_string_is_shrunk_but_structure_and_short_fields_survive() -> None:
    tool_input = {
        "file_path": "/r/a.py",
        "edits": [
            {"old_string": "q " * 18_000, "new_string": "short"},
            {"old_string": "x", "new_string": "y"},
        ],
    }
    out = json.loads(_input(tool_input))
    assert out["file_path"] == "/r/a.py"
    assert out["edits"][1] == {"old_string": "x", "new_string": "y"}
    assert out["edits"][0]["new_string"] == "short"
    assert "[TRUNCATED:" in out["edits"][0]["old_string"]
    assert json.loads(_input({"l": ["abcdefgh"] * 300_000})).startswith("[TRUNCATED:")


def test_colliding_redacted_keys_are_disambiguated() -> None:
    a, b = "gh" + "p_" + "A" * 36, "gh" + "p_" + "B" * 36
    out = json.loads(_input({a: 1, b: 2}))
    assert out == {"[REDACTED:github_token]": 1, "[REDACTED:github_token]#2": 2}


def test_pagination_keys_are_not_credentials() -> None:
    out = json.loads(
        _input(
            {
                "page_token": "CAESx1",
                "nextPageToken": "abc9",
                "cursor_token": "z1",
                "token": "t1x",
            }
        )
    )
    assert (out["page_token"], out["nextPageToken"], out["cursor_token"]) == (
        "CAESx1",
        "abc9",
        "z1",
    )
    assert out["token"] == "[REDACTED:credential]"


def test_nul_is_replaced_in_every_text_field() -> None:
    use = {
        "kind": "tool_use",
        "id": "t\x00",
        "name": "Bash\x00",
        "input_json": json.dumps({"command": "printf 'a\x00b'"}),
    }
    res = {
        "kind": "tool_result",
        "tool_use_id": "t\x00",
        "text": "bin\x00ary",
        "is_error": False,
    }
    prompt, response = sanitize_turn([{"kind": "text", "text": "hi\x00"}, res], [use])
    for block in prompt + response:
        for value in block.values():
            if isinstance(value, str):
                assert "\x00" not in value and "\\u0000" not in value
    turn = {
        "model": "m\x00",
        "eff_input": 1,
        "output": 1,
        "uuid": "u",
        "seconds": 1,
        "nanos": 0,
        "prompt_blocks": [],
        "response_blocks": [],
        "stop_reason": "end_turn",
    }
    events.build_llm_interaction_turn("s\x00", turn, "a\x00", "r\x00", "", 0)
    bucket = {
        "eff_input": 1,
        "output": 1,
        "last_uuid": "u",
        "last_seconds": 1,
        "last_nanos": 0,
    }
    body = events.build_llm_interaction(
        "s", "m", bucket, "a", "ti\x00tle", "r", "", "b\x00"
    )
    assert "ti\ufffdtle".encode() in body and b"ti\x00tle" not in body


_TITLE_SECRETS = [
    ("aws_access_key_id", "AK" + "IA" + F * 3 + "1234"),
    ("github_token", "gh" + "p_" + F * 9),
    ("switch_key", "sk_" + "live_" + F * 7 + "01"),
    ("private_key", PEM),
]


def _condensed_prompt(title: str, repo: str = "r", branch: str | None = "b") -> bytes:
    bucket = {"eff_input": 1, "output": 1, "last_seconds": 1, "last_nanos": 0}
    return events.build_llm_interaction("s", "m", bucket, "a", title, repo, "", branch)


@pytest.mark.parametrize(("kind", "secret"), _TITLE_SECRETS)
def test_condensed_title_repo_and_branch_are_redacted(kind: str, secret: str) -> None:
    marker = f"[REDACTED:{kind}]"
    for body in (
        _condensed_prompt(f"fix {secret} now"),
        _condensed_prompt("t", "r", secret),
    ):
        assert secret.encode() not in body and marker.encode() in body
    assert events.build_prompt_text("t", secret, None) == f"t ({marker})"


@pytest.mark.parametrize("branch", ["feat/x-1", None])
def test_clean_condensed_prompt_is_unchanged(branch: str | None) -> None:
    title = "Refactor token budget & cap handling (v2) \u00e9"
    expected = events.build_prompt_text(title, "hoot", branch)
    assert expected == f"{title} (hoot{':' + branch if branch else ''})"
    assert expected.encode() in _condensed_prompt(title, "hoot", branch)


def test_text_blocks_get_the_larger_cap() -> None:
    prompt_text = "w " * 25_000
    res = {
        "kind": "tool_result",
        "tool_use_id": "t",
        "text": "w " * 25_000,
        "is_error": False,
    }
    prompt, _ = sanitize_turn([{"kind": "text", "text": prompt_text}, res], [])
    assert prompt[0]["text"] == prompt_text
    assert len(prompt[1]["text"].encode()) <= BLOCK_CAP_BYTES
    assert "[TRUNCATED:" in prompt[1]["text"]
