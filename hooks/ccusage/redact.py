"""Best-effort secret redaction and size capping for text/full report modes.

Every pattern starts behind a negative lookbehind over its own body class, so a
run of repeated prefixes is scanned once instead of once per prefix.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from .pii import PiiRedactor

BLOCK_CAP_BYTES = 16 * 1024
TEXT_BLOCK_CAP_BYTES = 64 * 1024
EVENT_CAP_BYTES = 1024 * 1024
_ENVELOPE_RESERVE_BYTES = 64 * 1024
_BLOCK_OVERHEAD_BYTES = 64
_SENSITIVE_FILE = "[REDACTED:sensitive_file]"
_UNPROCESSABLE = "[REDACTED:unprocessable]"
_CREDENTIAL = "[REDACTED:credential]"

_SECRET = "secret"
_Q = r"""(?:\\{0,2}["'`])"""
_VALUE = r"""(?P<q>\\{0,2}["'`])?(?P<secret>[^\s"'`\\]{3,})"""
_KEYWORD = re.compile(
    r"passw(?:or)?d|pwd|secret|token|api[_-]?key|private[_-]?key",
    re.IGNORECASE,
)
_CAMEL_KEYWORD = r"(?<=[a-z0-9])(?:Passw(?:or)?d|Secret|Token|ApiKey|PrivateKey)"
_UPPER_KEYWORD = r"(?<=[A-Z0-9])(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN)"
_AUTH_KEY = r"(?<![A-Za-z0-9_])_?auth(?![A-Za-z0-9_])"
_IDENTIFIER = re.compile(r"[A-Za-z_]+")
_PLAIN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_.:]*")
_CALL = re.compile(r"[A-Za-z_][A-Za-z0-9_.:]*[(\[]")
_ENV_NAME = re.compile(r"[A-Z0-9_]+")
_LITERALS = frozenset(
    "true false null none undefined nil string str int bool number any unknown "
    "float bytes object required optional".split()
)
_PLACEHOLDER_PREFIXES = ("$", "%(", "{", "<", "...", "\u2026", "[REDACTED:")
_CODE_PREFIXES = ("-", "&", "*", "/", "(")
_PWD_NAMES = ("PWD", "OLDPWD")
_CODE_CHARS = frozenset("(){}[];|<>")
_REFERENCE_PREFIXES = (
    "process.env",
    "os.environ",
    "env.",
    "config.",
    "settings.",
    "self.",
    "this.",
    "credentials.",
)
_PRINTF = re.compile(r"(?:%[-#0 +]?\d*[sdrvq])+")
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)(?:your|enter|insert|replace)[\w-]*|[\w-]*_here|x{3,}|\*{3,}"
)
_AUTH_SCHEMES = frozenset("oauth oauth2 basic bearer digest none".split())
_PLACEHOLDER_WORDS = frozenset(
    "password passwd pass pwd secret token xxx xxxx xxxxxx redacted example "
    "mypassword yourpassword your_password your_token".split()
)
_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+/=."
)
_KEY_WORD = re.compile(r"[a-z0-9]+")
_CAMEL_HUMP = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_CREDENTIAL_WORDS = frozenset(
    "password passwords passwd passphrase pwd secret secrets token apikey auth credential "
    "credentials".split()
)
_KEY_QUALIFIERS = frozenset("api private access secret auth signing encryption".split())
_YAML_LIST_KEY = re.compile(
    r"(?i)^([ \t]*)[\w.-]*(?:passwords?|secrets?|tokens?|api_?keys?):[ \t]*$"
)
_YAML_LIST_HINT = re.compile(r"(?i)(?:password|secret|token|key)s?:[ \t]*\r?\n")
_YAML_MAP_ITEM = re.compile(r"[\w.-]+:(?:\s|$)")
_PAGINATION_WORDS = frozenset(
    "page next prev previous continuation cursor pagination resume".split()
)
_YAML_ITEM = re.compile(r"^([ \t]*)-[ \t]+(\S.*)$")
_NEWLINE = r"(?:\\{1,4}[nr]|\r?\n)"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]{1,16} ){0,4}PRIVATE KEY(?: BLOCK)?-----"
            rf"(?:{_NEWLINE}[A-Za-z][A-Za-z-]{{0,30}}: [^\r\n\\]{{0,200}})*"
            r"(?P<body>(?:\\{1,4}[nrt/]|\s|[A-Za-z0-9+/=])*)"
            r"(?:-----END (?:[A-Z0-9]{1,16} ){0,4}PRIVATE KEY(?: BLOCK)?-----)?"
        ),
    ),
    (
        "aws_credential",
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:aws_?)?(?:secret_?access_?key|session_?token"
            rf"|security_?token|access_?key_?id){_Q}?(?:[ \t]{{0,3}}[:=][ \t]{{0,3}}){_VALUE}"
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "github_token",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "slack_token",
        re.compile(r"(?<![A-Za-z0-9.-])(?:xox[a-z]|xapp)[.-][A-Za-z0-9.-]{10,}"),
    ),
    (
        "slack_webhook",
        re.compile(
            r"hooks\.slack\.com/(?:services|workflows|triggers)/(?P<secret>[A-Za-z0-9/_-]+)"
        ),
    ),
    (
        "google_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
    ),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    ("anthropic_key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}")),
    (
        "switch_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:[sr]k_(?:live|test)_[A-Za-z0-9]{16,1024}"
            r"|[sr]k_(?=[A-Za-z0-9_-]{0,512}\d)[A-Za-z0-9_-]{20,1024})"
        ),
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,16384}"
            r"\.[A-Za-z0-9_-]{8,}"
        ),
    ),
    (
        "url_credentials",
        re.compile(
            r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@\"'<>]{1,256}:"
            r"(?P<secret>[^\s/@\"'<>]{1,1024})@"
        ),
    ),
    (
        "basic_auth_flag",
        re.compile(
            r"(?<![A-Za-z0-9-])(?:-u|--user)[ \t=]{1,3}[\"']?[^\s:\"']{1,256}:"
            r"(?P<secret>[^\s\"']+)"
        ),
    ),
    (
        "password_hash",
        re.compile(
            r"(?<![^\s\"'])[^\s:\"']{1,64}:(?P<secret>\$(?:apr1|2[abxy]?|1|5|6|y)\$[^\s\"']{8,}"
            r"|\{SHA\}[A-Za-z0-9+/=]{20,})"
        ),
    ),
    (
        "authorization",
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:authorization[ \t]{0,3}:[ \t]{0,3}"
            r"(?:bearer|basic|apikey|token)|bearer)[ \t]{1,3}(?P<secret>[A-Za-z0-9._~+/-]{8,}=*)"
        ),
    ),
    (
        "credential",
        re.compile(
            rf"(?P<key>(?:(?<![A-Za-z0-9])(?i:{_KEYWORD.pattern})|{_CAMEL_KEYWORD}|{_UPPER_KEYWORD}|{_AUTH_KEY})"
            r"(?i:_access_key|_key|_value)?)"
            rf"(?P<sep>[ \t]{{0,3}}[=:][ \t]{{0,3}}|{_Q}[ \t]{{0,3}}:[ \t]{{0,3}}){_VALUE}"
        ),
    ),
]

_SENSITIVE_BASENAME = re.compile(
    r"(?i)^(?:\.env(?!\.(?:example|sample|template|dist)$)[^/]*|.+\.env"
    r"|.*\.(?:pem|key|p12|pfx)|id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?"
    r"|[._]netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|\.htpasswd)$"
)
_SENSITIVE_SUFFIXES = (".aws/credentials", ".docker/config.json", ".kube/config")
_ENV_DUMP_COMMANDS = ("env", "set", "export")
_PATH_TOKEN = re.compile(r"""[^\s"'`;|&<>()=]+""")
_COMMAND_SPLIT = re.compile(r"[;|&\n]")
_PATH_KEYS = ("file_path", "path", "notebook_path", "glob", "command")
_CONTENT_KEYS = ("content", "new_string", "old_string", "new_source", "edits")
_BOUNDARY = re.compile(r"""[\s"'`<>\\]""")


def _key_name(m: re.Match[str]) -> str:
    text, start = m.string, m.start("key")
    while (
        start > 0
        and m.start("key") - start < 64
        and (text[start - 1].isalnum() or text[start - 1] == "_")
    ):
        start -= 1
    return text[start : m.end("key")]


def _is_reference(value: str) -> bool:
    return bool(
        _CALL.match(value)
        or value.startswith(_REFERENCE_PREFIXES)
        or value.lower() in _PLACEHOLDER_WORDS
        or value.lower() in _AUTH_SCHEMES
        or _PLACEHOLDER_VALUE.fullmatch(value)
    )


def nul_free(text: str) -> str:
    """Postgres TEXT/jsonb rejects U+0000 (and its `\\u0000` JSON escape), failing the whole stored batch."""
    return text.replace("\x00", "\ufffd").replace("\\u0000", "\\ufffd")


def _credential_is_code(m: re.Match[str]) -> bool:
    sep, quoted = m.group("sep"), bool(m.group("q"))
    value = m.group(_SECRET).rstrip(",;:)]}")
    if (
        not value
        or value.startswith(_PLACEHOLDER_PREFIXES)
        or value.lower() in _LITERALS
    ):
        return True
    name = _key_name(m)
    name_start = m.end("key") - len(name)
    if (
        name in _PWD_NAMES
        or _is_pagination_name(name)
        or (sep == ":" and m.string[name_start - 1 : name_start] == ":")
    ):
        return True
    if (quoted and _IDENTIFIER.fullmatch(value) and _KEYWORD.search(value)) or (
        _is_reference(value)
    ):
        return True
    unquoted_key = sep[:1] not in ("'", '"', "`", "\\")
    if _ENV_NAME.fullmatch(name) and (
        quoted or not unquoted_key or sep == "=" or sep.strip() == ":"
    ):
        return False
    closed = m.string[m.end(_SECRET) : m.end(_SECRET) + 1] in ("'", '"', "`", "\\")
    if quoted and closed and value.isalpha():
        return False
    if (
        value.startswith(_CODE_PREFIXES)
        or (not quoted and value.startswith("!"))
        or _PLAIN_IDENTIFIER.fullmatch(value)
        or (not quoted and any(c in _CODE_CHARS for c in value))
    ):
        return True
    return not _secret_like(value)


def _secret_like(value: str) -> bool:
    if len(value) < 8 or any(c.isspace() for c in value):
        return False
    return any(c.isdigit() for c in value) or not (
        value.replace("-", "").replace("_", "").replace(".", "").isalnum()
    )


def _is_pagination_name(name: str) -> bool:
    words = _KEY_WORD.findall(_CAMEL_HUMP.sub("_", name).lower())
    return bool(set(words) & _PAGINATION_WORDS)


def _redact_yaml_lists(text: str) -> str:
    lines = text.split("\n")
    indent = None
    for n, line in enumerate(lines):
        item = _YAML_ITEM.match(line) if indent is not None else None
        if item and len(item.group(1)) >= indent:
            scalar = item.group(2).strip().strip("'\"")
            if not _YAML_MAP_ITEM.match(scalar) and _secret_like(scalar):
                lines[n] = f"{item.group(1)}- {_CREDENTIAL}"
            continue
        key = _YAML_LIST_KEY.match(line)
        indent = len(key.group(1)) if key else None
    return "\n".join(lines)


def _is_false_positive(kind: str, m: re.Match[str]) -> bool:
    if kind == "private_key":
        return sum(c.isalnum() for c in m.group("body")) < 16
    if kind == "credential":
        return _credential_is_code(m)
    if kind == "authorization" and m.group(0)[:1] in "bB":
        return m.group(_SECRET).isalpha()
    if _SECRET not in m.re.groupindex or kind == "password_hash":
        return False
    value = m.group(_SECRET)
    if kind == "aws_credential":
        bare = value.rstrip(",;:)]}")
        return (
            bare.startswith(_PLACEHOLDER_PREFIXES)
            or bare.lower() in _LITERALS
            or _is_reference(bare)
            or bool(_PLAIN_IDENTIFIER.fullmatch(bare))
        )
    if kind == "url_credentials" and (
        value.lower() in _PLACEHOLDER_WORDS or _PRINTF.fullmatch(value)
    ):
        return True
    return value.startswith(_PLACEHOLDER_PREFIXES)


def _replacement(kind: str) -> Callable[[re.Match[str]], str]:
    def sub(m: re.Match[str]) -> str:
        if _is_false_positive(kind, m):
            return m.group(0)
        if _SECRET not in m.re.groupindex:
            return f"[REDACTED:{kind}]"
        start, end = m.span(_SECRET)
        whole, base = m.group(0), m.start()
        return f"{whole[: start - base]}[REDACTED:{kind}]{whole[end - base :]}"

    return sub


def redact(text: str, pii: PiiRedactor | None = None) -> str:
    """Replace each matched secret with `[REDACTED:<type>]`; an unterminated PEM block redacts its base64 run."""
    if not text:
        return text
    for kind, pattern in _PATTERNS:
        text = pattern.sub(_replacement(kind), text)
    if _YAML_LIST_HINT.search(text):
        text = _redact_yaml_lists(text)
    return pii(text) if pii is not None else text


def truncate_utf8(text: str, cap: int, total: int | None = None) -> str:
    """Cut `text` to at most `cap` UTF-8 bytes, marker included, never mid-character.

    A token cut by the limit is dropped whole, so a block of one long token is just the marker.
    """
    data = text.encode("utf-8", "replace")
    if len(data) <= cap and total is None:
        return data.decode("utf-8")
    marker = f"\n[TRUNCATED: {total or len(data)} bytes total, cut to {cap}]"
    keep = max(min(len(data), cap - len(marker.encode("utf-8"))), 0)
    kept = data[:keep].decode("utf-8", "ignore")
    end = len(kept)
    while end and kept[end - 1] in _TOKEN_CHARS:
        end -= 1
    return kept[:end] + marker


def redact_capped(text: str, cap: int, pii: PiiRedactor | None = None) -> str:
    """Redact, then cap at `cap` bytes; only the first 2*cap chars are scanned.

    That prefix is cut back to a token boundary so a secret straddling the cut
    is never redaction-shrunk into view as a fragment.
    """
    if len(text) <= 2 * cap:
        return truncate_utf8(redact(text, pii), cap)
    head = text[: 2 * cap]
    tail_start = max(0, len(head) - 8192)
    cut = max(
        (b.start() for b in _BOUNDARY.finditer(head, tail_start)), default=tail_start
    )
    head = head[:cut]
    return truncate_utf8(redact(head, pii), cap, len(text.encode("utf-8", "replace")))


def is_sensitive_path(path: str) -> bool:
    normalized = path.replace("\\", "/").rstrip("/")
    if normalized.endswith(_SENSITIVE_SUFFIXES):
        return True
    return bool(_SENSITIVE_BASENAME.match(normalized.rsplit("/", 1)[-1]))


def command_is_sensitive(command: str) -> bool:
    for segment in _COMMAND_SPLIT.split(command):
        words = segment.split()
        if words and (
            words[0] == "printenv"
            or (
                words[0] in _ENV_DUMP_COMMANDS
                and (len(words) == 1 or words[1][:1] == "-")
            )
        ):
            return True
    return any(is_sensitive_path(tok) for tok in _PATH_TOKEN.findall(command))


def _touches_sensitive_path(tool_input: Any) -> bool:
    if not isinstance(tool_input, dict):
        return False
    return any(
        isinstance(tool_input.get(key), str) and command_is_sensitive(tool_input[key])
        for key in _PATH_KEYS
    )


def is_credential_key(key: str) -> bool:
    if key in _PWD_NAMES:
        return False
    words = _KEY_WORD.findall(_CAMEL_HUMP.sub("_", key).lower())
    if set(words) & _PAGINATION_WORDS:
        return False
    if words and words[-1] in ("value", "b64", "base64"):
        words.pop()
    if not words:
        return False
    if words[-1] == "key":
        return len(words) > 1 and words[-2] in _KEY_QUALIFIERS
    return words[-1] in _CREDENTIAL_WORDS


def _is_secret_value(value: str) -> bool:
    stripped = value.strip()
    return (
        bool(stripped)
        and stripped.lower() not in _LITERALS
        and not stripped.startswith(_PLACEHOLDER_PREFIXES)
    )


def _walk_json(
    root: Any, on_string: Callable[[str, bool, bool], str], on_key: Callable[[str], str]
) -> Any:
    holder = [root]
    stack: list[tuple[Any, Any, bool, bool]] = [(holder, 0, False, False)]
    while stack:
        parent, slot, in_content, credential = stack.pop()
        value = parent[slot]
        if isinstance(value, str):
            parent[slot] = on_string(value, in_content, credential)
        elif isinstance(value, list):
            copy = list(value)
            parent[slot] = copy
            stack.extend(
                (copy, i, in_content, credential) for i in reversed(range(len(copy)))
            )
        elif isinstance(value, dict):
            renamed: dict[Any, tuple[Any, Any]] = {}
            for k, v in value.items():
                new_key = on_key(k) if isinstance(k, str) else k
                suffix = 2
                unique = new_key
                while unique in renamed:
                    unique = f"{new_key}#{suffix}"
                    suffix += 1
                renamed[unique] = (k, v)
            copy = {k: v for k, (_, v) in renamed.items()}
            parent[slot] = copy
            for new_key in reversed(list(copy)):
                old_key = renamed[new_key][0]
                is_str = isinstance(old_key, str)
                stack.append(
                    (
                        copy,
                        new_key,
                        in_content or old_key in _CONTENT_KEYS,
                        is_str and is_credential_key(old_key),
                    )
                )
    return holder[0]


def _fit_json(
    tool_input: Any, cap: int, sensitive: bool, pii: PiiRedactor | None = None
) -> str:
    skeleton = json.dumps(_walk_json(tool_input, _blank, lambda k: k))
    if len(skeleton) > cap:
        return json.dumps(f"[TRUNCATED: input_json over the {cap}-byte cap]")
    if pii is not None:
        tool_input = pii.structured(tool_input)

    def on_string(value: str, in_content: bool, credential: bool) -> str:
        if sensitive and in_content:
            return _SENSITIVE_FILE
        if credential and _is_secret_value(value):
            return _CREDENTIAL
        return redact_capped(value, BLOCK_CAP_BYTES, pii)

    def on_key(key: str) -> str:
        return redact_capped(key, BLOCK_CAP_BYTES, pii)

    redacted = _walk_json(tool_input, on_string, on_key)
    out = json.dumps(redacted)
    if len(out) <= cap:
        return out
    strings: list[str] = []
    _walk_json(redacted, lambda v, _c, _k: strings.append(v) or v, lambda k: k)
    escaped = sorted(len(json.dumps(v)) - 2 for v in strings)
    budget = cap - len(json.dumps(_walk_json(redacted, _blank, lambda k: k)))
    for _ in range(12):
        limit = _fair_share(escaped, budget)
        out = json.dumps(_walk_json(redacted, _shrinker(limit), lambda k: k))
        if len(out) <= cap:
            return out
        budget = budget * 4 // 5
    return json.dumps(f"[TRUNCATED: input_json over the {cap}-byte cap]")


def _blank(_value: str, _content: bool, _credential: bool) -> str:
    return ""


def _fair_share(sizes: list[int], budget: int) -> int:
    for i, size in enumerate(sizes):
        share = budget // (len(sizes) - i)
        if size > share:
            return max(share, 0)
        budget -= size
    return sizes[-1] if sizes else 0


def _shrinker(limit: int) -> Callable[[str, bool, bool], str]:
    def shrink(value: str, _content: bool, _credential: bool) -> str:
        escaped = len(json.dumps(value)) - 2
        if escaped <= limit:
            return value
        if limit < 64:
            return "[TRUNCATED]" if limit >= 11 else ""
        ratio = len(value.encode("utf-8", "replace")) / max(escaped, 1)
        return truncate_utf8(value, max(int(limit * ratio) - 8, 0), escaped)

    return shrink


def guard_shell_blocks(
    raw_blocks: list[dict[str, Any]], pending: bool
) -> tuple[list[dict[str, Any]], bool]:
    """Placeholder `!`-mode shell output whose recorded `<bash-input>` command touched a sensitive path.

    Claude Code logs the command and its output as two consecutive user
    entries, so `pending` carries the decision only into the very next block.
    """
    out = []
    for block in raw_blocks:
        text = block.get("text") if block.get("type") == "text" else None
        if not isinstance(text, str):
            pending = False
            out.append(block)
            continue
        start = text.find("<bash-input>")
        sensitive = pending
        if start >= 0:
            end = text.find("</bash-input>", start)
            sensitive = command_is_sensitive(
                text[start + 12 : end if end >= 0 else None]
            )
        has_stdout = "<bash-stdout>" in text
        if has_stdout and sensitive:
            block = {**block, "text": _replace_stdout(text)}
        pending = start >= 0 and not has_stdout and sensitive
        out.append(block)
    return out, pending


def _replace_stdout(text: str) -> str:
    start = text.find("<bash-stdout>") + len("<bash-stdout>")
    end = text.find("</bash-stdout>", start)
    rest = text[end:] if end >= 0 else "</bash-stdout>"
    return text[:start] + _SENSITIVE_FILE + rest


def _field(block: dict[str, Any]) -> str:
    return {"text": "text", "tool_use": "input_json", "tool_result": "text"}[
        block["kind"]
    ]


def _parse(input_json: str) -> Any:
    try:
        return json.loads(input_json)
    except Exception:
        return None


def _sanitize_block(
    block: dict[str, Any],
    field: str,
    cap: int,
    inputs: dict[int, Any],
    sensitive_ids: set[str],
    pii: PiiRedactor,
) -> str:
    if block["kind"] == "tool_result" and block["tool_use_id"] in sensitive_ids:
        return _SENSITIVE_FILE if block[field] else ""
    if block["kind"] == "tool_use" and inputs[id(block)] is not None:
        sensitive = block["id"] in sensitive_ids
        return nul_free(_fit_json(inputs[id(block)], cap, sensitive, pii))
    return nul_free(redact_capped(block[field].replace("\x00", "\ufffd"), cap, pii))


def _sensitive_input(tool_input: Any) -> bool:
    try:
        return _touches_sensitive_path(tool_input)
    except Exception:
        return True


def sanitize_turn(
    prompt_blocks: list[dict[str, Any]],
    response_blocks: list[dict[str, Any]],
    pii: PiiRedactor | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Redact and cap a turn's blocks so the whole event stays under EVENT_CAP_BYTES.

    Text blocks are budgeted before tool blocks; blocks that no longer fit are
    dropped and counted in a trailing marker.
    """
    pii = pii if pii is not None else PiiRedactor()
    inputs = {
        id(b): _parse(b["input_json"])
        for b in response_blocks
        if b["kind"] == "tool_use"
    }
    sensitive_ids = {
        b["id"]
        for b in response_blocks
        if b["kind"] == "tool_use" and _sensitive_input(inputs[id(b)])
    }
    remaining = EVENT_CAP_BYTES - _ENVELOPE_RESERVE_BYTES
    omitted = 0
    sides = (list(prompt_blocks), list(response_blocks))
    out: list[list[dict[str, Any] | None]] = [[None] * len(s) for s in sides]
    order = [
        (side, i)
        for tools in (False, True)
        for side, blocks in enumerate(sides)
        for i, b in enumerate(blocks)
        if (b["kind"] != "text") == tools
    ]
    for side, i in order:
        block = sides[side][i]
        field = _field(block)
        ids = "".join(str(block.get(k, "")) for k in ("id", "name", "tool_use_id"))
        overhead = _BLOCK_OVERHEAD_BYTES + len(ids.encode("utf-8", "replace"))
        block_cap = TEXT_BLOCK_CAP_BYTES if block["kind"] == "text" else BLOCK_CAP_BYTES
        cap = min(block_cap, remaining - overhead)
        if cap < _BLOCK_OVERHEAD_BYTES:
            omitted += 1
            continue
        try:
            value = _sanitize_block(block, field, cap, inputs, sensitive_ids, pii)
        except Exception:
            value = _UNPROCESSABLE
            if block["kind"] == "tool_use":
                value = json.dumps(_UNPROCESSABLE)
        size = len(value.encode("utf-8"))
        if size > cap:
            omitted += 1
            continue
        remaining -= overhead + size
        out[side][i] = {
            **{k: nul_free(v) if isinstance(v, str) else v for k, v in block.items()},
            field: value,
        }
    prompt, response = ([b for b in side if b is not None] for side in out)
    if omitted:
        response.append(
            {
                "kind": "text",
                "text": f"[TRUNCATED: {omitted} blocks omitted, event size cap]",
            }
        )
    return prompt, response
