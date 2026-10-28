"""Best-effort redaction of structured personal data: cards, national IDs, IBANs, emails, IPs."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterator
from datetime import date
from functools import lru_cache
from typing import Any

from . import pii_ids
from .config import PII_REDACTION_DEFAULT, PII_REDACTION_OFF, PII_REDACTION_STRICT
from .pii_ids import luhn_valid

Span = tuple[int, int, str, str]

_DIGIT_BEFORE = re.compile(r"\d[.\-]?\Z")
_DIGIT_AFTER = re.compile(r"[.\-]?\d")
_ASCII_ALNUM = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
_GLUED_AFTER = re.compile(r"[A-Za-z0-9]*")
_HEX = re.compile(r"[0-9A-Fa-f]*")
_MIN_GLUED_BLOB = 8
_NON_DIGIT = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")
_TWO_DIGITS = re.compile(r"\d\d")


def _embedded_in_longer_token(text: str, start: int, end: int) -> bool:
    if _DIGIT_BEFORE.search(text, max(0, start - 2), start) or _DIGIT_AFTER.match(
        text, end
    ):
        return True
    begin = start
    while begin > max(0, start - 64) and text[begin - 1] in _ASCII_ALNUM:
        begin -= 1
    glued = text[begin:start] + _GLUED_AFTER.match(text, end, end + 64).group()
    return len(glued) >= _MIN_GLUED_BLOB and (
        _HEX.fullmatch(glued) is not None or any(c.isdigit() for c in glued)
    )


def _ascii_digits(text: str) -> str:
    return "".join(str(int(c)) for c in _NON_DIGIT.sub("", text))


def _known_issuer(digits: str) -> bool:
    n = len(digits)
    if digits[0] == "4":
        return n in (13, 16, 19)
    if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720:
        return n == 16
    if digits[:2] in ("34", "37"):
        return n == 15
    if digits[:4] == "6011" or digits[:2] == "65" or 644 <= int(digits[:3]) <= 649:
        return n in (16, 19)
    return False


def valid_credit_card(digits: str) -> bool:
    return 13 <= len(digits) <= 19 and _known_issuer(digits) and luhn_valid(digits)


def valid_ssn(digits: str) -> bool:
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return (
        area not in ("000", "666")
        and area[0] != "9"
        and group != "00"
        and serial != "0000"
    )


def _kw(*words: str) -> str:
    capitalized = "|".join(w[0].upper() + w[1:] for w in words)
    return rf"(?:(?<![A-Za-z])(?i:{'|'.join(words)})|(?<=[a-z0-9])(?:{capitalized}))"


_NUM_SUFFIX = r"(?:[ _-]?(?i:no\.?|number|num|nbr|id|\#))?s?"
_GAP = (
    r"""[\s"'`:=#|(),\[\]{}*_.-]{0,6}"""
    r"""(?:(?i:is|was|of|no\.?|number|\#)[\s"'`:=#.-]{1,4})?"""
)
_ID_WORDS = (
    "order",
    "invoice",
    "tracking",
    "shipment",
    "sku",
    "part",
    "p/n",
    "pn",
    "serial",
    "item",
    "model",
    "catalog",
    "ticket",
    "case",
    "ref",
    "reference",
    "request",
    "trace",
    "span",
    "event",
    "message",
    "msg",
    "build",
    "job",
    "batch",
    "lot",
    "product",
    "transaction",
    "txn",
)
_ID_LABEL = re.compile(
    _kw(*_ID_WORDS)
    + r"s?(?:[ _-]?(?i:id|no\.?|num|number|nbr|\#|code))?"
    + r"""[\s"'`:=#|(),\[\]{}.-]{0,6}\Z"""
)
_CARD_WORDS = (
    "card",
    "visa",
    "master",
    "amex",
    "discover",
    "cc",
    "pan",
    "payment",
    "credit",
    "debit",
)
_CARD_KW = re.compile(
    r"(?i)card|visa|master|amex|discover|\bcc\b|\bpan\b|payment|credit|debit"
)
_CARD = re.compile(
    r"(?<!\d)\d{4}(?:([ \u00a0-])\d{4}\1\d{4}\1\d{4}(?:\1\d{3})?"
    r"|([ \u00a0-])\d{6}\2\d{5}|\d{9,15})(?!\d)"
)
_LIST_BEFORE = re.compile(r"\d[ ,;]{1,2}\Z")
_LIST_AFTER = re.compile(r"[ ,;]{1,2}\d")
_SSN_DASHED = re.compile(r"(?<![0-9])\d{3}-\d{2}-\d{4}(?![0-9])")
_SSN_KEYWORD = re.compile(
    "(?:"
    + _kw(
        "ssn",
        "social[ _-]?security",
        "taxpayer[ _-]?id(?:entification)?",
        "tax[ _-]?id",
    )
    + r"|(?<![A-Za-z])I?TIN(?![A-Za-z]))"
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>\d{3}([ -]?)\d{2}\2\d{4})(?![0-9])"
)
_IBAN_LENGTHS = {
    entry[:2]: int(entry[2:])
    for entry in (
        "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 "
        "DE22 DK18 DO28 EE20 EG29 ES24 FI18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 "
        "HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 "
        "LV21 MC27 MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 "
        "RO24 RS22 SA24 SC31 SE24 SI19 SK24 SM27 ST25 SV28 TL23 TN24 TR26 UA29 VA22 "
        "VG24 XK20"
    ).split()
}
_IBAN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Z]{2}\d{2}"
    r"(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)(?![A-Za-z0-9+/])"
)
_PASSPORT = re.compile(
    _kw("passport")
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>(?=[A-Z0-9]{0,8}\d)[A-Z0-9]{6,9})(?![A-Za-z0-9])"
)
_DRIVER_LICENCE = re.compile(
    "(?:"
    + _kw(r"driver'?s?[ _-]?licen[cs]e", r"driving[ _-]?licen[cs]e")
    + r"|(?<![A-Za-z])DLN?(?=[ _-]?(?:\#|No|Number)))"
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>(?=[A-Z0-9-]{0,19}\d)[A-Z0-9][A-Z0-9-]{3,18}[A-Z0-9])(?![A-Za-z0-9-])"
)
_MRN = re.compile(
    _kw("mrn", "medical[ _-]?record")
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>[A-Z]{0,3}\d{5,10})(?![A-Za-z0-9])"
)
_MONTH = r"(?i:(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*)\.?"
_DATE = (
    r"(?:\d{4}(?P<s1>[-/.])\d{1,2}(?P=s1)\d{1,2}|\d{1,2}(?P<s2>[-/.])\d{1,2}(?P=s2)\d{4}"
    r"|\d{8}"
    rf"|{_MONTH} \d{{1,2}}(?:st|nd|rd|th)?,? \d{{4}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?[ -]{_MONTH},?[ -]\d{{4}})"
)
_DATE_ONLY = re.compile(_DATE)
_DOB = re.compile(
    _kw(
        "dob",
        r"d\.o\.b\.?",
        "date[ _-]?of[ _-]?birth",
        "birth[ _-]?date",
        "birthday",
        "born(?: on)?",
    )
    + r"s?"
    + _GAP
    + rf"(?P<v>{_DATE})(?![0-9])"
)
_E164 = re.compile(r"(?<![\w+])\+[1-9]\d{7,14}(?![\w])")
_PHONE_KEYWORD = re.compile(
    _kw("phone", "tel", "telephone", "mobile", "cell", "fax", "sms", "whatsapp")
    + "s?(?![a-z])"
)
_PHONE = re.compile(
    r"(?<![\w+.])(?:(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}"
    r"|[2-9]\d{2}[2-9]\d{6}|\+[1-9][\d ().-]{7,18}\d)(?![\w-])"
)
_KEYED_ID = re.compile(r"(?=[A-Za-z0-9 -]*\d)[A-Za-z0-9][A-Za-z0-9 -]{3,22}[A-Za-z0-9]")
_KEY_WORD = re.compile(r"[a-z0-9]+")
_CAMEL_HUMP = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _year_plausible(value: str) -> bool:
    years = [int(y) for y in re.findall(r"\d{4}", value)]
    if len(value) == 8 and value.isdigit():
        years = [int(value[:4])]
        month, day = int(value[4:6]), int(value[6:])
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return False
    return any(1900 <= y <= date.today().year for y in years)


def _labelled(
    text: str, start: int, width: int, words: tuple[str, ...], label: re.Pattern[str]
) -> bool:
    window = text[max(0, start - width) : start]
    lowered = window.lower()
    return any(w in lowered for w in words) and label.search(window) is not None


def _not_id_label(text: str, start: int) -> bool:
    return not _labelled(text, start, 32, _ID_WORDS, _ID_LABEL)


def _cards(text: str, _lower: str) -> Iterator[Span]:
    for m in _CARD.finditer(text):
        start, end = m.span()
        digits = _ascii_digits(m.group())
        grouped = len(digits) != end - start
        if not valid_credit_card(digits) or _embedded_in_longer_token(text, start, end):
            continue
        if grouped and (
            _LIST_BEFORE.search(text, max(0, start - 3), start)
            or _LIST_AFTER.match(text, end)
        ):
            continue
        keyword = _labelled(text, start, 60, _CARD_WORDS, _CARD_KW)
        if not grouped and len(digits) == 19 and not keyword:
            continue
        if keyword or _not_id_label(text, start):
            yield start, end, "card", digits


def _ssns(text: str, lower: str) -> Iterator[Span]:
    for m in _SSN_DASHED.finditer(text):
        start, end = m.span()
        digits = _ascii_digits(m.group())
        if (
            valid_ssn(digits)
            and not _embedded_in_longer_token(text, start, end)
            and _not_id_label(text, start)
        ):
            yield start, end, "ssn", digits
    if not _mentions(lower, ("ssn", "social", "tax")) and "TIN" not in text:
        return
    for m in _SSN_KEYWORD.finditer(text):
        digits = _ascii_digits(m.group("v"))
        if valid_ssn(digits):
            yield m.start("v"), m.end("v"), "ssn", digits


def iban_valid(compact: str) -> bool:
    if _IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rotated = compact[4:] + compact[:4]
    return int("".join(str(int(c, 36)) for c in rotated)) % 97 == 1


def _ibans(text: str, _lower: str) -> Iterator[Span]:
    for m in _IBAN.finditer(text):
        raw = m.group()
        for candidate in (raw, raw.rsplit(" ", 1)[0]):
            compact = candidate.replace(" ", "")
            if iban_valid(compact):
                yield m.start(), m.start() + len(candidate), "iban", compact
                break


def _mentions(lower: str, hints: tuple[str, ...]) -> bool:
    return any(hint in lower for hint in hints)


def _keyword_values(
    kind: str,
    pattern: re.Pattern[str],
    hints: tuple[str, ...],
    exact: tuple[str, ...] = (),
    valid: Callable[[str], bool] | None = None,
) -> Any:
    def find(text: str, lower: str) -> Iterator[Span]:
        if not _mentions(lower, hints) and not any(e in text for e in exact):
            return
        for m in pattern.finditer(text):
            value = m.group("v")
            if valid is not None:
                compact = _NON_ALNUM.sub("", value).upper()
                if valid(compact):
                    yield m.start("v"), m.end("v"), kind, compact
            elif kind != "dob" or _year_plausible(value):
                yield m.start("v"), m.end("v"), kind, value.upper()

    return find


def _shaped_ids(text: str, _lower: str) -> Iterator[Span]:
    for m in _SHAPED_IDS.finditer(text):
        kind = next(k for k in _SHAPED_KINDS if m.group(k) is not None)
        start, end = m.span()
        compact = _NON_ALNUM.sub("", m.group()).upper()
        if (
            _ID_VALIDATORS[kind](compact)
            and not _embedded_in_longer_token(text, start, end)
            and not _LIST_BEFORE.search(text, max(0, start - 3), start)
            and not _LIST_AFTER.match(text, end)
            and _not_id_label(text, start)
        ):
            yield start, end, kind, compact


def _id_keyword(value: str, *words: str, exact: str = "") -> re.Pattern[str]:
    exact_alt = rf"|(?<![A-Za-z]){exact}(?![A-Za-z])" if exact else ""
    initials = {w[0] for w in words} | set(re.findall(r"(?:^|[|(:])([A-Z])", exact))
    first = "".join(sorted(initials | {c.upper() for c in initials}))
    return re.compile(
        rf"(?=[{first}])(?:{_kw(*words)}{exact_alt})"
        + _NUM_SUFFIX
        + _GAP
        + rf"(?P<v>{value})(?![A-Za-z0-9])"
    )


_EMAIL_AT = re.compile(r"@|%40")
_EMAIL_LOCAL_CHAR = re.compile(r"[\w.%+-]")
_EMAIL_LOCAL_TAIL = re.compile(r"[\w.%+-]{1,64}\Z")
_EMAIL_DOMAIN = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}"
    r"([A-Za-z]{2,24}|xn--[A-Za-z0-9-]{1,59})"
    r"(?![A-Za-z0-9-])"
)
_NOT_MAILBOX_DOMAINS = frozenset(
    ("example.com", "example.net", "example.org", "openssh.com", "libssh.org")
)
_NOT_MAILBOX_SUFFIXES = tuple("." + d for d in _NOT_MAILBOX_DOMAINS)
_NOT_MAILBOX_LOCALS = frozenset(("git", "this", "super"))
_RESERVED_TLDS = frozenset(("example", "test", "invalid", "localhost"))
_FILE_EXTENSION_TLDS = frozenset(
    "png jpg jpeg gif svg webp ico pdf js mjs cjs ts tsx jsx css scss sass less html "
    "htm json yaml yml toml xml txt lock map whl tgz zip gz py go java kt rb php cpp "
    "hpp swift scala dart lua vue sql jar xpi".split()
)
_MAIL_LABEL_LINE = re.compile(
    r"[ \t>*|-]*(?i:author|commit|committer|from|to|cc|bcc|reply-to|sender"
    r"|maintainer|[a-z]+(?:-[a-z]+)*-by)[ \t]*:[ \t]*(?P<name>[^<>@\n]{1,80}?)[ \t]*\Z"
)
_NAME_WORD_TAIL = re.compile(r"(?<![\w.'-])[^\W\d_][\w.'-]{0,30}[ \t]*\Z")
_NAME_PARTICLES = frozenset(
    "van von der den de del della da di du la le bin al".split()
)


def _display_name_start(text: str, lt: int) -> int:
    newline = text.rfind("\n", max(0, lt - 120), lt)
    line_start = newline + 1 if newline >= 0 else max(0, lt - 120)
    line = text[line_start:lt]
    labelled = _MAIL_LABEL_LINE.match(line)
    if labelled:
        return line_start + labelled.start("name")
    stripped = line.rstrip()
    quote = stripped.rfind('"', 0, len(stripped) - 1)
    if stripped.endswith('"') and quote >= 0 and len(stripped) - quote <= 82:
        return line_start + quote
    start, end = lt, len(stripped)
    for _ in range(4):
        m = _NAME_WORD_TAIL.search(stripped, 0, end)
        if not m or not (
            m.group()[0].isupper() or m.group().strip() in _NAME_PARTICLES
        ):
            break
        start, end = line_start + m.start(), m.start()
    return start


def _personal_mailbox(local: str, domain: str, tld: str) -> bool:
    domain, tld = domain.lower(), tld.lower()
    return (
        local not in _NOT_MAILBOX_LOCALS
        and any(c.isalnum() for c in local)
        and tld not in _RESERVED_TLDS
        and not (tld in _FILE_EXTENSION_TLDS and domain.count(".") == 1)
        and domain not in _NOT_MAILBOX_DOMAINS
        and not domain.endswith(_NOT_MAILBOX_SUFFIXES)
    )


def _emails(text: str, _lower: str) -> Iterator[Span]:
    if "@" not in text and "%40" not in text:
        return
    pos = 0
    while True:
        sep = _EMAIL_AT.search(text, pos)
        if sep is None:
            return
        at, after = sep.span()
        domain = _EMAIL_DOMAIN.match(text, after)
        local = _EMAIL_LOCAL_TAIL.search(text, max(0, at - 64), at) if domain else None
        start = local.start() if local else at
        overlong = start > 0 and _EMAIL_LOCAL_CHAR.match(text, start - 1) is not None
        if start > 0 and text[start - 1] == "\\" and text[start] in "nrt":
            start += 1
        while start < at and text[start] in ".+-":
            start += 1
        if (
            domain is None
            or start == at
            or overlong
            or text[at - 1] == "."
            or not _personal_mailbox(text[start:at], domain.group(), domain.group(1))
        ):
            pos = after
            continue
        end = domain.end()
        address = f"{text[start:at]}@{domain.group()}".lower()
        if start > 0 and text[start - 1] == "<" and text.startswith(">", end):
            yield _display_name_start(text, start - 1), end + 1, "email", address
        else:
            yield start, end, "email", address
        pos = end


def _networks(*cidrs: str) -> tuple[Any, ...]:
    return tuple(ipaddress.ip_network(c) for c in cidrs)


_IP_NOT_PERSONAL = _networks(
    "0.0.0.0/8",
    "127.0.0.0/8",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/127",
    "100::/64",
    "2001:db8::/32",
    "3fff::/20",
)
_IPV6_UNICAST = _networks("2000::/3", "fc00::/7", "fe80::/10")
_IP_EXEMPT = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 "
        "208.67.220.220 2001:4860:4860::8888 2001:4860:4860::8844 "
        "2606:4700:4700::1111 2606:4700:4700::1001 "
        "169.254.169.254 169.254.169.253 169.254.170.2 169.254.170.23 "
        "168.63.129.16 100.100.100.200 fd00:ec2::254 fd00:ec2::23 fe80::1"
    ).split()
)
_IPV4 = re.compile(r"(?=\d)(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d|-?[A-Za-z_])")
_FILE_SUFFIX = re.compile(r"[.-][A-Za-z0-9]")
_CIDR_SUFFIX = re.compile(r"/(\d{1,3})(?!\d)")
_IPV6 = re.compile(
    r"(?=[0-9A-Fa-f:])(?<![\w:.])"
    r"(?=(?P<c>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}))"
    r"(?P=c)(?![\w.:]?\w)"
)
_IPV6_PERSONAL_PREFIXES = (
    *("2", "3", "::ffff:", "0:0:0:0:0:ffff:"),
    *("fc", "fd", "fe8", "fe9", "fea", "feb"),
)
_VERSION_BEFORE = re.compile(
    r"(?=[=<>~!^\u00a7vVrRbBfFkKsSoOcCpP])(?:(?:==|>=|<=|~=|!=|\^|~|(?<![A-Za-z])v\d{0,2}|(?<![A-Za-z])(?i:version|ver"
    r"|release|rev|build|firmware|kernel|sdk|oid|section|chapter|clause"
    r"|para(?:graph)?|figure)s?|\u00a7)[\s:=\"'#(-]{0,4})\Z"
)


def _int_ranges(networks: tuple[Any, ...], version: int) -> tuple[tuple[int, int], ...]:
    return tuple(
        (int(n.network_address), int(n.netmask))
        for n in networks
        if n.version == version
    )


_V4_NOT_PERSONAL = _int_ranges(_IP_NOT_PERSONAL, 4)
_V6_NOT_PERSONAL = _int_ranges(_IP_NOT_PERSONAL, 6)
_V6_UNICAST = _int_ranges(_IPV6_UNICAST, 6)
_V4_EXEMPT = frozenset(int(a) for a in _IP_EXEMPT if a.version == 4)
_V6_EXEMPT = frozenset(int(a) for a in _IP_EXEMPT if a.version == 6)


def _v4_personal(n: int) -> bool:
    return n not in _V4_EXEMPT and not any(
        n & mask == base for base, mask in _V4_NOT_PERSONAL
    )


def _v6_personal(n: int) -> bool:
    if n >> 32 == 0xFFFF:
        return _v4_personal(n & 0xFFFFFFFF)
    if n in _V6_EXEMPT or any(n & mask == base for base, mask in _V6_NOT_PERSONAL):
        return False
    return any(n & mask == base for base, mask in _V6_UNICAST)


def personal_ip(address: Any) -> bool:
    """False for loopback, documentation, multicast, reserved, resolver and cloud-metadata addresses."""
    n = int(address)
    return _v4_personal(n) if address.version == 4 else _v6_personal(n)


def _ips(text: str, _lower: str) -> Iterator[Span]:
    for m in _IPV4.finditer(text):
        octets = m.group().split(".")
        if (len(octets[0]) == 1 and len(octets[1]) == 1) or any(
            len(o) > 1 and o[0] == "0" for o in octets
        ):
            continue
        a, b, c, d = (int(o) for o in octets)
        if max(a, b, c, d) > 255 or not _v4_personal(a << 24 | b << 16 | c << 8 | d):
            continue
        start, end = m.span()
        if text[start - 1 : start] == "-" and _FILE_SUFFIX.match(text, end):
            continue
        slash_after = text.startswith("/", end)
        if start >= 2 and text[start - 1] == "/":
            prev = text[start - 2]
            if (prev.isalnum() or prev in "_-") and (octets[1] == "0" or slash_after):
                continue
        if slash_after:
            cidr = _CIDR_SUFFIX.match(text, end)
            if cidr and int(cidr.group(1)) <= 24:
                continue
        if not _VERSION_BEFORE.search(text, max(0, start - 24), start):
            yield start, end, "ip", m.group()
    if "::" not in text and text.count(":") < 6:
        return
    for m in _IPV6.finditer(text):
        literal = m.group("c")
        if not literal.lower().startswith(_IPV6_PERSONAL_PREFIXES):
            continue
        try:
            packed = socket.inet_pton(socket.AF_INET6, literal)
        except (OSError, ValueError):
            continue
        cidr = _CIDR_SUFFIX.match(text, m.end())
        if cidr and int(cidr.group(1)) <= 32:
            continue
        if _v6_personal(int.from_bytes(packed, "big")):
            yield m.start(), m.end(), "ip", socket.inet_ntop(socket.AF_INET6, packed)


_NINO_VALUE = (
    r"[A-Z]{2}(?:\d{6}|(?P<ns>[ -])\d{2}(?P=ns)\d{2}(?P=ns)\d{2}(?P=ns)| \d{6} )[A-D]"
)
_SHAPED_IDS = re.compile(
    r"(?=[0-9A-Z])(?:(?<![A-Za-z0-9])(?:"
    rf"(?P<nino>{_NINO_VALUE})"
    r"|(?P<in_pan>[A-Z]{5}\d{4}[A-Z])"
    r"|(?P<dni>[XYZ0-9]\d{7}-?[A-Z])"
    r"|(?P<codice_fiscale>[A-Z]{6}[\dLMNP-V]{2}[A-Z]"
    r"[\dLMNP-V]{2}[A-Z][\dLMNP-V]{3}[A-Z])"
    r")(?![A-Za-z0-9])"
    r"|(?<![\w.-])(?:"
    r"(?P<nir>[1-478] \d{2} \d{2} (?:\d{2}|2[AB]) \d{3} \d{3} \d{2})(?!\w| \d)"
    r"|(?P<aadhaar>[2-9]\d{3} \d{4} \d{4})(?!\w|[ .-]\d)"
    r"|(?P<be_nn>\d{2}\.\d{2}\.\d{2}[-.]\d{3}\.\d{2})(?!\w|[.-]\d)"
    r"))"
)
_SHAPED_KINDS = ("nino", "in_pan", "dni", "codice_fiscale", "nir", "aadhaar", "be_nn")
_NINO_KW = _id_keyword(
    r"[A-Za-z]{2}[ -]?\d{2}[ -]?\d{2}[ -]?\d{2}[ -]?[A-Da-d]",
    "nino",
    "ni[ _-]?(?:no|number)",
    "national[ _-]insurance",
)
_IN_PAN_KW = _id_keyword(
    r"[A-Za-z]{5}\d{4}[A-Za-z]", "pan", "permanent[ _-]account[ _-]number"
)
_DNI_KW = _id_keyword(r"[XYZxyz0-9]\d{7}-?[A-Za-z]", "dni", "nie", "nif")
_SIN_KW = _id_keyword(
    r"\d{3}([ -]?)\d{3}\2\d{3}", "social[ _-]?insurance", exact="(?:SIN|NAS)"
)
_AADHAAR_KW = _id_keyword(r"[2-9]\d{3}([ -]?)\d{4}\2\d{4}", "aadhaa?r", "uidai")
_BSN_KW = _id_keyword(
    r"\d{9}|\d{4}\.\d{2}\.\d{3}", "bsn", "burgerservicenummer", "sofi[ _-]?nummer"
)
_PESEL_KW = _id_keyword(r"\d{11}", "pesel")
_NIR_KW = _id_keyword(
    r"[1-478] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}",
    "nir",
    "insee",
    "s[\u00e9e]curit[\u00e9e][ _-]sociale",
    "num[\u00e9e]ro[ _-]de[ _-]s[\u00e9e]cu",
)
_BE_NN_KW = _id_keyword(
    r"\d{2}\.?\d{2}\.?\d{2}[-.]?\d{3}\.?\d{2}",
    "rijksregister(?:nummer)?",
    "registre[ _-]national",
    "num[\u00e9e]ro[ _-]national",
    "national[ _-]register(?:[ _-]number)?",
    "insz",
    "niss",
)


def _phones(text: str, lower: str) -> Iterator[Span]:
    if "+" in text:
        for m in _E164.finditer(text):
            yield m.start(), m.end(), "phone", m.group()
    hints = ("phone", "tel", "mobile", "cell", "fax", "sms", "whatsapp")
    if not _mentions(lower, hints):
        return
    for kw in _PHONE_KEYWORD.finditer(text):
        m = _PHONE.search(text, kw.end(), kw.end() + 40)
        if m and 8 <= len(_NON_DIGIT.sub("", m.group())) <= 15:
            yield m.start(), m.end(), "phone", "+" + _NON_DIGIT.sub("", m.group())


_DEFAULT_FINDERS = (
    _cards,
    _ssns,
    _ibans,
    _emails,
    _keyword_values("passport", _PASSPORT, ("passport",)),
    _keyword_values("driver_licence", _DRIVER_LICENCE, ("licen",), ("DL",)),
    _keyword_values("mrn", _MRN, ("mrn", "medical")),
    _keyword_values("dob", _DOB, ("dob", "d.o.b", "birth", "born")),
    _shaped_ids,
    _keyword_values(
        "nino", _NINO_KW, ("nino", "ni ", "insurance"), (), pii_ids.nino_valid
    ),
    _keyword_values(
        "in_pan", _IN_PAN_KW, ("pan", "permanent"), (), pii_ids.in_pan_valid
    ),
    _keyword_values("dni", _DNI_KW, ("dni", "nie", "nif"), (), pii_ids.dni_valid),
    _keyword_values("sin", _SIN_KW, ("insurance",), ("SIN", "NAS"), pii_ids.sin_valid),
    _keyword_values(
        "aadhaar", _AADHAAR_KW, ("aadha", "uidai"), (), pii_ids.aadhaar_valid
    ),
    _keyword_values(
        "bsn", _BSN_KW, ("bsn", "burgerservice", "sofi"), (), pii_ids.bsn_valid
    ),
    _keyword_values("pesel", _PESEL_KW, ("pesel",), (), pii_ids.pesel_valid),
    _keyword_values(
        "nir",
        _NIR_KW,
        ("nir", "insee", "sociale", "secu", "s\u00e9cu"),
        (),
        pii_ids.nir_valid,
    ),
    _keyword_values(
        "be_nn",
        _BE_NN_KW,
        ("rijksregister", "national", "insz", "niss"),
        (),
        pii_ids.be_nn_valid,
    ),
)
_FINDERS = {
    PII_REDACTION_OFF: (),
    PII_REDACTION_DEFAULT: _DEFAULT_FINDERS + (_ips,),
    PII_REDACTION_STRICT: _DEFAULT_FINDERS + (_ips, _phones),
}
_ID_VALIDATORS = {
    "nino": pii_ids.nino_valid,
    "in_pan": pii_ids.in_pan_valid,
    "dni": pii_ids.dni_valid,
    "codice_fiscale": pii_ids.codice_fiscale_valid,
    "nir": pii_ids.nir_valid,
    "aadhaar": pii_ids.aadhaar_valid,
    "be_nn": pii_ids.be_nn_valid,
    "pesel": pii_ids.pesel_valid,
    "bsn": pii_ids.bsn_valid,
    "sin": pii_ids.sin_valid,
}
_KEY_HINT = re.compile(
    r"ssn|tin|tax|social|passport|driv|licen|mrn|medical|nino|insurance|sin|aadha"
    r"|bsn|burgerservice|pesel|nir|insee|dni|nie|nif|codice|fiscal|rijksregister"
    r"|insz|niss|national|dob|birth|pan|card|cc|phone|mobile|fax"
)
_KEY_KINDS = (
    ("nino", {"nino"}, ("national_insurance",)),
    ("sin", {"sin"}, ("social_insurance",)),
    ("aadhaar", {"aadhaar", "aadhar"}, ()),
    ("bsn", {"bsn", "burgerservicenummer"}, ()),
    ("pesel", {"pesel"}, ()),
    ("nir", {"nir", "insee"}, ()),
    ("dni", {"dni", "nie", "nif"}, ()),
    ("codice_fiscale", {"codicefiscale"}, ("codice_fiscale", "fiscal_code")),
    ("be_nn", {"rijksregisternummer", "insz", "niss"}, ("national_number",)),
    ("national_id", {"nationalid"}, ("national_id",)),
)


@lru_cache(maxsize=1024)
def _key_kind(key: str) -> str | None:
    if not _KEY_HINT.search(key.lower()):
        return None
    words = _KEY_WORD.findall(_CAMEL_HUMP.sub("_", key).lower())
    joined = "_".join(words)
    found = set(words)
    if "ssn" in found or "itin" in found or words in (["tin"], ["tax", "id"]):
        return "ssn"
    if "social_security" in joined or "taxpayer_id" in joined:
        return "ssn"
    if "passport" in found:
        return "passport"
    if found & {"driver", "drivers", "driving"} and found & {"license", "licence"}:
        return "driver_licence"
    if "mrn" in found or "medical_record" in joined:
        return "mrn"
    for kind, key_words, phrases in _KEY_KINDS:
        if found & key_words or any(p in joined for p in phrases):
            return kind
    if found & {"dob", "birthdate", "birthday"} or "birth" in found:
        return "dob"
    if "pan" in found or "card_number" in joined or "cc_number" in joined:
        return "card"
    if found & {"phone", "mobile", "telephone", "fax"}:
        return "phone"
    return None


def _keyed_value(kind: str, value: str) -> tuple[str, str] | None:
    compact = _NON_ALNUM.sub("", value).upper()
    if kind == "national_id" or (kind == "card" and not compact.isdigit()):
        candidates = ("in_pan",) if kind == "card" else tuple(_ID_VALIDATORS)
        for candidate in candidates:
            if _ID_VALIDATORS[candidate](compact):
                return candidate, compact
        ssn = kind == "national_id" and compact.isdigit() and valid_ssn(compact)
        return ("ssn", compact) if ssn else None
    if kind in _ID_VALIDATORS:
        return (kind, compact) if _ID_VALIDATORS[kind](compact) else None
    if kind in ("ssn", "card"):
        digits = value.replace(" ", "").replace("-", "")
        if not digits.isdigit():
            return None
        valid = valid_ssn if kind == "ssn" else valid_credit_card
        return (kind, digits) if valid(digits) else None
    if kind == "dob":
        stripped = value.strip()
        ok = _DATE_ONLY.fullmatch(stripped) and _year_plausible(stripped)
        return (kind, stripped.upper()) if ok else None
    if kind == "phone":
        digits = _NON_DIGIT.sub("", value)
        return (kind, "+" + digits) if 7 <= len(digits) <= 15 else None
    stripped = value.strip()
    return (kind, stripped.upper()) if _KEYED_ID.fullmatch(stripped) else None


class PiiRedactor:
    """Replaces detected values with per-report tokens like `[card-1]` or `[ip-2]`; nothing to reverse."""

    def __init__(self, level: str = PII_REDACTION_DEFAULT) -> None:
        self.level = level if level in _FINDERS else PII_REDACTION_DEFAULT
        self._finders = _FINDERS[self.level]
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._tokens:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._tokens[key] = f"[{kind}-{self._counts[kind]}]"
        return self._tokens[key]

    def __call__(self, text: str) -> str:
        if not self._finders or not text:
            return text
        if not _TWO_DIGITS.search(text) and "@" not in text:
            return text
        lower = text.lower()
        spans = [span for find in self._finders for span in find(text, lower)]
        if not spans:
            return text
        spans.sort(key=lambda s: (s[0], -s[1]))
        out, pos = [], 0
        for start, end, kind, value in spans:
            if start < pos:
                continue
            out.append(text[pos:start])
            out.append(self.token(kind, value))
            pos = end
        out.append(text[pos:])
        return "".join(out)

    def _keyed(self, key: str | None, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return value
        kind = _key_kind(key) if key is not None else None
        if kind == "phone" and self.level != PII_REDACTION_STRICT:
            kind = None
        if kind is not None and self._finders:
            keyed = _keyed_value(kind, str(value))
            if keyed is not None:
                return self.token(*keyed)
        if isinstance(value, int) and self._finders:
            digits = str(abs(value))
            if len(digits) < 19 and valid_credit_card(digits):
                return self.token("card", digits)
        return value

    def structured(self, root: Any) -> Any:
        """Copy of parsed tool input with values under PII keys, and card-valued JSON numbers, tokenized."""
        if not self._finders:
            return root
        holder = [root]
        stack: list[tuple[Any, Any, str | None]] = [(holder, 0, None)]
        while stack:
            parent, slot, key = stack.pop()
            value = parent[slot]
            if isinstance(value, dict):
                copy = dict(value)
                parent[slot] = copy
                stack.extend(
                    (copy, k, k if isinstance(k, str) else None)
                    for k in reversed(list(copy))
                )
            elif isinstance(value, list):
                items = list(value)
                parent[slot] = items
                stack.extend((items, i, key) for i in reversed(range(len(items))))
            else:
                parent[slot] = self._keyed(key, value)
        return holder[0]
